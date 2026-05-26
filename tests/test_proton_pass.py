import importlib.util
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


def _install_ansible_stubs():
    ansible = types.ModuleType("ansible")
    errors = types.ModuleType("ansible.errors")
    plugins = types.ModuleType("ansible.plugins")
    lookup = types.ModuleType("ansible.plugins.lookup")
    utils = types.ModuleType("ansible.utils")
    display = types.ModuleType("ansible.utils.display")

    class AnsibleError(Exception):
        pass

    class AnsibleOptionsError(AnsibleError):
        pass

    class LookupBase:
        def set_options(self, var_options=None, direct=None):
            self._options = {}
            if var_options:
                self._options.update(var_options)
            if direct:
                self._options.update(direct)

        def get_option(self, name):
            return self._options.get(name)

    class Display:
        def vvv(self, *_args, **_kwargs):
            return None

    errors.AnsibleError = AnsibleError
    errors.AnsibleOptionsError = AnsibleOptionsError
    lookup.LookupBase = LookupBase
    display.Display = Display

    sys.modules["ansible"] = ansible
    sys.modules["ansible.errors"] = errors
    sys.modules["ansible.plugins"] = plugins
    sys.modules["ansible.plugins.lookup"] = lookup
    sys.modules["ansible.utils"] = utils
    sys.modules["ansible.utils.display"] = display


def _load_plugin():
    _install_ansible_stubs()
    plugin_path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "lookup_plugins"
        / "proton_pass.py"
    )
    spec = importlib.util.spec_from_file_location("proton_pass_plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


class FakeCLI:
    values = {}
    captured_init = None

    def __init__(self, cli_path, pass_pat, session_dir):
        FakeCLI.captured_init = {
            "cli_path": cli_path,
            "pass_pat": pass_pat,
            "session_dir": session_dir,
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def get_field(self, **kwargs):
        return FakeCLI.values[kwargs["item_id"] or kwargs["item_title"]]


class LookupModuleTests(unittest.TestCase):
    def test_supports_positional_item_titles(self):
        FakeCLI.values = {
            "GitHub": "gh-password",
            "GitLab": "gl-password",
        }

        with mock.patch.object(plugin, "ProtonPassCLI", FakeCLI):
            result = plugin.LookupModule().run(
                terms=["GitHub", "GitLab"],
                variables=None,
                vault_name="Personal",
                field="password",
            )

        self.assertEqual(result, ["gh-password", "gl-password"])

    def test_positional_titles_and_item_id_are_mutually_exclusive(self):
        with self.assertRaises(plugin.AnsibleOptionsError):
            plugin.LookupModule().run(
                terms=["GitHub"],
                variables=None,
                vault_name="Personal",
                item_id="item-123",
            )

    def test_session_dir_is_normalized_before_cli_init(self):
        FakeCLI.values = {"GitHub": "gh-password"}

        with tempfile.TemporaryDirectory() as tmpdir:
            relative_session_dir = (
                pathlib.Path(tmpdir) / ".." / pathlib.Path(tmpdir).name
            )

            with mock.patch.object(plugin, "ProtonPassCLI", FakeCLI):
                plugin.LookupModule().run(
                    terms=["GitHub"],
                    variables=None,
                    vault_name="Personal",
                    session_dir=str(relative_session_dir),
                )

        self.assertEqual(
            FakeCLI.captured_init["session_dir"],
            str(
                pathlib.Path(
                    os.path.abspath(os.path.expanduser(str(relative_session_dir)))
                )
            ),
        )


class ProtonPassCLITests(unittest.TestCase):
    def test_persistent_session_reauthenticates_when_sentinel_is_stale(self):
        with tempfile.TemporaryDirectory() as session_dir:
            cli = plugin.ProtonPassCLI(
                cli_path="pass-cli",
                pass_pat="pst_secret",
                session_dir=session_dir,
            )

            with (
                mock.patch.object(cli, "_build_native_env", return_value={}),
                mock.patch.object(cli, "_build_env", return_value={}),
                mock.patch.object(cli, "_needs_login", return_value=False),
                mock.patch.object(
                    cli, "_is_logged_in", side_effect=[False, False, False]
                ),
                mock.patch.object(cli, "_logout_force") as logout_force,
                mock.patch.object(cli, "_login") as login,
                mock.patch.object(cli, "_write_sentinel") as write_sentinel,
            ):
                with cli:
                    pass

        logout_force.assert_called_once()
        login.assert_called_once()
        write_sentinel.assert_called_once()

    def test_command_logging_redacts_pat(self):
        cli = plugin.ProtonPassCLI(cli_path="pass-cli", pass_pat="pst_secret")

        rendered = cli._format_command(
            ["login", "--personal-access-token", "pst_secret"]
        )

        self.assertIn("--personal-access-token", rendered)
        self.assertIn("***", rendered)
        self.assertNotIn("pst_secret", rendered)


if __name__ == "__main__":
    unittest.main()
