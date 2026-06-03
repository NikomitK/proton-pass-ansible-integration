# Copyright (c) Proton AG
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import json

from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display


DOCUMENTATION = r"""
name: proton_pass
author:
  - Proton Pass CLI Team
requirements:
  - pass-cli (command line utility)
  - An already logged-in pass-cli session or a valid Proton Pass Personal Access Token (PAT)
short_description: Retrieve secrets from Proton Pass using the pass-cli binary
version_added: "1.0.0"
description:
  - Retrieve a field value from a Proton Pass item using the C(pass-cli) binary.
  - The plugin runs C(pass-cli info) to detect whether the binary already has an
    active session. If it does, that session is reused and no PAT is required.
    If it does not, O(pass_pat) must be provided and the plugin will authenticate
    before performing the lookup.
notes:
  - C(pass-cli) must be installed and on C($PATH) on the Ansible controller (or the
    full path provided via O(pass_cli_path)).
  - When reusing an existing session (C(pass-cli info) exits 0) the plugin runs
    commands in the current environment without any XDG directory redirection, so
    it shares the user's own session.
  - When logging in itself the plugin redirects XDG base directories to an isolated
    temporary (or persistent, if O(session_dir) is set) directory so it never
    interferes with any existing C(pass-cli) session on the controller.
options:
  pass_pat:
    description:
      - Personal Access Token used to authenticate against Proton Pass.
      - Required only when C(pass-cli info) indicates the binary is not currently
        logged in. If the binary already has an active session this option is ignored.
      - Can also be supplied via the E(PROTON_PASS_PERSONAL_ACCESS_TOKEN) environment
        variable.
    type: str
    env:
      - name: PROTON_PASS_PERSONAL_ACCESS_TOKEN
  pass_cli_path:
    description:
      - Path to the C(pass-cli) binary.
      - Defaults to C(pass-cli) (resolved from C($PATH)).
      - E(PASS_CLI) is checked first, then E(PROTON_PASS_CLI_PATH), so you can
        override the binary for quick local testing without touching playbook
        variables (for example C(PASS_CLI=/path/to/dev-build ansible-playbook ...)).
    type: str
    default: pass-cli
    env:
      - name: PASS_CLI
      - name: PROTON_PASS_CLI_PATH
  vault_name:
    description:
      - Human-readable name of the vault that contains the item.
      - Mutually exclusive with O(share_id).
    type: str
  share_id:
    description:
      - Share ID (opaque identifier) of the vault that contains the item.
      - Mutually exclusive with O(vault_name).
    type: str
  item_title:
    description:
      - Title of the item to look up.
      - Mutually exclusive with O(item_id).
    type: str
  item_id:
    description:
      - Opaque item ID to look up.
      - Mutually exclusive with O(item_title).
    type: str
  field:
    description:
      - Field to extract from the matched item.
      - "Built-in fields for login items: C(username), C(password), C(email), C(url), C(note)."
      - Custom fields are referenced by their label.
      - Defaults to C(password).
    type: str
    default: password
  session_dir:
    description:
      - Path to a directory used to persist the C(pass-cli) session across multiple
        lookup calls within the same Ansible run (or even across runs).
      - When set, the plugin logs in only once and reuses the session on every
        subsequent call that specifies the same directory, avoiding the overhead of
        a login round-trip per lookup.
      - The session is tied to the PAT that created it.  If O(pass_pat) changes the
        plugin automatically re-authenticates and updates the stored session.
      - The directory and its contents are B(not) deleted when the plugin exits.
        Remove it manually when the session is no longer needed, or let the OS clean
        it up if you point it at a subdirectory of C(/tmp).
      - When omitted (default) a fresh temporary directory is created for every
        lookup call and removed automatically on exit.
    type: str
    env:
      - name: PROTON_PASS_SESSION_DIR
"""

EXAMPLES = r"""
# All examples assume the PAT is exported beforehand:
#   export PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_...::KEY"
# or supplied inline via pass_pat=.

- name: Get password by vault name and item title
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                item_title='GitHub',
                vault_name='Personal') }}

- name: Get username from the same item
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                item_title='GitHub',
                vault_name='Personal',
                field='username') }}

- name: Look up by share_id and item_title
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                share_id='abc123def',
                item_title='Database',
                field='password') }}

- name: Look up by share_id and item_id (most precise, no name ambiguity)
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                share_id='abc123def',
                item_id='xyz789',
                field='password') }}

- name: Read a custom field
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                item_title='Database',
                vault_name='Production',
                field='connection_string') }}

- name: Inline PAT (not recommended for production, prefer the env variable)
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                item_title='My Secret',
                vault_name='Work',
                pass_pat='pst_...::KEY') }}

- name: Store DB credentials in variables for use throughout the play
  ansible.builtin.set_fact:
    db_password: "{{ lookup('proton_pass', item_title='DB Prod', vault_name='Infrastructure', field='password') }}"
    db_user:     "{{ lookup('proton_pass', item_title='DB Prod', vault_name='Infrastructure', field='username') }}"

# Reusing a session across calls with session_dir

- name: Fetch several secrets with a shared session
  ansible.builtin.set_fact:
    db_pass: "{{ lookup('proton_pass', vault_name='Prod', item_title='DB',   field='password', session_dir='/tmp/pp_session') }}"
    api_key: "{{ lookup('proton_pass', vault_name='Prod', item_title='API',  field='key',      session_dir='/tmp/pp_session') }}"
    smtp_pw: "{{ lookup('proton_pass', vault_name='Prod', item_title='Mail', field='password', session_dir='/tmp/pp_session') }}"

# session_dir can also be set globally via the environment variable:
#   export PROTON_PASS_SESSION_DIR=/tmp/pp_session
"""

RETURN = r"""
_raw:
  description:
    - List of field values, one entry per resolved item.
    - Each entry is the raw string value returned by C(pass-cli item view --field).
  type: list
  elements: str
"""

display = Display()


class ProtonPassException(AnsibleError):
    pass


class ProtonPassCLI:
    """Thin wrapper around the pass-cli binary.

    On entry the plugin runs C(pass-cli info) to detect whether the binary
    already has an active session:

    * **Existing session**, commands are executed in the current environment
      without any XDG directory redirection; no PAT is required.
    * **No session (ephemeral, default)**, a fresh temporary directory is
      created, XDG dirs are redirected there, the plugin logs in with *pass_pat*,
      and the directory is removed on exit.
    * **No session (persistent)**, like ephemeral but the directory at
      *session_dir* is kept across calls; a sentinel file prevents redundant
      re-logins as long as the PAT has not changed.
    """

    # File written inside a persistent session directory after a successful
    # login. Contains the SHA-256 of the PAT so token rotation is detected.
    _SENTINEL = ".proton_pass_session"
    _COMMAND_TIMEOUT = 30

    def __init__(
        self,
        cli_path: str = "pass-cli",
        pass_pat: str = "",
        session_dir: str | None = None,
    ) -> None:
        self._cli_path = cli_path
        self._pass_pat = pass_pat
        self._session_dir = session_dir  # None means ephemeral
        self._working_dir: str | None = None  # set in __enter__ when we own the session
        self._ephemeral = session_dir is None
        self._env: dict[str, str] = {}
        self._is_native_session: bool = (
            False  # True when reusing the user's own session
        )

    # ------------------------------------------------------------------
    # Context manager, handles session directory lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> "ProtonPassCLI":
        # 1. Check whether the binary already has an active session.
        native_env = self._build_native_env()
        if self._is_logged_in(native_env) and not self._session_dir:
            # Reuse the existing session as-is. No XDG redirection, no login.
            self._env = native_env
            self._is_native_session = True
            display.vvv("proton_pass: reusing existing authenticated session")
            return self

        # 2. Set up an isolated working directory.
        if self._ephemeral:
            self._working_dir = tempfile.mkdtemp(prefix="proton_pass_ansible_")
            display.vvv(f"proton_pass: ephemeral session dir: {self._working_dir}")
        else:
            self._working_dir = self._session_dir
            os.makedirs(self._working_dir, mode=0o700, exist_ok=True)
            display.vvv(f"proton_pass: persistent session dir: {self._working_dir}")

        self._env = self._build_env(self._working_dir)

        # 3. For persistent sessions, try the sentinel fast path.
        if not self._ephemeral and self._pass_pat and not self._needs_login():
            if self._is_logged_in(self._env):
                display.vvv(
                    "proton_pass: reusing persistent session (sentinel matched)"
                )
                return self
            display.vvv(
                "proton_pass: sentinel matched but the isolated session is not valid; reauthenticating"
            )

        # 4. Check the isolated environment itself.
        if self._is_logged_in(self._env):
            display.vvv("proton_pass: isolated session already authenticated")
            return self

        # 5. Need to log in.
        if not self._pass_pat:
            raise ProtonPassException(
                "pass-cli is not logged in and no PAT was provided. "
                "Either log in first ('pass-cli login') or supply "
                "pass_pat= / PROTON_PASS_PERSONAL_ACCESS_TOKEN."
            )
        self._logout_force()
        self._login()
        if not self._ephemeral:
            self._write_sentinel()

        return self

    def __exit__(self, *_) -> None:
        if self._is_native_session:
            return  # the session belongs to the user, no cleanup to be made
        if self._ephemeral and self._working_dir:
            self._logout()
            shutil.rmtree(self._working_dir, ignore_errors=True)
            display.vvv(
                f"proton_pass: cleaned up ephemeral session dir: {self._working_dir}"
            )
        # Persistent session: leave the directory intact for the next call.

    # ------------------------------------------------------------------
    # Login detection
    # ------------------------------------------------------------------

    def _build_native_env(self) -> dict[str, str]:
        """Current OS environment, optionally with the PAT injected."""
        env = os.environ.copy()
        if self._pass_pat:
            env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = self._pass_pat
        return env

    def _is_logged_in(self, env: dict[str, str]) -> bool:
        """Return True if C(pass-cli info) exits 0 in *env*."""
        try:
            result = subprocess.run(
                [self._cli_path, "info"],
                env=env,
                capture_output=True,
                text=True,
                timeout=self._COMMAND_TIMEOUT,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Session sentinel helpers (persistent-session optimisation)
    # ------------------------------------------------------------------

    def _pat_fingerprint(self) -> str:
        """SHA-256 hex digest of the PAT used as the sentinel value."""
        return hashlib.sha256(self._pass_pat.encode()).hexdigest()

    def _sentinel_path(self) -> str:
        return os.path.join(self._working_dir, self._SENTINEL)

    def _needs_login(self) -> bool:
        """Return True when no valid sentinel exists for the current PAT."""
        sentinel = self._sentinel_path()
        if not os.path.exists(sentinel):
            return True
        try:
            with open(sentinel, encoding="utf-8") as fh:
                return fh.read().strip() != self._pat_fingerprint()
        except OSError:
            return True

    def _write_sentinel(self) -> None:
        sentinel_path = self._sentinel_path()
        with open(sentinel_path, "w", encoding="utf-8") as fh:
            fh.write(self._pat_fingerprint())
        try:
            os.chmod(sentinel_path, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Environment helpers
    # ------------------------------------------------------------------

    def _build_env(self, tmp_dir: str) -> dict[str, str]:
        """Current OS environment with XDG dirs redirected to *tmp_dir*
        for full session isolation, and the PAT injected if provided."""
        env = os.environ.copy()
        if self._pass_pat:
            env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = self._pass_pat
        # Redirect XDG base dirs. pass-cli respects these on Linux.
        # On macOS the CLI may additionally use ~/Library/Application Support;
        # see plugin documentation for guidance.
        data_dir = os.path.join(tmp_dir, "data")
        config_dir = os.path.join(tmp_dir, "config")
        cache_dir = os.path.join(tmp_dir, "cache")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(config_dir, exist_ok=True)
        os.makedirs(cache_dir, exist_ok=True)
        env["XDG_DATA_HOME"] = data_dir
        env["XDG_CONFIG_HOME"] = config_dir
        env["XDG_CACHE_HOME"] = cache_dir
        return env

    def _format_command(self, args: list[str]) -> str:
        redacted: list[str] = []
        redact_next = False
        for arg in [self._cli_path] + args:
            if redact_next:
                redacted.append("***")
                redact_next = False
                continue
            if arg == "--personal-access-token":
                redacted.append(arg)
                redact_next = True
                continue
            if self._pass_pat and arg == self._pass_pat:
                redacted.append("***")
                continue
            redacted.append(arg)
        return shlex.join(redacted)

    def _run(self, args: list[str], description: str, isTotp=False) -> str:
        cmd = [self._cli_path] + args
        debug_cmd = self._format_command(args)
        display.vvv(f"proton_pass: running: {debug_cmd}")
        if os.environ.get("PASS_ANSIBLE_DEBUG"):
            print(f"[proton_pass] {debug_cmd}", file=sys.stderr)
        try:
            result = subprocess.run(
                cmd,
                env=self._env,
                capture_output=True,
                text=True,
                timeout=self._COMMAND_TIMEOUT,
            )
        except FileNotFoundError:
            raise ProtonPassException(
                f"pass-cli binary not found at '{self._cli_path}'. "
                "Install pass-cli or set pass_cli_path / PROTON_PASS_CLI_PATH."
            )
        except subprocess.TimeoutExpired:
            raise ProtonPassException(f"pass-cli timed out during: {description}")
        if result.returncode != 0:
            error_output = (
                result.stderr or result.stdout
            ).strip() or f"exit code {result.returncode}"
            raise ProtonPassException(
                f"pass-cli failed during '{description}': {error_output}"
            )
        if isTotp:
            return json.loads(result.stdout)['totp']
        return result.stdout

    def _login(self) -> None:
        self._run(
            ["login", "--personal-access-token", self._pass_pat],
            description="login",
        )
        display.vvv("proton_pass: authenticated successfully")

    def _logout(self) -> None:
        try:
            self._run(["logout"], description="logout")
        except ProtonPassException:
            pass  # best-effort; don't obscure the real error

    def _logout_force(self) -> None:
        """Best-effort forced logout to clear any stale state before login."""
        try:
            self._run(["logout", "--force"], description="logout --force")
        except ProtonPassException:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_field(
        self,
        *,
        vault_name: str | None,
        share_id: str | None,
        item_title: str | None,
        item_id: str | None,
        field: str,
    ) -> str:
        """Return the value of *field* for the specified item.

        Exactly one of (vault_name, share_id) and exactly one of
        (item_title, item_id) must be provided.
        """
        if field == "totp-gen":
            args = ["item", "totp"]
        else:
            args = ["item", "view"]

        if share_id:
            args += ["--share-id", share_id]
        else:
            args += ["--vault-name", vault_name]

        if item_id:
            args += ["--item-id", item_id]
        else:
            args += ["--item-title", item_title]

        if field != "totp-gen":
            args += ["--field", field]
        else:
            args += ["--output", "json"]

        desc = f"fetch field '{field}' from item '{item_id or item_title}'"
        return self._run(args, description=desc, isTotp=field=="totp-gen").strip()


class LookupModule(LookupBase):
    @staticmethod
    def _clean_string(value):
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def _normalize_terms(self, terms):
        if not terms:
            return []
        if isinstance(terms, str):
            terms = [terms]

        normalized = []
        for term in terms:
            cleaned = self._clean_string(term)
            if not cleaned:
                raise AnsibleOptionsError(
                    "Positional item titles must be non-empty strings."
                )
            normalized.append(cleaned)
        return normalized

    def run(self, terms=None, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        item_terms = self._normalize_terms(terms)
        pass_pat = self._clean_string(self.get_option("pass_pat")) or ""
        pass_cli_path = (
            self._clean_string(self.get_option("pass_cli_path")) or "pass-cli"
        )
        session_dir = self._clean_string(self.get_option("session_dir")) or None
        vault_name = self._clean_string(self.get_option("vault_name"))
        share_id = self._clean_string(self.get_option("share_id"))
        item_title = self._clean_string(self.get_option("item_title"))
        item_id = self._clean_string(self.get_option("item_id"))
        field = self._clean_string(self.get_option("field")) or "password"

        if session_dir:
            session_dir = os.path.abspath(os.path.expanduser(session_dir))

        # ----- Validate options -----

        if vault_name and share_id:
            raise AnsibleOptionsError(
                "'vault_name' and 'share_id' are mutually exclusive."
            )
        if not vault_name and not share_id:
            raise AnsibleOptionsError(
                "One of 'vault_name' or 'share_id' must be provided."
            )

        if item_terms and item_title:
            raise AnsibleOptionsError(
                "Positional item titles and 'item_title' are mutually exclusive."
            )
        if item_terms and item_id:
            raise AnsibleOptionsError(
                "Positional item titles and 'item_id' are mutually exclusive."
            )
        if item_title and item_id:
            raise AnsibleOptionsError(
                "'item_title' and 'item_id' are mutually exclusive."
            )
        if not item_terms and not item_title and not item_id:
            raise AnsibleOptionsError("Provide an item via 'item_title' or 'item_id'.")
        if not field:
            raise AnsibleOptionsError("'field' must be a non-empty string.")

        # ----- Execute -----

        item_titles = item_terms or ([item_title] if item_title else [])

        with ProtonPassCLI(
            cli_path=pass_cli_path, pass_pat=pass_pat, session_dir=session_dir
        ) as pp:
            if item_id:
                return [
                    pp.get_field(
                        vault_name=vault_name,
                        share_id=share_id,
                        item_title=None,
                        item_id=item_id,
                        field=field,
                    )
                ]

            return [
                pp.get_field(
                    vault_name=vault_name,
                    share_id=share_id,
                    item_title=title,
                    item_id=None,
                    field=field,
                )
                for title in item_titles
            ]
