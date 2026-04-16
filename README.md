# Proton Pass Ansible Lookup Plugin

This repository contains an Ansible lookup plugin that reads secrets from Proton Pass through the `pass-cli` binary. The lookup runs on the Ansible controller, so the controller needs access to `pass-cli` and to a valid Proton Pass session or Personal Access Token (PAT).

## What the plugin does

The plugin fetches a single field from a Proton Pass item by calling `pass-cli item view --field ...`.

It supports two vault selectors:

- `vault_name`
- `share_id`

And also supports two item selectors:

- `item_id`, which is the most stable option for automation.
- `item_title`

## Requirements

| Requirement | Notes |
| --- | --- |
| `pass-cli` | Must be available on the controller, either on `$PATH` or via `pass_cli_path`, `PASS_CLI`, or `PROTON_PASS_CLI_PATH`. |
| Proton Pass PAT or active session | A PAT is only required when `pass-cli` is not already logged in. |
| Python 3.9+ | The plugin uses modern type hints internally. |
| Ansible 2.14+ | This is the intended baseline. Older versions may work, but they are not covered here. |

## Installation

Copy or symlink `lookup_plugins/proton_pass.py` into your playbook directory, or add the repository lookup path to `ansible.cfg`.

Example layout:

```text
your-playbook/
|-- lookup_plugins/
|   `-- proton_pass.py
`-- site.yml
```

Example `ansible.cfg`:

```ini
[defaults]
lookup_plugins = /path/to/pass-cli-ansible-integration/lookup_plugins
```

## Example setup

If you want a runnable local fixture, use [tools/setup_example.sh](tools/setup_example.sh).
It creates the `ForAnsible` vault and the `TestItem` login used by [examples/playbook.yml](examples/playbook.yml).

By default the script runs `pass-cli`, but you can point it at a wrapper or a custom binary with `PASS_CLI`:

```bash
export PASS_CLI=/path/to/pass-cli-wrapper

tools/setup_example.sh
ansible-playbook -i localhost, examples/playbook.yml
```

## Authentication

Create a [Personal Access Token](https://protonpass.github.io/pass-cli/commands/personal-access-token/) if you do not want to rely on an existing local `pass-cli` session.

```bash
pass-cli pat create --name "ansible-runner" --expiration 3m
pass-cli pat access grant --pat-name "ansible-runner" --vault-name "Production" --role viewer
export PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_...::KEY"
```

PAT precedence is:

1. `pass_pat=` on the lookup call
2. `PROTON_PASS_PERSONAL_ACCESS_TOKEN`
3. No PAT, if `pass-cli info` already reports an authenticated local session

## Session behavior

The plugin has two execution modes.

### Reuse the current local session

If `pass-cli info` succeeds and you did not set `session_dir`, the plugin reuses the existing local session.

### Create an isolated session

If there is no active local session, or if you set `session_dir`, the plugin creates an isolated environment for `pass-cli`.

- Without `session_dir`, it creates a temporary directory for the lookup call, logs in with the PAT, runs the lookup, logs out, and removes the directory.
- With `session_dir`, it keeps the directory on disk and reuses it across calls. The plugin stores a PAT fingerprint in `.proton_pass_session` and reauthenticates automatically when the PAT changes or the cached session is no longer valid.

`session_dir` can also be defined using the environment variable `PROTON_PASS_SESSION_DIR`.

## Options

| Option | Required | Description |
| --- | --- | --- |
| `vault_name` | Yes, unless `share_id` is set | Human-readable vault name. |
| `share_id` | Yes, unless `vault_name` is set | Opaque vault share identifier. |
| `item_title` | Yes, unless `item_id` is set | Human-readable item title. |
| `item_id` | Yes, unless `item_title` is set | Opaque item identifier. |
| `field` | No | Field to read. Defaults to `password`. |
| `pass_pat` | No | PAT used when a login is needed. |
| `pass_cli_path` | No | Path to `pass-cli`. Defaults to `pass-cli`. |
| `session_dir` | No | Persistent session directory for repeated lookups. |

## Usage

Fetch a field:

```yaml
- name: Fetch GitHub password
  ansible.builtin.debug:
    msg: "{{ lookup('proton_pass', vault_name='Personal', item_title='GitHub', field='password') }}"
```

Fetch by `share_id` and `item_id` (most precise, no name ambiguity):

```yaml
- name: Fetch by IDs
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                share_id='abc123def456',
                item_id='xyz789item',
                field='password') }}
```

Retrieve multiple secrets in variables with `no_log`:

```yaml
- name: Fetch DB credentials
  ansible.builtin.set_fact:
    db_user: "{{ lookup('proton_pass', vault_name='Prod', item_title='DB Prod', field='username') }}"
    db_pass: "{{ lookup('proton_pass', vault_name='Prod', item_title='DB Prod', field='password') }}"
  no_log: true
```

Do it using a persistent session:

```yaml
- name: Fetch several secrets with one cached session
  ansible.builtin.set_fact:
    db_pass: "{{ lookup('proton_pass', vault_name='Prod', item_title='DB',   field='password', session_dir='/tmp/pp_session') }}"
    api_key: "{{ lookup('proton_pass', vault_name='Prod', item_title='API',  field='token',    session_dir='/tmp/pp_session') }}"
    smtp_pw: "{{ lookup('proton_pass', vault_name='Prod', item_title='Mail', field='password', session_dir='/tmp/pp_session') }}"
  no_log: true
```

Supply an inline PAT (prefer the environment variable in production):

```yaml
- name: Lookup with an explicit PAT
  ansible.builtin.debug:
    msg: >-
      {{ lookup('proton_pass',
                vault_name='Work',
                item_title='My Secret',
                pass_pat='pst_...::KEY') }}
```

## Security notes

- Do not print secrets with `debug` in real playbooks.
- Prefer `no_log: true` when storing or passing secret values.
- Prefer `item_id` over `item_title` for stable automation and avoiding conflicts in case of item rename.
- The plugin redacts PAT values from its own command logging.

## Example playbook

See [examples/playbook.yml](examples/playbook.yml) for a practical example that matches the current plugin behavior and the fixture created by [tools/setup_example.sh](tools/setup_example.sh).

## Local validation

This repository includes a small unit test suite that stubs the Ansible imports so contributors can validate the plugin logic without installing Ansible locally.

```bash
python3 -m unittest discover -s tests
```
