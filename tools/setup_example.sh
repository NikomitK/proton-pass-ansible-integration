#!/usr/bin/env bash

set -euo pipefail

PASS_CLI_BIN="${PASS_CLI:-pass-cli}"

VAULT_NAME="${PROTON_PASS_EXAMPLE_VAULT:-ForAnsible}"
ITEM_TITLE="${PROTON_PASS_EXAMPLE_ITEM:-TestItem}"
ITEM_USERNAME="${PROTON_PASS_EXAMPLE_USERNAME:-ansible-user}"
ITEM_PASSWORD="${PROTON_PASS_EXAMPLE_PASSWORD:-ansible-password}"
ITEM_EMAIL="${PROTON_PASS_EXAMPLE_EMAIL:-ansible@example.test}"
ITEM_URL="${PROTON_PASS_EXAMPLE_URL:-https://example.test/login}"
ITEM_NOTE="${PROTON_PASS_EXAMPLE_NOTE:-Fixture created for the proton_pass lookup example playbook.}"
ITEM_CUSTOMFIELD="${PROTON_PASS_EXAMPLE_CUSTOMFIELD:-customfield-value}"
ITEM_HIDDENFIELD="${PROTON_PASS_EXAMPLE_HIDDENFIELD:-hiddenfield-value}"

log() {
  printf '%s\n' "$*" >&2
}

run_pass_cli() {
  "$PASS_CLI_BIN" "$@"
}

require_prerequisites() {
  if ! command -v "$PASS_CLI_BIN" >/dev/null 2>&1; then
    log "Could not find pass-cli binary: $PASS_CLI_BIN"
    log "Set PASS_CLI to a valid binary or wrapper path and try again."
    exit 1
  fi
}

ensure_login() {
  if run_pass_cli info >/dev/null 2>&1; then
    return
  fi

  if [ -z "${PROTON_PASS_PERSONAL_ACCESS_TOKEN:-}" ]; then
    log "pass-cli is not logged in."
    log "Run '$PASS_CLI_BIN login' first, or export PROTON_PASS_PERSONAL_ACCESS_TOKEN."
    exit 1
  fi

  log "Logging in with PROTON_PASS_PERSONAL_ACCESS_TOKEN"
  run_pass_cli login --personal-access-token "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" >/dev/null
}

vault_exists() {
  run_pass_cli item list "$VAULT_NAME" >/dev/null 2>&1
}

item_exists() {
  run_pass_cli item view \
    --vault-name "$VAULT_NAME" \
    --item-title "$ITEM_TITLE" \
    --field password >/dev/null 2>&1
}

ensure_vault() {
  if vault_exists; then
    log "Vault already exists: $VAULT_NAME"
    return
  fi

  log "Creating vault: $VAULT_NAME"
  run_pass_cli vault create --name "$VAULT_NAME" >/dev/null
}

ensure_item() {
  if item_exists; then
    log "Item already exists: $ITEM_TITLE"
    return
  fi

  log "Creating login item: $ITEM_TITLE"
  run_pass_cli item create login \
    --vault-name "$VAULT_NAME" \
    --title "$ITEM_TITLE" \
    --username "$ITEM_USERNAME" \
    --email "$ITEM_EMAIL" \
    --password "$ITEM_PASSWORD" \
    --url "$ITEM_URL" >/dev/null
}

update_item_fields() {
  if ! item_exists; then
    log "Could not find item '$ITEM_TITLE' in vault '$VAULT_NAME' after creation."
    exit 1
  fi

  log "Updating example item fields"
  run_pass_cli item update \
    --vault-name "$VAULT_NAME" \
    --item-title "$ITEM_TITLE" \
    --field "title=$ITEM_TITLE" \
    --field "username=$ITEM_USERNAME" \
    --field "password=$ITEM_PASSWORD" \
    --field "email=$ITEM_EMAIL" \
    --field "url=$ITEM_URL" \
    --field "note=$ITEM_NOTE" \
    --field "customfield=$ITEM_CUSTOMFIELD" \
    --field "hiddenfield=$ITEM_HIDDENFIELD" >/dev/null
}

print_summary() {
  cat <<EOF
Example fixture is ready.

PASS_CLI:   $PASS_CLI_BIN
Vault name: $VAULT_NAME
Item title: $ITEM_TITLE

Fields configured:
  username=$ITEM_USERNAME
  password=$ITEM_PASSWORD
  email=$ITEM_EMAIL
  url=$ITEM_URL
  note=$ITEM_NOTE
  customfield=$ITEM_CUSTOMFIELD
  hiddenfield=$ITEM_HIDDENFIELD

Run the example playbook with:
  ansible-playbook -i localhost, examples/playbook.yml

If you need the generated IDs later:
  $PASS_CLI_BIN vault list --output json
  $PASS_CLI_BIN item list "$VAULT_NAME" --output json
EOF
}

main() {
  require_prerequisites
  ensure_login
  ensure_vault
  ensure_item
  update_item_fields
  print_summary
}

main "$@"
