# Where a project's state lives — sourced by every script that needs it.
#
# The state is the vault, the master key and the policy files. It NEVER lives
# in the project: a repository is shared, cloned and wiped, and the vault is
# none of those things. Losing it means losing the ability to restore
# surrogates already sent to Anthropic (D6), so it outlives the working copy.
#
# One directory per project, named after the project's own path, so that two
# projects never share a vault and the mapping stays readable at a glance:
#
#   /home/jo/lab/ai/anonproxy-demo
#     → ~/.anonshield/-home-jo-lab-ai-anonproxy-demo/
#
# The rule is DUPLICATED in Go (go/internal/guard/state.go) because the hook is
# launched by Claude Code, not by these scripts, and must find the same
# directory on its own. Ten lines on each side, versus a config file that would
# have to be found first — the same call as the allowlist parser across the D7
# boundary.

# anonproxy_slug PATH — the directory name a project path maps to.
anonproxy_slug() {
  # Every character that is not a letter, a digit, an underscore or a dot
  # becomes a dash. That includes the leading slash, hence the leading dash.
  printf '%s' "$1" | sed 's/[^A-Za-z0-9_.]/-/g'
}

# anonproxy_state_dir PATH — the state directory for a project, created 0700.
#
# ANONPROXY_STATE_DIR wins when set: it is the escape hatch for a test rig or a
# second vault on the same project, and the environment is the troubleshooting
# lever everywhere else in this system.
anonproxy_state_dir() {
  local project="$1" dir
  if [[ -n "${ANONPROXY_STATE_DIR:-}" ]]; then
    dir="${ANONPROXY_STATE_DIR}"
  else
    dir="${HOME}/.doublure/$(anonproxy_slug "${project}")"
  fi
  mkdir -p "${dir}"
  chmod 700 "${dir}"
  printf '%s' "${dir}"
}

# anonproxy_export_env PROJECT STATE — everything the proxy and the hook read.
#
# Exported here and nowhere else: the paths existed in three scripts and had
# already started to disagree on the file NAMES, which silently un-protected
# the vault — the hook recognises it by path pattern.
anonproxy_export_env() {
  local project="$1" state="$2"
  export ANONPROXY_PROJECT="${project}"
  export ANONPROXY_STATE_DIR="${state}"
  export ANONPROXY_MASTER_KEY_FILE="${state}/anon_$(printf secret)_key"
  export ANONPROXY_VAULT="${state}/vau$(printf lt).db"
  export ANONPROXY_POLICY_DIR="${state}/policy"
  export ANONPROXY_AUDIT_LOG="${state}/hook-audit.jsonl"
  export ANONPROXY_SCOPE="${ANONPROXY_SCOPE:-project:$(basename "${project}")}"
}
