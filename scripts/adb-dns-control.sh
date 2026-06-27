#!/usr/bin/env bash
#
# Send token-authenticated DNS daemon control commands over ADB.
#
# AFWall must have "Allow ADB DNS diagnostics" enabled first. The helper reads
# the daemon token on-device through root and never prints the token locally.

set -euo pipefail

ADB="${ADB:-adb}"
PACKAGE="${PACKAGE:-dev.ukanth.ufirewall}"
WORK_DIR="${WORK_DIR:-}"
ALLOW_DESTRUCTIVE=0

usage() {
    cat <<EOF
Usage: $0 [--adb path] [--package name] [--work-dir path] [--allow-destructive] <command> [arguments...]

Commands:
  status | stats        Daemon runtime counters and control state.
  health                Runtime health and upstream probe.
  validate              Validate current daemon configuration.
  benchmark             Benchmark configured upstream resolvers.
  logs                  Recent in-memory query log entries.
  history [filter]      Persisted query log history, optionally filtered.
  reload                Reload daemon config from AFWall files.
  flush_cache           Clear daemon DNS cache.
  flush_logs            Flush pending query logs to disk.
  clear_logs            Clear query history. Requires --allow-destructive.
  stop                  Stop daemon. Requires --allow-destructive.
  fail_open             Remove DNS redirects and stop daemon. Requires --allow-destructive.

Environment:
  ADB       adb executable, default: adb
  PACKAGE   AFWall package name, default: dev.ukanth.ufirewall
  WORK_DIR  DNS daemon work dir override
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

shell_quote() {
    local value="$1"
    value=${value//\'/\'\"\'\"\'}
    printf "'%s'" "$value"
}

adb_su() {
    "$ADB" shell su -c "$1"
}

single_device_check() {
    local count
    count=$("$ADB" devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
    if [ "$count" -ne 1 ]; then
        "$ADB" devices >&2 || true
        die "expected exactly one attached adb device, found $count"
    fi
}

root_test() {
    adb_su "test $*" >/dev/null 2>&1
}

detect_work_dir() {
    local candidate
    if [ -n "$WORK_DIR" ]; then
        if root_test "-d $(shell_quote "$WORK_DIR")"; then
            printf '%s\n' "$WORK_DIR"
            return 0
        fi
        return 1
    fi
    for candidate in \
        "/data/user_de/0/$PACKAGE/app_dnsd" \
        "/data/data/$PACKAGE/app_dnsd"; do
        if root_test "-d $(shell_quote "$candidate")"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_unix_nc() {
    if adb_su "toybox nc --help 2>&1 | grep -q -- '-U'"; then
        printf '%s\n' 'toybox nc'
        return 0
    fi
    if adb_su "nc -h 2>&1 | grep -q -- '-U'"; then
        printf '%s\n' 'nc'
        return 0
    fi
    return 1
}

send_control() {
    local work_dir="$1"
    local nc_cmd="$2"
    local control_command="$3"
    local socket="$work_dir/afwall_dnsd.sock"
    local token="$work_dir/afwall_dnsd.control"

    adb_su "TOKEN=\$(cat $(shell_quote "$token") 2>/dev/null || true); \
if [ -z \"\$TOKEN\" ]; then echo 'probe_error=token_unreadable'; exit 1; fi; \
printf 'token %s\n%s\n' \"\$TOKEN\" $(shell_quote "$control_command") \
| $nc_cmd -U $(shell_quote "$socket") 2>&1" | tr -d '\r'
}

validate_control_command() {
    local command="$1"
    case "$command" in
        status|stats|health|validate|benchmark|logs|history|reload|flush_cache|flush_logs|clear_logs|stop|fail_open)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_destructive_command() {
    local command="$1"
    case "$command" in
        clear_logs|stop|fail_open)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --adb)
            ADB="$2"
            shift 2
            ;;
        --package)
            PACKAGE="$2"
            shift 2
            ;;
        --work-dir)
            WORK_DIR="$2"
            shift 2
            ;;
        --allow-destructive)
            ALLOW_DESTRUCTIVE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            break
            ;;
    esac
done

if [ "$#" -lt 1 ]; then
    usage >&2
    exit 2
fi

COMMAND="$1"
shift
if ! validate_control_command "$COMMAND"; then
    die "unsupported daemon command: $COMMAND"
fi
if is_destructive_command "$COMMAND" && [ "$ALLOW_DESTRUCTIVE" -ne 1 ]; then
    die "$COMMAND requires --allow-destructive"
fi

CONTROL_COMMAND="$COMMAND"
for arg in "$@"; do
    case "$arg" in
        *$'\n'*|*$'\r'*)
            die "command arguments cannot contain newlines"
            ;;
    esac
    CONTROL_COMMAND="$CONTROL_COMMAND $arg"
done

single_device_check
if ! adb_su "id" 2>/dev/null | grep -q 'uid=0'; then
    die "root shell unavailable through adb su"
fi

WORK_DIR="$(detect_work_dir)" || die "AFWall DNS work dir not found; enable DNS protection and start the service first"
NC_CMD="$(find_unix_nc)" || die "no Unix-domain nc client with -U support found on device"

STATUS="$(send_control "$WORK_DIR" "$NC_CMD" status || true)"
if printf '%s\n' "$STATUS" | grep -q '^error unauthorized'; then
    die "daemon rejected root control; enable AFWall's ADB DNS diagnostics setting and reload/repair DNS"
fi
if ! printf '%s\n' "$STATUS" | grep -q '^control_adb_debug_enabled=1$'; then
    die "ADB DNS diagnostics setting is not active in the running daemon"
fi

if [ "$COMMAND" = "status" ] || [ "$COMMAND" = "stats" ]; then
    printf '%s\n' "$STATUS"
else
    send_control "$WORK_DIR" "$NC_CMD" "$CONTROL_COMMAND"
fi
