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

The helper prefers the daemon Unix control socket and falls back to the
loopback TCP control port when AFWall's ADB DNS diagnostics setting is active.
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

find_tcp_nc() {
    if adb_su "toybox nc --help >/dev/null 2>&1"; then
        printf '%s\n' 'toybox nc'
        return 0
    fi
    if adb_su "command -v nc >/dev/null 2>&1"; then
        printf '%s\n' 'nc'
        return 0
    fi
    return 1
}

read_control_tcp_port() {
    local work_dir="$1"
    local config="$work_dir/afwall_dnsd.conf"
    local value
    value=$(adb_su "sed -n 's/^control_tcp_port=//p' $(shell_quote "$config") | head -n 1" \
        2>/dev/null | tr -d '\r' || true)
    case "$value" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac
    if [ "$value" -le 0 ] || [ "$value" -gt 65535 ]; then
        return 1
    fi
    printf '%s\n' "$value"
}

send_control_unix() {
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

send_control_tcp() {
    local work_dir="$1"
    local nc_cmd="$2"
    local port="$3"
    local control_command="$4"
    local token="$work_dir/afwall_dnsd.control"

    adb_su "TOKEN=\$(cat $(shell_quote "$token") 2>/dev/null || true); \
if [ -z \"\$TOKEN\" ]; then echo 'probe_error=token_unreadable'; exit 1; fi; \
printf 'token %s\n%s\n' \"\$TOKEN\" $(shell_quote "$control_command") \
| $nc_cmd 127.0.0.1 $(shell_quote "$port") 2>&1" | tr -d '\r'
}

status_allows_debug() {
    local status="$1"
    printf '%s\n' "$status" | grep -q '^running=1' \
        && printf '%s\n' "$status" | grep -q '^control_adb_debug_enabled=1$'
}

send_selected_control() {
    local control_command="$1"
    case "$TRANSPORT" in
        unix)
            send_control_unix "$WORK_DIR" "$NC_CMD" "$control_command"
            ;;
        tcp)
            send_control_tcp "$WORK_DIR" "$NC_CMD" "$TCP_PORT" "$control_command"
            ;;
        *)
            die "internal error: no selected control transport"
            ;;
    esac
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
TRANSPORT=""
NC_CMD=""
TCP_PORT=""
STATUS=""

if NC_CANDIDATE="$(find_unix_nc)"; then
    STATUS="$(send_control_unix "$WORK_DIR" "$NC_CANDIDATE" status || true)"
    if status_allows_debug "$STATUS"; then
        TRANSPORT="unix"
        NC_CMD="$NC_CANDIDATE"
    fi
fi

if [ -z "$TRANSPORT" ]; then
    if TCP_PORT="$(read_control_tcp_port "$WORK_DIR")" && NC_CANDIDATE="$(find_tcp_nc)"; then
        STATUS="$(send_control_tcp "$WORK_DIR" "$NC_CANDIDATE" "$TCP_PORT" status || true)"
        if status_allows_debug "$STATUS"; then
            TRANSPORT="tcp"
            NC_CMD="$NC_CANDIDATE"
        fi
    fi
fi

if [ -z "$TRANSPORT" ]; then
    if printf '%s\n' "$STATUS" | grep -q '^error unauthorized'; then
        die "daemon rejected root control; enable AFWall's ADB DNS diagnostics setting and reload/repair DNS"
    fi
    die "no usable daemon control transport found; enable ADB DNS diagnostics and ensure Unix nc -U or loopback TCP nc is available"
fi

if [ "$COMMAND" = "status" ] || [ "$COMMAND" = "stats" ]; then
    printf '%s\n' "$STATUS"
else
    send_selected_control "$CONTROL_COMMAND"
fi
