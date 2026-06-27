#!/usr/bin/env bash
#
# Runtime validation for AFWall root DNS Magisk integration.
#
# Baseline checks are evidence-oriented and do not toggle AFWall preferences.
# Optional recovery probes intentionally alter root daemon state, then verify
# fail-open cleanup and restore the service. Enable DNS protection and Magisk
# boot persistence from AFWall first, then run this against a rooted device.

set -euo pipefail

ADB="${ADB:-adb}"
PACKAGE="${PACKAGE:-dev.ukanth.ufirewall}"
APK="${APK:-app/build/outputs/apk/debug/app-debug.apk}"
MODULE_DIR="${MODULE_DIR:-/data/adb/modules/afwall_dnsd}"
OUT_DIR="${OUT_DIR:-runtime-validation-logs/dns-magisk-$(date +%Y%m%d-%H%M%S)}"
EXPECTED_SCRIPT_VERSION="${EXPECTED_SCRIPT_VERSION:-4}"
INSTALL_APK=0
REBOOT_CHECK=0
DAEMON_RESTART_CHECK=0
ORPHAN_SERVICE_CHECK=0
STALE_MARKER_CHECK=0
EMBEDDED_CLEANUP_CHECK=0
DIRECT_CLEANUP_CHECK=0
DAEMON_FAIL_OPEN_CHECK=0
ADB_DEBUG_CONTROL_CHECK=0
BOOT_TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-180}"
POST_BOOT_SETTLE_SECONDS="${POST_BOOT_SETTLE_SECONDS:-20}"
RECOVERY_WAIT_SECONDS="${RECOVERY_WAIT_SECONDS:-45}"
CURRENT_PHASE="preboot"

failures=0
warnings=0

usage() {
    cat <<EOF
Usage: $0 [--install] [--reboot-check] [--daemon-restart-check] [--orphan-service-check] [--stale-marker-check] [--embedded-cleanup-check] [--direct-cleanup-check] [--daemon-fail-open-check] [--adb-debug-control-check] [--apk path] [--package name] [--out dir]

Environment:
  ADB          adb executable, default: adb
  APK          APK to install when --install is used
  PACKAGE      Android package name, default: dev.ukanth.ufirewall
  MODULE_DIR   Magisk module path, default: /data/adb/modules/afwall_dnsd
  OUT_DIR      Evidence output directory
  EXPECTED_SCRIPT_VERSION Expected AFWall DNS module script version
  BOOT_TIMEOUT_SECONDS      Time to wait for boot completion with --reboot-check
  POST_BOOT_SETTLE_SECONDS  Extra settle time after boot completion
  RECOVERY_WAIT_SECONDS     Time to wait for daemon/service recovery checks

Preconditions:
  - exactly one rooted Magisk device is attached
  - AFWall DNS protection is enabled in the app
  - "Use Magisk DNS module at boot" is enabled in the app
  - the daemon has been started at least once by applying rules or repairing DNS

Optional recovery checks:
  --daemon-restart-check  Kills the daemon and verifies the supervisor restarts it.
  --orphan-service-check  Runs copied module scripts with a missing package name to
                          verify fail-open cleanup, then restarts the service.
  --stale-marker-check    Runs a copied module service with a missing enable marker
                          to verify stale boot modules disable themselves.
  --embedded-cleanup-check
                          Runs a copied module service without app cleanup files to
                          verify the Magisk fallback stops the daemon and fails open.
  --direct-cleanup-check  Runs a direct no-supervisor cleanup probe that clears the
                          enable marker, kills daemon state, removes redirects, then
                          verifies the service can be started again.
  --daemon-fail-open-check
                          Clears the enable marker and sends authenticated fail_open
                          over the daemon control socket as the AFWall app UID, then
                          verifies redirects are removed and the service restores.
  --adb-debug-control-check
                          Expect AFWall's ADB DNS diagnostics setting to be enabled
                          and verify root-over-ADB can run token-authenticated status
                          over the Unix socket or loopback TCP fallback.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --install)
            INSTALL_APK=1
            shift
            ;;
        --reboot-check)
            REBOOT_CHECK=1
            shift
            ;;
        --daemon-restart-check)
            DAEMON_RESTART_CHECK=1
            shift
            ;;
        --orphan-service-check)
            ORPHAN_SERVICE_CHECK=1
            shift
            ;;
        --stale-marker-check)
            STALE_MARKER_CHECK=1
            shift
            ;;
        --embedded-cleanup-check)
            EMBEDDED_CLEANUP_CHECK=1
            shift
            ;;
        --direct-cleanup-check)
            DIRECT_CLEANUP_CHECK=1
            shift
            ;;
        --daemon-fail-open-check)
            DAEMON_FAIL_OPEN_CHECK=1
            shift
            ;;
        --adb-debug-control-check)
            ADB_DEBUG_CONTROL_CHECK=1
            shift
            ;;
        --apk)
            APK="$2"
            shift 2
            ;;
        --package)
            PACKAGE="$2"
            shift 2
            ;;
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

mkdir -p "$OUT_DIR"

log() {
    printf '%s\n' "$*"
}

pass() {
    log "PASS: $*"
}

warn() {
    warnings=$((warnings + 1))
    log "WARN: $*"
}

fail() {
    failures=$((failures + 1))
    log "FAIL: $*"
}

capture() {
    local name="$1"
    shift
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        "$@" 2>&1
    } > "$OUT_DIR/$CURRENT_PHASE-$name" || true
}

adb_shell() {
    "$ADB" shell "$@"
}

adb_su() {
    "$ADB" shell su -c "$*"
}

root_test() {
    adb_su "test $*" >/dev/null 2>&1
}

root_cat() {
    adb_su "cat $*"
}

shell_quote() {
    local value="$1"
    value=${value//\'/\'\"\'\"\'}
    printf "'%s'" "$value"
}

single_device_check() {
    local count
    count=$("$ADB" devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
    if [ "$count" -ne 1 ]; then
        fail "expected exactly one attached device, found $count"
        "$ADB" devices | tee "$OUT_DIR/adb-devices.txt" >/dev/null
        exit 1
    fi
    pass "one adb device attached"
}

install_apk_if_requested() {
    if [ "$INSTALL_APK" -ne 1 ]; then
        return
    fi
    if [ ! -f "$APK" ]; then
        fail "APK not found: $APK"
        exit 1
    fi
    capture install-apk.txt "$ADB" install -r "$APK"
    pass "APK install command completed"
}

detect_work_dir() {
    local candidate
    for candidate in \
        "/data/user_de/0/$PACKAGE/app_dnsd" \
        "/data/data/$PACKAGE/app_dnsd"; do
        if root_test "-d '$candidate'"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

detect_app_uid() {
    local uid
    uid=$("$ADB" shell cmd package list packages -U 2>/dev/null \
        | tr -d '\r' \
        | awk -v p="package:$PACKAGE" '$1 == p { for (i = 1; i <= NF; i++) if ($i ~ /^uid:/) { sub(/^uid:/, "", $i); print $i; exit } }')
    if [[ "$uid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$uid"
        return 0
    fi
    uid=$("$ADB" shell dumpsys package "$PACKAGE" 2>/dev/null \
        | tr -d '\r' \
        | sed -n 's/.*userId=\([0-9][0-9]*\).*/\1/p' \
        | head -n 1)
    if [[ "$uid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$uid"
        return 0
    fi
    return 1
}

root_command_exists() {
    adb_su "command -v '$1' >/dev/null 2>&1" >/dev/null 2>&1
}

read_root_number_file() {
    local path="$1"
    adb_su "cat $(shell_quote "$path") 2>/dev/null || true" \
        | tr -d '\r' \
        | sed -n 's/^\([0-9][0-9]*\).*/\1/p' \
        | head -n 1
}

root_stat_owner_mode() {
    local path="$1"
    adb_su "if stat -c '%u %a' $(shell_quote "$path") >/dev/null 2>&1; then stat -c '%u %a' $(shell_quote "$path"); elif toybox stat -c '%u %a' $(shell_quote "$path") >/dev/null 2>&1; then toybox stat -c '%u %a' $(shell_quote "$path"); fi" \
        | tr -d '\r' \
        | sed -n 's/^\([0-9][0-9]*\)[[:space:]][[:space:]]*\([0-7][0-7]*\).*$/\1 \2/p' \
        | head -n 1
}

mode_has_no_group_world_bits() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 077) == 0 ))
}

daemon_pid() {
    local work_dir="$1"
    read_root_number_file "$work_dir/afwall_dnsd.pid"
}

restart_count() {
    local work_dir="$1"
    local count
    count=$(read_root_number_file "$work_dir/afwall_dnsd_restart_count")
    printf '%s\n' "${count:-0}"
}

supervisor_command() {
    local work_dir="$1"
    local action="$2"
    adb_su "$(shell_quote "$work_dir/afwall_dnsd_supervisor.sh") $action 2>&1"
}

wait_for_supervisor_ready() {
    local work_dir="$1"
    local deadline=$((SECONDS + RECOVERY_WAIT_SECONDS))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if supervisor_command "$work_dir" status | tr -d '\r' | grep -q '^readiness=ready$'; then
            return 0
        fi
        sleep 2
    done
    return 1
}

check_root_and_magisk() {
    capture root-id.txt "$ADB" shell su -c id
    if ! adb_su "id" 2>/dev/null | grep -q 'uid=0'; then
        fail "root shell unavailable through su"
        exit 1
    fi
    pass "root shell available"

    capture magisk-version.txt "$ADB" shell su -c 'magisk -V 2>/dev/null || magisk -v 2>/dev/null || ls -la /data/adb 2>/dev/null'
    if ! root_test "-d /data/adb/modules"; then
        fail "Magisk modules directory missing"
    else
        pass "Magisk modules directory present"
    fi
}

check_module_state() {
    capture module-listing.txt "$ADB" shell su -c "ls -la '$MODULE_DIR' 2>&1 || true"
    capture module-prop.txt "$ADB" shell su -c "cat '$MODULE_DIR/module.prop' 2>&1 || true"
    capture module-service-script-head.txt "$ADB" shell su -c "sed -n '1,80p' '$MODULE_DIR/service.sh' 2>&1 || true"
    capture module-uninstall-script-head.txt "$ADB" shell su -c "sed -n '1,120p' '$MODULE_DIR/uninstall.sh' 2>&1 || true"
    if ! root_test "-d '$MODULE_DIR'"; then
        fail "DNS Magisk module directory missing: $MODULE_DIR"
        return
    fi
    if ! adb_su "grep -q '^id=afwall_dnsd$' '$MODULE_DIR/module.prop'"; then
        fail "DNS Magisk module id missing or wrong"
    else
        pass "DNS Magisk module id verified"
    fi
    if root_test "-f '$MODULE_DIR/disable'"; then
        fail "DNS Magisk module is disabled"
    else
        pass "DNS Magisk module is not disabled"
    fi
    if root_test "-f '$MODULE_DIR/remove'"; then
        fail "DNS Magisk module removal is pending"
    else
        pass "DNS Magisk module removal is not pending"
    fi
    check_module_script_versions
}

check_module_script_versions() {
    local script
    local marker="AFWALL_DNS_MODULE_SCRIPT_VERSION=$EXPECTED_SCRIPT_VERSION"
    for script in service.sh uninstall.sh; do
        if ! root_test "-f '$MODULE_DIR/$script'"; then
            fail "DNS Magisk module script missing: $script"
            continue
        fi
        if adb_su "grep -q '^$marker$' '$MODULE_DIR/$script'"; then
            pass "DNS Magisk module script version verified: $script"
        else
            fail "DNS Magisk module script version mismatch for $script; expected $EXPECTED_SCRIPT_VERSION"
        fi
    done
    if adb_su "grep -q '^MARKER=' '$MODULE_DIR/service.sh'"; then
        pass "DNS Magisk service script has enable-marker gate"
    else
        fail "DNS Magisk service script is missing enable-marker gate"
    fi
    if adb_su "grep -q 'cleanup_service_state' '$MODULE_DIR/service.sh'"; then
        pass "DNS Magisk service script has embedded fallback cleanup"
    else
        fail "DNS Magisk service script is missing embedded fallback cleanup"
    fi
    if adb_su "grep -q 'remove_root_copies' '$MODULE_DIR/service.sh'"; then
        pass "DNS Magisk service script removes legacy root startup hooks during fallback cleanup"
    else
        fail "DNS Magisk service script is missing legacy root startup hook cleanup"
    fi
    if adb_su "grep -q 'rm -f \"\\\$MARKER\"' '$MODULE_DIR/service.sh'"; then
        pass "DNS Magisk service script clears the enable marker during fallback cleanup"
    else
        fail "DNS Magisk service script does not clear the enable marker during fallback cleanup"
    fi
    if adb_su "grep -q 'cleanup_service_state' '$MODULE_DIR/uninstall.sh'"; then
        pass "DNS Magisk uninstall script has embedded fallback cleanup"
    else
        fail "DNS Magisk uninstall script is missing embedded fallback cleanup"
    fi
    if adb_su "grep -q 'remove_root_copies' '$MODULE_DIR/uninstall.sh'"; then
        pass "DNS Magisk uninstall script removes legacy root startup hooks during fallback cleanup"
    else
        fail "DNS Magisk uninstall script is missing legacy root startup hook cleanup"
    fi
    if adb_su "grep -q 'rm -f \"\\\$MARKER\"' '$MODULE_DIR/uninstall.sh'"; then
        pass "DNS Magisk uninstall script clears the enable marker during fallback cleanup"
    else
        fail "DNS Magisk uninstall script does not clear the enable marker during fallback cleanup"
    fi
}

check_work_dir_state() {
    local work_dir="$1"
    local app_uid
    capture workdir-listing.txt "$ADB" shell su -c "ls -la '$work_dir' 2>&1 || true"
    capture service-events.txt "$ADB" shell su -c "tail -n 200 '$work_dir/afwall_dnsd_events.log' 2>&1 || true"
    capture supervisor-log.txt "$ADB" shell su -c "tail -n 200 '$work_dir/afwall_dnsd_supervisor.log' 2>&1 || true"
    capture boot-log.txt "$ADB" shell su -c "tail -n 200 '$work_dir/afwall_dnsd_boot.log' 2>&1 || true"
    capture module-log.txt "$ADB" shell su -c "tail -n 200 /data/local/tmp/afwall_dnsd_module.log 2>&1 || true"

    if root_test "-S '$work_dir/afwall_dnsd.sock'"; then
        pass "control socket present"
    else
        fail "control socket missing"
    fi
    if root_test "-s '$work_dir/afwall_dnsd.control'"; then
        pass "control token file exists and is non-empty"
    else
        fail "control token file missing or empty"
    fi
    if root_test "-f '$work_dir/afwall_dnsd.enabled'"; then
        pass "enabled marker present"
    else
        fail "enabled marker missing"
    fi
    if app_uid=$(detect_app_uid); then
        check_control_file_permissions "$work_dir" "$app_uid"
    else
        fail "unable to detect AFWall app UID for control file permission checks"
    fi
}

check_control_path_stat() {
    local label="$1"
    local path="$2"
    local expected_uid="$3"
    local stat_line
    local owner
    local mode
    stat_line=$(root_stat_owner_mode "$path")
    printf '%s %s\n' "$path" "${stat_line:-stat_unavailable}" \
        >> "$OUT_DIR/$CURRENT_PHASE-control-path-permissions.txt"
    if [ -z "$stat_line" ]; then
        fail "$label stat unavailable"
        return
    fi
    owner=${stat_line%% *}
    mode=${stat_line##* }
    if [ "$owner" = "$expected_uid" ]; then
        pass "$label is owned by AFWall app UID"
    else
        fail "$label owner UID is $owner, expected $expected_uid"
    fi
    if mode_has_no_group_world_bits "$mode"; then
        pass "$label has no group/world permission bits"
    else
        fail "$label mode $mode exposes group/world permission bits"
    fi
}

check_shell_uid_cannot_read_sensitive_file() {
    local label="$1"
    local path="$2"
    local file_label
    local response_file
    local id_file="$OUT_DIR/$CURRENT_PHASE-shell-uid-id.txt"
    file_label=$(printf '%s\n' "$label" | tr -c 'A-Za-z0-9_' '_')
    response_file="$OUT_DIR/$CURRENT_PHASE-shell-uid-${file_label}-read.txt"
    if ! adb_su "su 2000 -c id" > "$id_file" 2>&1; then
        warn "unable to run shell UID read probe on this device; see $id_file"
        return
    fi
    if adb_su "su 2000 -c $(shell_quote "cat $(shell_quote "$path") >/dev/null")" \
        > "$response_file" 2>&1; then
        fail "shell UID can read $label"
    else
        pass "shell UID cannot read $label"
    fi
}

check_control_file_permissions() {
    local work_dir="$1"
    local app_uid="$2"
    check_control_path_stat "DNS work directory" "$work_dir" "$app_uid"
    check_control_path_stat "daemon config file" "$work_dir/afwall_dnsd.conf" "$app_uid"
    check_control_path_stat "control token file" "$work_dir/afwall_dnsd.control" "$app_uid"
    check_control_path_stat "control socket" "$work_dir/afwall_dnsd.sock" "$app_uid"
    check_shell_uid_cannot_read_sensitive_file "the daemon config" "$work_dir/afwall_dnsd.conf"
    check_shell_uid_cannot_read_sensitive_file "the daemon control token" "$work_dir/afwall_dnsd.control"
}

check_daemon_process() {
    capture daemon-process.txt "$ADB" shell su -c "ps -A 2>/dev/null | grep afwall_dnsd || true"
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        pass "daemon process is running"
    else
        fail "daemon process not found"
    fi
}

check_redirect_rules() {
    capture iptables-dns.txt "$ADB" shell su -c "iptables-save 2>/dev/null | grep -E 'afwall-dns|afwall_dns' || true"
    capture ip6tables-dns.txt "$ADB" shell su -c "ip6tables-save 2>/dev/null | grep -E 'afwall-dns|afwall_dns' || true"
    capture nft-dns.txt "$ADB" shell su -c "nft list ruleset 2>/dev/null | grep -E 'afwall_dns|afwall-dns' || true"
    if adb_su "iptables-save 2>/dev/null | grep -q 'afwall-dns'"; then
        pass "IPv4 DNS redirect rules are present"
    else
        fail "IPv4 DNS redirect rules not found"
    fi
    if adb_su "ip6tables-save 2>/dev/null | grep -q 'afwall-dns6'"; then
        pass "IPv6 DNS redirect rules are present"
    else
        warn "IPv6 DNS redirect rules not found; this is expected if IPv6 capture is disabled"
    fi
}

check_redirect_rules_absent() {
    capture iptables-dns-absent.txt "$ADB" shell su -c "iptables-save 2>/dev/null | grep -E 'afwall-dns|afwall_dns' || true"
    capture ip6tables-dns-absent.txt "$ADB" shell su -c "ip6tables-save 2>/dev/null | grep -E 'afwall-dns|afwall_dns' || true"
    capture nft-dns-absent.txt "$ADB" shell su -c "nft list ruleset 2>/dev/null | grep -E 'afwall_dns|afwall-dns' || true"
    if adb_su "iptables-save 2>/dev/null | grep -q 'afwall-dns'"; then
        fail "IPv4 DNS redirect rules are still present after cleanup"
    else
        pass "IPv4 DNS redirect rules are absent after cleanup"
    fi
    if adb_su "ip6tables-save 2>/dev/null | grep -q 'afwall-dns6'"; then
        fail "IPv6 DNS redirect rules are still present after cleanup"
    else
        pass "IPv6 DNS redirect rules are absent after cleanup"
    fi
    if adb_su "command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'afwall_dns'"; then
        fail "nft DNS redirect table/rules are still present after cleanup"
    else
        pass "nft DNS redirect table/rules are absent after cleanup"
    fi
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

send_root_control_unix() {
    local work_dir="$1"
    local nc_cmd="$2"
    local control_command="$3"
    adb_su "TOKEN=\$(cat $(shell_quote "$work_dir/afwall_dnsd.control") 2>/dev/null); printf 'token %s\n%s\n' \"\$TOKEN\" $(shell_quote "$control_command") | $nc_cmd -U $(shell_quote "$work_dir/afwall_dnsd.sock") 2>&1 || true"
}

send_root_control_tcp() {
    local work_dir="$1"
    local nc_cmd="$2"
    local port="$3"
    local control_command="$4"
    adb_su "TOKEN=\$(cat $(shell_quote "$work_dir/afwall_dnsd.control") 2>/dev/null); printf 'token %s\n%s\n' \"\$TOKEN\" $(shell_quote "$control_command") | $nc_cmd 127.0.0.1 $(shell_quote "$port") 2>&1 || true"
}

check_external_control_rejection() {
    local work_dir="$1"
    local nc_cmd
    local response_file="$OUT_DIR/$CURRENT_PHASE-external-root-control-response.txt"
    if ! nc_cmd=$(find_unix_nc); then
        warn "no Unix-domain nc client found on device; external control rejection probe skipped"
        return
    fi
    adb_su "TOKEN=\$(cat '$work_dir/afwall_dnsd.control' 2>/dev/null); printf 'token %s\nstatus\n' \"\$TOKEN\" | $nc_cmd -U '$work_dir/afwall_dnsd.sock' 2>&1 || true" > "$response_file" || true
    if grep -q '^error unauthorized' "$response_file"; then
        pass "root-side external control probe was rejected"
    else
        fail "root-side external control probe was not rejected; see $response_file"
    fi
}

check_adb_debug_control_allowed() {
    local work_dir="$1"
    local nc_cmd
    local tcp_port
    local transport=""
    local response_file="$OUT_DIR/$CURRENT_PHASE-adb-debug-root-control-response.txt"
    local bad_response_file="$OUT_DIR/$CURRENT_PHASE-adb-debug-bad-token-response.txt"
    if nc_cmd=$(find_unix_nc); then
        send_root_control_unix "$work_dir" "$nc_cmd" status > "$response_file" || true
        if grep -q '^running=1' "$response_file" \
            && grep -q '^control_adb_debug_enabled=1$' "$response_file"; then
            transport="unix"
        fi
    fi
    if [ -z "$transport" ]; then
        if tcp_port=$(read_control_tcp_port "$work_dir") && nc_cmd=$(find_tcp_nc); then
            send_root_control_tcp "$work_dir" "$nc_cmd" "$tcp_port" status > "$response_file" || true
            if grep -q '^running=1' "$response_file" \
                && grep -q '^control_adb_debug_enabled=1$' "$response_file"; then
                transport="tcp"
            fi
        fi
    fi
    if [ "$transport" = "unix" ]; then
        pass "root-over-ADB debug control probe succeeded over Unix socket"
        adb_su "printf 'token %s\nstatus\n' '0000000000000000000000000000000000000000000000000000000000000000' | $nc_cmd -U $(shell_quote "$work_dir/afwall_dnsd.sock") 2>&1 || true" > "$bad_response_file" || true
    elif [ "$transport" = "tcp" ]; then
        pass "root-over-ADB debug control probe succeeded over loopback TCP"
        adb_su "printf 'token %s\nstatus\n' '0000000000000000000000000000000000000000000000000000000000000000' | $nc_cmd 127.0.0.1 $(shell_quote "$tcp_port") 2>&1 || true" > "$bad_response_file" || true
    else
        if [ ! -s "$response_file" ]; then
            echo "probe_error=no_usable_unix_or_tcp_control_transport" > "$response_file"
        fi
        fail "root-over-ADB debug control probe failed or setting is disabled; see $response_file"
        return
    fi
    if grep -q '^error unauthorized' "$bad_response_file"; then
        pass "root-over-ADB debug control still rejects a bad token"
    else
        fail "root-over-ADB debug control accepted a bad token; see $bad_response_file"
    fi
}

write_control_probe_script() {
    local local_script="$1"
    local work_dir="$2"
    local nc_cmd="$3"
    local control_command="${4:-status}"
    {
        printf '#!/system/bin/sh\n'
        printf 'WORK_DIR=%s\n' "$(shell_quote "$work_dir")"
        printf 'NC_CMD=%s\n' "$(shell_quote "$nc_cmd")"
        printf 'CONTROL_COMMAND=%s\n' "$(shell_quote "$control_command")"
        printf 'TOKEN=$(cat "$WORK_DIR/afwall_dnsd.control" 2>/dev/null || true)\n'
        printf 'if [ -z "$TOKEN" ]; then echo "probe_error=token_unreadable"; exit 1; fi\n'
        printf 'printf '"'"'token %%s\\n%%s\\n'"'"' "$TOKEN" "$CONTROL_COMMAND" | $NC_CMD -U "$WORK_DIR/afwall_dnsd.sock" 2>&1\n'
    } > "$local_script"
}

check_app_control_authorized() {
    local work_dir="$1"
    local app_uid
    local nc_cmd
    local token_check_file="$OUT_DIR/$CURRENT_PHASE-app-uid-token-read.txt"
    local push_log="$OUT_DIR/$CURRENT_PHASE-app-uid-control-probe-push.txt"
    local response_file="$OUT_DIR/$CURRENT_PHASE-app-uid-control-response.txt"
    local local_script="$OUT_DIR/$CURRENT_PHASE-app-uid-control-probe-device.sh"
    local remote_script="/data/local/tmp/afwall_dns_probe_$$.sh"
    local token_check

    if ! app_uid=$(detect_app_uid); then
        fail "unable to detect AFWall app UID for authorized control probe"
        return
    fi
    printf '%s\n' "$app_uid" > "$OUT_DIR/$CURRENT_PHASE-app-uid.txt"
    pass "AFWall app UID detected: $app_uid"

    token_check="test -r $(shell_quote "$work_dir/afwall_dnsd.control")"
    if adb_su "su $(shell_quote "$app_uid") -c $(shell_quote "$token_check")" > "$token_check_file" 2>&1; then
        pass "AFWall app UID can read the daemon control token"
    else
        fail "AFWall app UID cannot read the daemon control token; see $token_check_file"
        return
    fi

    if ! nc_cmd=$(find_unix_nc); then
        warn "no Unix-domain nc client found on device; app UID authorized control probe skipped"
        return
    fi

    write_control_probe_script "$local_script" "$work_dir" "$nc_cmd"
    if ! "$ADB" push "$local_script" "$remote_script" > "$push_log" 2>&1; then
        fail "unable to push app UID control probe script; see $push_log"
        return
    fi
    adb_su "chmod 755 $(shell_quote "$remote_script")" >/dev/null 2>&1 || true
    adb_su "su $(shell_quote "$app_uid") -c $(shell_quote "$remote_script")" > "$response_file" 2>&1 || true
    adb_su "rm -f $(shell_quote "$remote_script")" >/dev/null 2>&1 || true

    if grep -q '^running=1' "$response_file" \
        && grep -q '^control_peer_uid_enforced=1' "$response_file"; then
        pass "AFWall app UID authorized control probe succeeded"
    else
        fail "AFWall app UID authorized control probe failed; see $response_file"
    fi
    if grep -q '^fail_open_control_supported=1$' "$response_file"; then
        pass "daemon advertises authenticated fail-open control support"
    else
        fail "daemon did not advertise authenticated fail-open control support; see $response_file"
    fi
    if grep -q '^cleanup_iptables_safe=1$' "$response_file" \
        && grep -q '^cleanup_ip6tables_safe=1$' "$response_file"; then
        pass "daemon cleanup tools are available for fail-open control cleanup"
    else
        fail "daemon cleanup tools are not fully available; see $response_file"
    fi
}

check_query_activity() {
    local work_dir="$1"
    capture query-log-tail.txt "$ADB" shell su -c "tail -n 200 '$work_dir/afwall_dnsd.log' 2>&1 || true"
    if root_test "-s '$work_dir/afwall_dnsd.log'"; then
        pass "DNS query log has entries"
    else
        warn "DNS query log is empty; run a DNS lookup on-device and rerun validation"
    fi
}

run_daemon_restart_check() {
    CURRENT_PHASE="daemon-restart"
    local work_dir
    local before_pid
    local after_pid
    local before_restarts
    local after_restarts
    local kill_log="$OUT_DIR/$CURRENT_PHASE-kill-daemon.txt"

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi
    before_pid=$(daemon_pid "$work_dir")
    before_restarts=$(restart_count "$work_dir")
    printf 'work_dir=%s\nbefore_pid=%s\nbefore_restarts=%s\n' \
        "$work_dir" "${before_pid:-missing}" "$before_restarts" \
        > "$OUT_DIR/$CURRENT_PHASE-before.txt"
    if [ -z "$before_pid" ]; then
        fail "[$CURRENT_PHASE] daemon PID missing before restart check"
        return
    fi

    adb_su "kill -TERM $(shell_quote "$before_pid")" > "$kill_log" 2>&1 || true
    if ! wait_for_supervisor_ready "$work_dir"; then
        capture supervisor-status-after-kill.txt "$ADB" shell su -c "$(shell_quote "$work_dir/afwall_dnsd_supervisor.sh") status 2>&1 || true"
        fail "[$CURRENT_PHASE] supervisor did not report readiness after daemon kill"
        return
    fi

    after_pid=$(daemon_pid "$work_dir")
    after_restarts=$(restart_count "$work_dir")
    printf 'work_dir=%s\nafter_pid=%s\nafter_restarts=%s\n' \
        "$work_dir" "${after_pid:-missing}" "$after_restarts" \
        > "$OUT_DIR/$CURRENT_PHASE-after.txt"
    capture supervisor-log-after-kill.txt "$ADB" shell su -c "tail -n 120 '$work_dir/afwall_dnsd_supervisor.log' 2>&1 || true"
    capture daemon-events-after-kill.txt "$ADB" shell su -c "tail -n 120 '$work_dir/afwall_dnsd_events.log' 2>&1 || true"

    if [ -n "$after_pid" ] && [ "$after_pid" != "$before_pid" ]; then
        pass "daemon restarted with a new PID after kill"
    else
        fail "daemon PID did not change after kill"
    fi
    if [ "${after_restarts:-0}" -gt "$before_restarts" ]; then
        pass "supervisor restart counter increased after daemon kill"
    else
        fail "supervisor restart counter did not increase after daemon kill"
    fi
    check_redirect_rules
}

run_daemon_fail_open_check() {
    CURRENT_PHASE="daemon-fail-open"
    local work_dir
    local app_uid
    local nc_cmd
    local push_log="$OUT_DIR/$CURRENT_PHASE-app-uid-fail-open-push.txt"
    local response_file="$OUT_DIR/$CURRENT_PHASE-app-uid-fail-open-response.txt"
    local local_script="$OUT_DIR/$CURRENT_PHASE-app-uid-fail-open-device.sh"
    local remote_script="/data/local/tmp/afwall_dns_fail_open_$$.sh"
    local restore_log="$OUT_DIR/$CURRENT_PHASE-restore.txt"

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi
    if ! app_uid=$(detect_app_uid); then
        fail "[$CURRENT_PHASE] unable to detect AFWall app UID"
        return
    fi
    if ! nc_cmd=$(find_unix_nc); then
        warn "no Unix-domain nc client found on device; daemon fail-open control probe skipped"
        return
    fi

    if ! wait_for_supervisor_ready "$work_dir"; then
        capture fail-open-before-status.txt "$ADB" shell su -c "$(shell_quote "$work_dir/afwall_dnsd_supervisor.sh") status 2>&1 || true"
        fail "[$CURRENT_PHASE] service was not ready before fail-open probe"
        return
    fi

    adb_su "rm -f $(shell_quote "$work_dir/afwall_dnsd.enabled")" >/dev/null 2>&1 || true
    write_control_probe_script "$local_script" "$work_dir" "$nc_cmd" "fail_open"
    if ! "$ADB" push "$local_script" "$remote_script" > "$push_log" 2>&1; then
        fail "unable to push app UID fail-open probe script; see $push_log"
        return
    fi
    adb_su "chmod 755 $(shell_quote "$remote_script")" >/dev/null 2>&1 || true
    adb_su "su $(shell_quote "$app_uid") -c $(shell_quote "$remote_script")" > "$response_file" 2>&1 || true
    adb_su "rm -f $(shell_quote "$remote_script")" >/dev/null 2>&1 || true
    sleep 2

    capture fail-open-workdir.txt "$ADB" shell su -c "ls -la '$work_dir' 2>&1 || true"
    capture fail-open-daemon-events.txt "$ADB" shell su -c "tail -n 160 '$work_dir/afwall_dnsd_events.log' 2>&1 || true"
    capture fail-open-supervisor-log.txt "$ADB" shell su -c "tail -n 160 '$work_dir/afwall_dnsd_supervisor.log' 2>&1 || true"

    if grep -q '^ok fail_open' "$response_file"; then
        pass "AFWall app UID fail-open control command succeeded"
    else
        fail "AFWall app UID fail-open control command failed; see $response_file"
    fi
    if adb_su "test ! -e $(shell_quote "$work_dir/afwall_dnsd.enabled")"; then
        pass "daemon fail-open probe cleared the enable marker"
    else
        fail "daemon fail-open probe left the enable marker behind"
    fi
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        fail "daemon is still running after authenticated fail-open probe"
    else
        pass "daemon stopped after authenticated fail-open probe"
    fi
    check_redirect_rules_absent

    supervisor_command "$work_dir" start > "$restore_log" 2>&1 || true
    if wait_for_supervisor_ready "$work_dir"; then
        pass "DNS service restored after daemon fail-open probe"
        check_redirect_rules
    else
        fail "DNS service did not restore after daemon fail-open probe; see $restore_log"
    fi
}

run_orphan_service_check() {
    CURRENT_PHASE="orphan-service"
    local work_dir
    local probe_dir="/data/local/tmp/afwall_dns_orphan_probe_$$"
    local fake_package="${PACKAGE}.missing.$$"
    local prepare_log="$OUT_DIR/$CURRENT_PHASE-prepare.txt"
    local run_log="$OUT_DIR/$CURRENT_PHASE-run.txt"
    local restore_log="$OUT_DIR/$CURRENT_PHASE-restore.txt"
    local prepare_cmd

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi
    prepare_cmd="PROBE=$(shell_quote "$probe_dir"); WORK=$(shell_quote "$work_dir"); MOD=$(shell_quote "$MODULE_DIR"); FAKE=$(shell_quote "$fake_package"); "
    prepare_cmd+="rm -rf \"\$PROBE\"; mkdir -p \"\$PROBE\" "
    prepare_cmd+="&& cp \"\$MOD/service.sh\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& cp \"\$WORK/afwall_dnsd_cleanup.sh\" \"\$PROBE/cleanup.sh\" "
    prepare_cmd+="&& sed -i \"s|^PACKAGE=.*|PACKAGE='\$FAKE'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& sed -i \"s|^PACKAGE=.*|PACKAGE='\$FAKE'|\" \"\$PROBE/cleanup.sh\" "
    prepare_cmd+="&& sed -i \"s|^CLEANUP=.*|CLEANUP='\$PROBE/cleanup.sh'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& chmod 755 \"\$PROBE/service.sh\" \"\$PROBE/cleanup.sh\""
    if ! adb_su "$prepare_cmd" > "$prepare_log" 2>&1; then
        fail "[$CURRENT_PHASE] unable to prepare orphan service probe; see $prepare_log"
        return
    fi

    adb_su "$(shell_quote "$probe_dir/service.sh")" > "$run_log" 2>&1 || true
    capture orphan-probe-listing.txt "$ADB" shell su -c "ls -la '$probe_dir' 2>&1 || true"
    capture cleanup-log-after-orphan.txt "$ADB" shell su -c "tail -n 120 '$work_dir/afwall_dnsd_cleanup.log' 2>&1 || true"
    capture module-log-after-orphan.txt "$ADB" shell su -c "tail -n 120 /data/local/tmp/afwall_dnsd_module.log 2>&1 || true"

    if adb_su "test -f $(shell_quote "$probe_dir/disable") && test -f $(shell_quote "$probe_dir/remove")"; then
        pass "orphan service probe scheduled module disable/remove in its module directory"
    else
        fail "orphan service probe did not schedule module disable/remove"
    fi
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        fail "daemon is still running after orphan cleanup probe"
    else
        pass "daemon stopped after orphan cleanup probe"
    fi
    check_redirect_rules_absent

    supervisor_command "$work_dir" start > "$restore_log" 2>&1 || true
    if wait_for_supervisor_ready "$work_dir"; then
        pass "DNS service restored after orphan cleanup probe"
        check_redirect_rules
    else
        fail "DNS service did not restore after orphan cleanup probe; see $restore_log"
    fi
    adb_su "rm -rf $(shell_quote "$probe_dir")" >/dev/null 2>&1 || true
}

run_stale_marker_check() {
    CURRENT_PHASE="stale-marker"
    local work_dir
    local probe_dir="/data/local/tmp/afwall_dns_marker_probe_$$"
    local fake_marker="$probe_dir/missing-enabled-marker"
    local prepare_log="$OUT_DIR/$CURRENT_PHASE-prepare.txt"
    local run_log="$OUT_DIR/$CURRENT_PHASE-run.txt"
    local restore_log="$OUT_DIR/$CURRENT_PHASE-restore.txt"
    local prepare_cmd

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi
    prepare_cmd="PROBE=$(shell_quote "$probe_dir"); WORK=$(shell_quote "$work_dir"); MOD=$(shell_quote "$MODULE_DIR"); MARKER=$(shell_quote "$fake_marker"); "
    prepare_cmd+="rm -rf \"\$PROBE\"; mkdir -p \"\$PROBE\" "
    prepare_cmd+="&& cp \"\$MOD/service.sh\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& cp \"\$WORK/afwall_dnsd_cleanup.sh\" \"\$PROBE/cleanup.sh\" "
    prepare_cmd+="&& sed -i \"s|^CLEANUP=.*|CLEANUP='\$PROBE/cleanup.sh'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& sed -i \"s|^MARKER=.*|MARKER='\$MARKER'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& sed -i \"s|^MARKER=.*|MARKER='\$MARKER'|\" \"\$PROBE/cleanup.sh\" "
    prepare_cmd+="&& chmod 755 \"\$PROBE/service.sh\" \"\$PROBE/cleanup.sh\""
    if ! adb_su "$prepare_cmd" > "$prepare_log" 2>&1; then
        fail "[$CURRENT_PHASE] unable to prepare stale marker probe; see $prepare_log"
        return
    fi

    adb_su "$(shell_quote "$probe_dir/service.sh")" > "$run_log" 2>&1 || true
    capture stale-marker-probe-listing.txt "$ADB" shell su -c "ls -la '$probe_dir' 2>&1 || true"
    capture cleanup-log-after-stale-marker.txt "$ADB" shell su -c "tail -n 120 '$work_dir/afwall_dnsd_cleanup.log' 2>&1 || true"
    capture module-log-after-stale-marker.txt "$ADB" shell su -c "tail -n 120 /data/local/tmp/afwall_dnsd_module.log 2>&1 || true"

    if adb_su "test -f $(shell_quote "$probe_dir/disable") && test -f $(shell_quote "$probe_dir/remove")"; then
        pass "stale marker probe scheduled module disable/remove in its module directory"
    else
        fail "stale marker probe did not schedule module disable/remove"
    fi
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        fail "daemon is still running after stale marker cleanup probe"
    else
        pass "daemon stopped after stale marker cleanup probe"
    fi
    check_redirect_rules_absent

    supervisor_command "$work_dir" start > "$restore_log" 2>&1 || true
    if wait_for_supervisor_ready "$work_dir"; then
        pass "DNS service restored after stale marker cleanup probe"
        check_redirect_rules
    else
        fail "DNS service did not restore after stale marker cleanup probe; see $restore_log"
    fi
    adb_su "rm -rf $(shell_quote "$probe_dir")" >/dev/null 2>&1 || true
}

run_embedded_cleanup_check() {
    CURRENT_PHASE="embedded-cleanup"
    local work_dir
    local probe_dir="/data/local/tmp/afwall_dns_embedded_cleanup_probe_$$"
    local fake_package="${PACKAGE}.missing.$$"
    local missing_cleanup="$probe_dir/missing-cleanup.sh"
    local prepare_log="$OUT_DIR/$CURRENT_PHASE-prepare.txt"
    local run_log="$OUT_DIR/$CURRENT_PHASE-run.txt"
    local restore_log="$OUT_DIR/$CURRENT_PHASE-restore.txt"
    local prepare_cmd

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi
    prepare_cmd="PROBE=$(shell_quote "$probe_dir"); MOD=$(shell_quote "$MODULE_DIR"); FAKE=$(shell_quote "$fake_package"); CLEAN=$(shell_quote "$missing_cleanup"); "
    prepare_cmd+="rm -rf \"\$PROBE\"; mkdir -p \"\$PROBE\" "
    prepare_cmd+="&& cp \"\$MOD/service.sh\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& sed -i \"s|^PACKAGE=.*|PACKAGE='\$FAKE'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& sed -i \"s|^CLEANUP=.*|CLEANUP='\$CLEAN'|\" \"\$PROBE/service.sh\" "
    prepare_cmd+="&& chmod 755 \"\$PROBE/service.sh\""
    if ! adb_su "$prepare_cmd" > "$prepare_log" 2>&1; then
        fail "[$CURRENT_PHASE] unable to prepare embedded cleanup probe; see $prepare_log"
        return
    fi

    adb_su "$(shell_quote "$probe_dir/service.sh")" > "$run_log" 2>&1 || true
    capture embedded-cleanup-probe-listing.txt "$ADB" shell su -c "ls -la '$probe_dir' 2>&1 || true"
    capture module-log-after-embedded-cleanup.txt "$ADB" shell su -c "tail -n 160 /data/local/tmp/afwall_dnsd_module.log 2>&1 || true"

    if adb_su "test -f $(shell_quote "$probe_dir/disable") && test -f $(shell_quote "$probe_dir/remove")"; then
        pass "embedded cleanup probe scheduled module disable/remove in its module directory"
    else
        fail "embedded cleanup probe did not schedule module disable/remove"
    fi
    if grep -q 'cleanup_service_state: not found\|cleanup_service_state: inaccessible' "$run_log"; then
        fail "embedded cleanup function missing from copied Magisk service"
    fi
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        fail "daemon is still running after embedded cleanup probe"
    else
        pass "daemon stopped after embedded cleanup probe"
    fi
    check_redirect_rules_absent

    supervisor_command "$work_dir" start > "$restore_log" 2>&1 || true
    if wait_for_supervisor_ready "$work_dir"; then
        pass "DNS service restored after embedded cleanup probe"
        check_redirect_rules
    else
        fail "DNS service did not restore after embedded cleanup probe; see $restore_log"
    fi
    adb_su "rm -rf $(shell_quote "$probe_dir")" >/dev/null 2>&1 || true
}

run_direct_cleanup_check() {
    CURRENT_PHASE="direct-cleanup"
    local work_dir
    local cleanup_log="$OUT_DIR/$CURRENT_PHASE-run.txt"
    local restore_log="$OUT_DIR/$CURRENT_PHASE-restore.txt"
    local cleanup_cmd

    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found"
        return
    fi

    cleanup_cmd="WORK=$(shell_quote "$work_dir"); "
    cleanup_cmd+="ipt() { if command -v iptables >/dev/null 2>&1; then iptables \"\$@\"; else return 0; fi; }; "
    cleanup_cmd+="ip6t() { if command -v ip6tables >/dev/null 2>&1; then ip6tables \"\$@\"; else return 0; fi; }; "
    cleanup_cmd+="stop_named_daemon() { signal=\"\$1\"; "
    cleanup_cmd+="if command -v pidof >/dev/null 2>&1; then for p in \$(pidof afwall_dnsd 2>/dev/null); do kill \"\$signal\" \"\$p\" 2>/dev/null || true; done; fi; "
    cleanup_cmd+="for proc in /proc/[0-9]*; do [ -r \"\$proc/comm\" ] || continue; name=\$(cat \"\$proc/comm\" 2>/dev/null || true); [ \"\$name\" = afwall_dnsd ] || continue; pid=\${proc#/proc/}; kill \"\$signal\" \"\$pid\" 2>/dev/null || true; done; "
    cleanup_cmd+="}; "
    cleanup_cmd+="cleanup_redirects() { "
    cleanup_cmd+="ipt -D OUTPUT -m mark --mark 0xaf053 -j ACCEPT >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -D OUTPUT -m mark --mark 0xaf053 -j ACCEPT >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -D OUTPUT -j afwall-dns-out >/dev/null 2>&1 || true; ipt -F afwall-dns-out >/dev/null 2>&1 || true; ipt -X afwall-dns-out >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -D OUTPUT -j afwall-dns-out >/dev/null 2>&1 || true; ip6t -F afwall-dns-out >/dev/null 2>&1 || true; ip6t -X afwall-dns-out >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -D OUTPUT -p udp --dport 53 -j afwall-dns >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -D OUTPUT -p tcp --dport 53 -j afwall-dns >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -D PREROUTING -p udp --dport 53 -j afwall-dns-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -D PREROUTING -p tcp --dport 53 -j afwall-dns-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -F afwall-dns >/dev/null 2>&1 || true; ipt -t nat -F afwall-dns-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ipt -t nat -X afwall-dns >/dev/null 2>&1 || true; ipt -t nat -X afwall-dns-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -D OUTPUT -p udp --dport 53 -j afwall-dns6 >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -D OUTPUT -p tcp --dport 53 -j afwall-dns6 >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -D PREROUTING -p udp --dport 53 -j afwall-dns6-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -D PREROUTING -p tcp --dport 53 -j afwall-dns6-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -F afwall-dns6 >/dev/null 2>&1 || true; ip6t -t nat -F afwall-dns6-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="ip6t -t nat -X afwall-dns6 >/dev/null 2>&1 || true; ip6t -t nat -X afwall-dns6-pre >/dev/null 2>&1 || true; "
    cleanup_cmd+="if command -v nft >/dev/null 2>&1; then nft delete table ip afwall_dns >/dev/null 2>&1 || true; nft delete table ip6 afwall_dns6 >/dev/null 2>&1 || true; fi; "
    cleanup_cmd+="}; "
    cleanup_cmd+="rm -f \"\$WORK/afwall_dnsd.enabled\" 2>/dev/null || true; "
    cleanup_cmd+="for PIDFILE in \"\$WORK/afwall_dnsd_supervisor.pid\" \"\$WORK/afwall_dnsd.pid\"; do [ -f \"\$PIDFILE\" ] || continue; pid=\$(cat \"\$PIDFILE\" 2>/dev/null || true); case \"\$pid\" in ''|*[!0-9]*) ;; *) kill -TERM \"\$pid\" 2>/dev/null || true ;; esac; done; "
    cleanup_cmd+="stop_named_daemon -TERM; sleep 1; "
    cleanup_cmd+="for PIDFILE in \"\$WORK/afwall_dnsd_supervisor.pid\" \"\$WORK/afwall_dnsd.pid\"; do [ -f \"\$PIDFILE\" ] || continue; pid=\$(cat \"\$PIDFILE\" 2>/dev/null || true); case \"\$pid\" in ''|*[!0-9]*) ;; *) kill -KILL \"\$pid\" 2>/dev/null || true ;; esac; done; "
    cleanup_cmd+="stop_named_daemon -KILL; "
    cleanup_cmd+="rm -f \"\$WORK/afwall_dnsd_supervisor.pid\" \"\$WORK/afwall_dnsd.pid\" \"\$WORK/afwall_dnsd.heartbeat\" \"\$WORK/afwall_dnsd.sock\" 2>/dev/null || true; "
    cleanup_cmd+="cleanup_redirects; true"

    adb_su "$cleanup_cmd" > "$cleanup_log" 2>&1 || true
    capture direct-cleanup-workdir.txt "$ADB" shell su -c "ls -la '$work_dir' 2>&1 || true"

    if adb_su "test ! -e $(shell_quote "$work_dir/afwall_dnsd.enabled")"; then
        pass "direct cleanup cleared the enable marker"
    else
        fail "direct cleanup did not clear the enable marker"
    fi
    if adb_su "test ! -e $(shell_quote "$work_dir/afwall_dnsd.pid") && test ! -e $(shell_quote "$work_dir/afwall_dnsd_supervisor.pid") && test ! -e $(shell_quote "$work_dir/afwall_dnsd.heartbeat") && test ! -S $(shell_quote "$work_dir/afwall_dnsd.sock")"; then
        pass "direct cleanup cleared transient daemon state files"
    else
        fail "direct cleanup left transient daemon state files behind"
    fi
    if adb_su "ps -A 2>/dev/null | grep -q '[a]fwall_dnsd'"; then
        fail "daemon is still running after direct cleanup probe"
    else
        pass "daemon stopped after direct cleanup probe"
    fi
    check_redirect_rules_absent

    supervisor_command "$work_dir" start > "$restore_log" 2>&1 || true
    if wait_for_supervisor_ready "$work_dir"; then
        pass "DNS service restored after direct cleanup probe"
        check_redirect_rules
    else
        fail "DNS service did not restore after direct cleanup probe; see $restore_log"
    fi
}

run_optional_recovery_checks() {
    if [ "$DAEMON_RESTART_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_daemon_restart_check
        else
            warn "skipping daemon restart check because earlier validation had failures"
        fi
    fi
    if [ "$DAEMON_FAIL_OPEN_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_daemon_fail_open_check
        else
            warn "skipping daemon fail-open check because earlier validation had failures"
        fi
    fi
    if [ "$STALE_MARKER_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_stale_marker_check
        else
            warn "skipping stale marker check because earlier validation had failures"
        fi
    fi
    if [ "$EMBEDDED_CLEANUP_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_embedded_cleanup_check
        else
            warn "skipping embedded cleanup check because earlier validation had failures"
        fi
    fi
    if [ "$ORPHAN_SERVICE_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_orphan_service_check
        else
            warn "skipping orphan service check because earlier validation had failures"
        fi
    fi
    if [ "$DIRECT_CLEANUP_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_direct_cleanup_check
        else
            warn "skipping direct cleanup check because earlier validation had failures"
        fi
    fi
}

run_runtime_checks() {
    CURRENT_PHASE="$1"
    local work_dir
    if ! work_dir=$(detect_work_dir); then
        fail "[$CURRENT_PHASE] AFWall DNS work directory not found; enable DNS protection and apply rules first"
        return
    fi
    log "[$CURRENT_PHASE] Detected DNS work dir: $work_dir"
    printf '%s\n' "$work_dir" > "$OUT_DIR/$CURRENT_PHASE-work-dir.txt"

    check_module_state
    check_work_dir_state "$work_dir"
    check_daemon_process
    check_redirect_rules
    if [ "$ADB_DEBUG_CONTROL_CHECK" -eq 1 ]; then
        check_adb_debug_control_allowed "$work_dir"
    else
        check_external_control_rejection "$work_dir"
    fi
    check_app_control_authorized "$work_dir"
    check_query_activity "$work_dir"
}

wait_for_boot_completed() {
    local deadline
    local boot_completed
    "$ADB" wait-for-device
    deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
    while [ "$SECONDS" -lt "$deadline" ]; do
        boot_completed=$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)
        if [ "$boot_completed" = "1" ]; then
            pass "device reported sys.boot_completed=1"
            sleep "$POST_BOOT_SETTLE_SECONDS"
            return
        fi
        sleep 2
    done
    fail "device did not complete boot within ${BOOT_TIMEOUT_SECONDS}s"
    exit 1
}

run_reboot_check() {
    CURRENT_PHASE="reboot"
    log "Reboot validation requested; rebooting device now"
    capture reboot-command.txt "$ADB" reboot
    wait_for_boot_completed
    check_root_and_magisk
    run_runtime_checks postboot
}

main() {
    log "Writing runtime evidence to $OUT_DIR"
    single_device_check
    install_apk_if_requested
    check_root_and_magisk
    run_runtime_checks preboot
    run_optional_recovery_checks

    if [ "$REBOOT_CHECK" -eq 1 ]; then
        if [ "$failures" -eq 0 ]; then
            run_reboot_check
        else
            warn "skipping reboot check because preboot validation had failures"
        fi
    fi

    log "Validation complete: failures=$failures warnings=$warnings"
    if [ "$failures" -ne 0 ]; then
        exit 1
    fi
}

main "$@"
