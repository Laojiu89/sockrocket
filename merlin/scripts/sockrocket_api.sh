#!/bin/sh
# Authenticated firmware RPC adapter. Per-request dbus keys isolate tabs;
# results are private, atomically published, acknowledged and short-lived.
. /koolshare/scripts/base.sh
umask 077
SOCKROCKET_BIN="${SOCKROCKET_BIN:-/jffs/addons/sockrocket/sockrocket-cli}"
UPLOAD_DIR="${SOCKROCKET_RPC_UPLOAD_DIR:-/tmp/upload}"
RUNTIME_DIR="${SOCKROCKET_RPC_RUNTIME_DIR:-/tmp/sockrocket-rpc}"
ACTION="${2:-$1}"
SEQ="$3"
ENCODING=raw
respond() {
    curl --max-time 3 -fsS -X POST --data "${1:-$ID}" "http://127.0.0.1:3030/_resp/$ID" >/dev/null 2>&1 || true
}
# New clients pass a cryptographic nonce; retain compatibility with old pages.
if [ -n "$SEQ" ]; then
    case "$SEQ" in *[!0-9a-f]*|'') respond; exit 1 ;; esac
    [ "${#SEQ}" -eq 32 ] || { respond; exit 1; }
    # Some Softcenter versions shell-escape every quote/backslash in fields.
    # Base64 carries UTF-8 JSON without those characters; never eval/unescape it.
    ARGS=$(dbus get "sockrocket_rpc_b64_$SEQ" 2>/dev/null)
    if [ -n "$ARGS" ]; then
        ENCODING=base64
    else
        ARGS=$(dbus get "sockrocket_rpc_body_$SEQ" 2>/dev/null)
    fi
    dbus remove "sockrocket_rpc_b64_$SEQ" >/dev/null 2>&1 || true
    dbus remove "sockrocket_rpc_body_$SEQ" >/dev/null 2>&1 || true
else
    SEQ=$(dbus get sockrocket_rpc_seq 2>/dev/null)
    case "$SEQ" in ''|*[!0-9]*) respond; exit 1 ;; esac
    [ "${#SEQ}" -le 24 ] || { respond; exit 1; }
    ARGS=$(dbus get sockrocket_rpc_args 2>/dev/null)
    dbus remove sockrocket_rpc_args >/dev/null 2>&1 || true
fi
case "$ACTION" in ''|*[!a-z_]* ) respond; exit 1 ;; esac
mkdir -p "$UPLOAD_DIR" "$RUNTIME_DIR" || exit 1
RESULT="$UPLOAD_DIR/sockrocket_rpc_${SEQ}.json"
BODY="$RUNTIME_DIR/rule-body-$SEQ"
# Abandoned uploads never apply partial changes. Expire their private files.
for pending in "$RUNTIME_DIR"/rule-body-*; do
    [ -f "$pending" ] || break
    # Merlin BusyBox find lacks -mmin. Skip the active transfer.
    [ "$pending" != "$BODY" ] || continue
    modified=$(date -r "$pending" +%s 2>/dev/null) || continue
    [ "$(( $(date +%s) - modified ))" -le 120 ] || rm -f "$pending"
done
# Maximum Base64 length for each action's decoded JSON request.
transfer_limit() {
    case "$1" in
        save_config) echo 11184812 ;;
        batch_add_rules|replace_rule_group) echo 5592408 ;;
        *) echo 1398104 ;;
    esac
}
if [ "$ACTION" = rpc_rule_part ]; then
    reject_part() { respond 0; exit 1; }
    offset=$4
    case "$offset" in ''|*[!0-9]*) reject_part ;; esac
    # Older pages omit the action. Allow a rule-sized upload, then enforce
    # the final action's limit independently before dispatch.
    part_limit=$(transfer_limit "${5:-batch_add_rules}")
    [ "${#SEQ}" = 32 ] && [ "${#offset}" -le 8 ] && [ "$offset" -lt "$part_limit" ] || reject_part
    [ "$ENCODING" = base64 ] && [ -n "$ARGS" ] && [ "${#ARGS}" -le 2048 ] || reject_part
    [ "$offset" -le "$((part_limit - ${#ARGS}))" ] || reject_part
    if [ "$offset" = 0 ]; then
        (set -C; : > "$BODY") || reject_part
    fi
    [ -f "$BODY" ] && [ "$(wc -c < "$BODY")" -eq "$offset" ] || reject_part
    printf '%s' "$ARGS" >> "$BODY" || reject_part
    respond
    exit 0
fi
if [ "$ACTION" = rpc_ack ]; then
    rm -f "$RESULT"
    respond
    exit 0
fi
# Compatibility pages may not acknowledge; bound leftover data to minutes.
find "$UPLOAD_DIR" -maxdepth 1 -name 'sockrocket_rpc_*.json' -mmin +2 -exec rm -f {} + 2>/dev/null || true
RAW="$RUNTIME_DIR/response-$SEQ.$$"
TEMP="$RUNTIME_DIR/result-$SEQ.$$"
SLOT=""
missing_body=false
[ -n "$ARGS" ] || { missing_body=true; ARGS="{}"; }
staged=""
if [ -n "$4" ]; then
    # Only one final request can claim the complete body for this nonce.
    staged="$RUNTIME_DIR/rule-body-$SEQ.claimed.$$"
    mv "$BODY" "$staged" 2>/dev/null || :
fi
cleanup() { [ -z "$staged" ] || rm -f "$staged"; rm -f "$RAW" "$TEMP"; [ -z "$SLOT" ] || rm -rf "$SLOT"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# The firmware starts a fresh CGI process per job: cap these independently
# of the long-lived HTTP API. Reserve Stop outside the normal work slots.
if [ "$ACTION" = stop ]; then
    slots="stop"
elif [ "$ACTION" = speedtest_node ]; then
    # Leave two firmware worker slots available for status and controls.
    slots="1 2"
else
    slots="3 4 1 2"
fi
for n in $slots; do
    slot="$RUNTIME_DIR/slot-$n"
    if [ -f "$slot/pid" ]; then
        pid=$(cat "$slot/pid")
        case "$pid" in ''|*[!0-9]*) ;; *) kill -0 "$pid" 2>/dev/null || rm -rf "$slot" ;; esac
    fi
    if mkdir "$slot" 2>/dev/null; then SLOT="$slot"; echo $$ > "$slot/pid"; break; fi
done
# The dbus body is a new request; inherited HTTP CONTENT_LENGTH must not
# truncate its JSON when forwarding to the CGI backend.
request_body() {
    if [ -n "$staged" ]; then cat "$staged"; else printf '%s' "$ARGS"; fi
}
valid_staged_body() {
    limit=$(transfer_limit "$ACTION")
    case "$4" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#4}" -le 8 ] && [ "$4" -gt 0 ] && [ "$4" -le "$limit" ] &&
        [ -f "$staged" ] && [ "$(wc -c < "$staged")" -eq "$4" ]
}
if [ -n "$staged" ]; then ENCODING=base64; fi
case "$ACTION" in
    add_rule|batch_add_rules|replace_rule_group|set_rule_group_enabled|delete_rule_group|add_node|save_config) requires_body=true ;;
    *) requires_body=false ;;
esac
if [ -n "$staged" ] && ! valid_staged_body "$@"; then
    printf '{"ok":false,"msg":"提交内容未完整传到路由器，请保留草稿并重试。"}' > "$TEMP"
elif [ "$requires_body" = true ] && [ -z "$staged" ] && [ "$missing_body" = true ]; then
    printf '{"ok":false,"msg":"路由器未收到提交内容，请保留草稿并重试。"}' > "$TEMP"
elif [ -z "$SLOT" ]; then
    printf '{"error":"Router busy; retry shortly","error_code":"busy"}' > "$TEMP"
elif [ ! -x "$SOCKROCKET_BIN" ]; then
    printf '{"ok":false,"error":"Backend executable unavailable","error_code":"backend_unavailable","stage":"invoke_backend","cause":"NotFound","hint":"通过软件中心重新安装适配机型的完整插件包。"}' > "$TEMP"
elif request_body | SOCKROCKET_LOCAL_RPC=1 SOCKROCKET_RPC_ENCODING="$ENCODING" REQUEST_METHOD=POST CONTENT_LENGTH= QUERY_STRING="action=$ACTION" "$SOCKROCKET_BIN" cgi > "$RAW" 2>/dev/null; then
    sed '1,3d' "$RAW" > "$TEMP"
    [ -s "$TEMP" ] || printf '{"ok":false,"error":"Empty backend response","error_code":"backend_empty_response","stage":"invoke_backend","hint":"通过软件中心重新安装完整插件包，并刷新页面。"}' > "$TEMP"
else
    backend_status=$?
    # Raw stderr can contain subscription credentials. Only expose exit status.
    printf '{"ok":false,"error":"Backend process failed","error_code":"backend_failed","stage":"invoke_backend","exit_code":%s,"hint":"记录退出码并检查系统日志；通过软件中心重新安装完整插件包，勿单独替换二进制。"}' "$backend_status" > "$TEMP"
fi
mv -f "$TEMP" "$RESULT" || exit 1
chmod 600 "$RESULT"
respond
