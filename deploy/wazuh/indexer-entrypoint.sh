#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $(id -u) -ne 0 ]]; then
    printf '%s\n' 'The Tijeri indexer entrypoint must start as root to read the mounted secret.' >&2
    exit 1
fi

installation_dir=/usr/share/wazuh-indexer
security_dir="$installation_dir/opensearch-security"
tools_dir="$installation_dir/plugins/opensearch-security/tools"
data_dir=/var/lib/wazuh-indexer
secret_file="${TIJERI_WAZUH_INDEXER_PASSWORD_FILE:-/run/secrets/wazuh_indexer_password}"
ready_file="$data_dir/.tijeri-security-ready"
internal_users_file="$security_dir/internal_users.yml"
securityadmin="$tools_dir/securityadmin.sh"
hash_tool="$tools_dir/hash.sh"
ca_file="$installation_dir/certs/root-ca.pem"
admin_cert="$installation_dir/certs/admin.pem"
admin_key="$installation_dir/certs/admin-key.pem"

if [[ ! -r $secret_file ]]; then
    printf '%s\n' 'Wazuh indexer password secret is not readable.' >&2
    exit 1
fi

password=$(<"$secret_file")
if [[ ${#password} -lt 32 || $password == *$'\n'* || $password == *$'\r'* ]]; then
    printf '%s\n' 'Wazuh indexer password must be a single line with at least 32 characters.' >&2
    exit 1
fi

hash_output=$(JAVA_HOME="$installation_dir/jdk" bash "$hash_tool" -p "$password" 2>/dev/null) || {
    printf '%s\n' 'Could not generate the Wazuh indexer password hash.' >&2
    exit 1
}
password_hash=$(printf '%s\n' "$hash_output" | awk '/^\$2[aby]\$[0-9][0-9]\$/ { print; exit }')
unset hash_output password
if [[ -z $password_hash ]]; then
    printf '%s\n' 'The Wazuh indexer hash tool returned an unexpected result.' >&2
    exit 1
fi

replace_admin_hash() {
    local source_file=$1
    local target_file=$2
    local replacement_hash=$3

    if ! awk -v replacement_hash="$replacement_hash" '
        $0 == "admin:" { in_admin = 1; print; next }
        in_admin && /^  hash:/ {
            print "  hash: \"" replacement_hash "\""
            changed++
            in_admin = 0
            next
        }
        in_admin && /^[^[:space:]]/ { in_admin = 0 }
        { print }
        END { if (changed != 1) exit 1 }
    ' "$source_file" > "$target_file"; then
        rm -f "$target_file"
        return 1
    fi

    chown 1000:0 "$target_file"
    chmod 660 "$target_file"
    mv "$target_file" "$source_file"
}

temporary_users=$(mktemp "$security_dir/internal_users.yml.XXXXXX")
if ! replace_admin_hash "$internal_users_file" "$temporary_users" "$password_hash"; then
    printf '%s\n' 'Could not update the admin user in the Wazuh indexer configuration.' >&2
    exit 1
fi

export JAVA_HOME="$installation_dir/jdk"
export OPENSEARCH_CONF_DIR="$installation_dir"
mkdir -p "$data_dir"
rm -f "$ready_file"
backup_dir=
backup_log=
indexer_pid=

cleanup() {
    local exit_code=$?
    trap - EXIT
    if [[ -n $indexer_pid ]] && kill -0 "$indexer_pid" 2>/dev/null; then
        kill -TERM "$indexer_pid" 2>/dev/null || true
        wait "$indexer_pid" 2>/dev/null || true
    fi
    if [[ -n $backup_dir ]]; then
        rm -rf -- "$backup_dir"
    fi
    if [[ -n $backup_log ]]; then
        rm -f -- "$backup_log"
    fi
    exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 143' TERM INT

/entrypoint.sh "$@" &
indexer_pid=$!

port_ready=false
for attempt in {1..180}; do
    if (exec 3<>/dev/tcp/127.0.0.1/9200) 2>/dev/null; then
        port_ready=true
        break
    fi
    if ! kill -0 "$indexer_pid" 2>/dev/null; then
        wait "$indexer_pid"
        exit 1
    fi
    sleep 2
done
if [[ $port_ready != true ]]; then
    printf '%s\n' 'Wazuh indexer did not open its TLS listener within six minutes.' >&2
    exit 1
fi

securityadmin_args=(-nhnv -cacert "$ca_file" -cert "$admin_cert" -key "$admin_key" -p 9200 -icl -h localhost)
backup_dir=$(mktemp -d /tmp/tijeri-wazuh-security.XXXXXX)
backup_log=$(mktemp /tmp/tijeri-wazuh-security-log.XXXXXX)

if bash "$securityadmin" -backup "$backup_dir" "${securityadmin_args[@]}" > "$backup_log" 2>&1; then
    backup_users="$backup_dir/internal_users.yml"
    if [[ ! -f $backup_users ]]; then
        printf '%s\n' 'The existing Wazuh security configuration has no internal-users file; refusing to overwrite it.' >&2
        cat "$backup_log" >&2
        exit 1
    fi
    temporary_users="$backup_dir/internal_users.yml.tijeri"
    if ! replace_admin_hash "$backup_users" "$temporary_users" "$password_hash"; then
        printf '%s\n' 'Could not update the existing Wazuh admin user configuration.' >&2
        exit 1
    fi
    if ! bash "$securityadmin" -f "$backup_users" -t internalusers "${securityadmin_args[@]}"; then
        printf '%s\n' 'Could not apply the Wazuh indexer admin credential.' >&2
        exit 1
    fi
else
    if ! grep -Eiq 'no such index|no security index|security index.*does not exist|security index.*does not exists|not yet initialized' "$backup_log"; then
        printf '%s\n' 'Could not safely read the existing Wazuh security configuration; refusing to replace it.' >&2
        cat "$backup_log" >&2
        exit 1
    fi
    printf '%s\n' 'Initializing the Wazuh indexer security configuration.'
    if ! bash "$securityadmin" -cd "$security_dir" "${securityadmin_args[@]}"; then
        printf '%s\n' 'Could not initialize the Wazuh indexer security configuration.' >&2
        exit 1
    fi
fi

touch "$ready_file"
chmod 644 "$ready_file"
printf '%s\n' 'Wazuh indexer security is initialized and ready.'
wait "$indexer_pid"
