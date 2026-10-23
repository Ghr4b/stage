#!/bin/bash
set -euo pipefail

config_file=/var/ossec/etc/ossec.conf

: "${TIJERI_API_TOKEN:?TIJERI_API_TOKEN must be configured}"
: "${TIJERI_WAZUH_WEBHOOK_URL:?TIJERI_WAZUH_WEBHOOK_URL must be configured}"
: "${TIJERI_CA_BUNDLE:?TIJERI_CA_BUNDLE must point to the company CA bundle}"

if [[ ${#TIJERI_API_TOKEN} -lt 32 ]]; then
    printf '%s\n' 'TIJERI_API_TOKEN must contain at least 32 characters.' >&2
    exit 1
fi
if [[ $TIJERI_WAZUH_WEBHOOK_URL != https://* ]]; then
    printf '%s\n' 'TIJERI_WAZUH_WEBHOOK_URL must use HTTPS.' >&2
    exit 1
fi
if [[ ! -r $TIJERI_CA_BUNDLE ]]; then
    printf '%s\n' 'TIJERI_CA_BUNDLE is not readable.' >&2
    exit 1
fi
if [[ ! -f $config_file ]]; then
    printf '%s\n' 'Wazuh ossec.conf was not found.' >&2
    exit 1
fi

indexer_password_file=${TIJERI_WAZUH_INDEXER_PASSWORD_FILE:-}
if [[ -n $indexer_password_file ]]; then
    if [[ ! -r $indexer_password_file ]]; then
        printf '%s\n' 'Wazuh indexer password secret is not readable.' >&2
        exit 1
    fi
    INDEXER_PASSWORD=$(<"$indexer_password_file")
    if [[ ${#INDEXER_PASSWORD} -lt 32 || $INDEXER_PASSWORD == *$'\n'* || $INDEXER_PASSWORD == *$'\r'* ]]; then
        printf '%s\n' 'Wazuh indexer password must be a single line with at least 32 characters.' >&2
        exit 1
    fi
    export INDEXER_PASSWORD
fi

if ! grep -Fq '<name>custom-tijeri</name>' "$config_file"; then
    temporary_config=$(mktemp)
    if ! awk '
        /<\/ossec_config>/ && !inserted {
            print "  <integration>"
            print "    <name>custom-tijeri</name>"
            print "    <group>rescan_trigger</group>"
            print "    <alert_format>json</alert_format>"
            print "  </integration>"
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "$config_file" > "$temporary_config"; then
        rm -f "$temporary_config"
        printf '%s\n' 'Wazuh ossec.conf is missing its closing ossec_config element.' >&2
        exit 1
    fi
    chmod --reference="$config_file" "$temporary_config"
    chown --reference="$config_file" "$temporary_config"
    mv "$temporary_config" "$config_file"
fi

exec /init "$@"
