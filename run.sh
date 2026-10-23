#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/deploy/compose"

COMPOSE_FILE="docker-compose.full.yml"
RUNTIME_ENV=".env.runtime"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || die "Docker is required."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
[[ -f .env ]] || die "Missing deploy/compose/.env. Copy .env.example there and set the required secrets."

umask 077
chmod 600 .env
touch "$RUNTIME_ENV"
chmod 600 "$RUNTIME_ENV"

read_env_value() {
    local file="$1" name="$2"
    awk -F= -v name="$name" '$1 == name { sub(/^[^=]*=/, ""); gsub(/^\"|\"$/, ""); print; exit }' "$file"
}

API_TOKEN="${TIJERI_API_TOKEN:-$(read_env_value .env TIJERI_API_TOKEN)}"
TLS_CERT_PATH="${TLS_CERT_FILE:-$(read_env_value .env TLS_CERT_FILE)}"
TLS_KEY_PATH="${TLS_KEY_FILE:-$(read_env_value .env TLS_KEY_FILE)}"
SERVER_NAME="${TIJERI_SERVER_NAME:-$(read_env_value .env TIJERI_SERVER_NAME)}"
[[ ${#API_TOKEN} -ge 32 ]] || die "Set TIJERI_API_TOKEN to a random value of at least 32 characters in deploy/compose/.env."
for secret_name in POSTGRES_PASSWORD TIJERI_DATABASE_PASSWORD DD_DATABASE_PASSWORD DTRACK_DATABASE_PASSWORD DD_SECRET_KEY DD_AES_KEY DD_ADMIN_PASSWORD NATS_PASSWORD OIDC_SESSION_SECRET; do
	secret_value="$(read_env_value .env "$secret_name")"
	if [[ -v "$secret_name" ]]; then
		secret_value="${!secret_name}"
	fi
	[[ ${#secret_value} -ge 32 ]] || die "$secret_name must be a generated secret of at least 32 characters."
done
OIDC_ENABLED_VALUE="${OIDC_ENABLED:-$(read_env_value .env OIDC_ENABLED)}"
[[ "$OIDC_ENABLED_VALUE" == true ]] || die "Set OIDC_ENABLED=true and configure an OIDC provider for the production deployment."
for setting_name in OIDC_ISSUER_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_REDIRECT_URL; do
	setting_value="$(read_env_value .env "$setting_name")"
	if [[ -v "$setting_name" ]]; then
		setting_value="${!setting_name}"
	fi
	[[ -n "$setting_value" ]] || die "$setting_name must be configured for OIDC sign-in."
done
OIDC_GROUPS="${OIDC_ADMIN_GROUPS:-$(read_env_value .env OIDC_ADMIN_GROUPS)}${OIDC_OPERATOR_GROUPS:-$(read_env_value .env OIDC_OPERATOR_GROUPS)}${OIDC_VIEWER_GROUPS:-$(read_env_value .env OIDC_VIEWER_GROUPS)}"
[[ -n "$OIDC_GROUPS" ]] || die "Configure at least one OIDC role group mapping."
DOJO_VERSION="${DEFECTDOJO_VERSION:-$(read_env_value .env DEFECTDOJO_VERSION)}"
[[ -n "$DOJO_VERSION" && "$DOJO_VERSION" != latest ]] || die "Set DEFECTDOJO_VERSION to a reviewed, pinned release tag (not latest)."
[[ -r "$TLS_CERT_PATH" ]] || die "TLS_CERT_FILE must point to a readable company-trusted certificate."
[[ -r "$TLS_KEY_PATH" ]] || die "TLS_KEY_FILE must point to a readable private key."
[[ -n "$SERVER_NAME" ]] || die "Set TIJERI_SERVER_NAME to the DNS name users will access."
command -v openssl >/dev/null 2>&1 || die "OpenSSL is required to validate the configured TLS certificate."
openssl x509 -in "$TLS_CERT_PATH" -noout -checkend 0 >/dev/null 2>&1 || die "TLS certificate is expired or invalid."
openssl x509 -in "$TLS_CERT_PATH" -noout -checkhost "$SERVER_NAME" >/dev/null 2>&1 || die "TLS certificate does not cover TIJERI_SERVER_NAME."
openssl pkey -in "$TLS_KEY_PATH" -noout >/dev/null 2>&1 || die "TLS_KEY_FILE is not a valid private key."
cmp -s <(openssl x509 -in "$TLS_CERT_PATH" -pubkey -noout) <(openssl pkey -in "$TLS_KEY_PATH" -pubout) || die "TLS certificate and private key do not match."

wait_for() {
    local service="$1" label="$2" timeout="$3" interval="$4"
    shift 4
    local deadline=$((SECONDS + timeout))

    printf '  %s' "$label"
    while (( SECONDS < deadline )); do
        if "$@" >/dev/null 2>&1; then
            printf ' ready\n'
            return 0
        fi
        printf '.'
        sleep "$interval"
    done

    printf ' timed out after %ss\n' "$timeout" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=80 "$service" >&2 || true
    return 1
}

persist_runtime_keys() {
    local dojo_key="$1" dtrack_key="$2" temp_file
    temp_file="$(mktemp "${RUNTIME_ENV}.XXXXXX")"
    printf 'DEFECTDOJO_API_KEY=%s\nDTRACK_API_KEY=%s\n' "$dojo_key" "$dtrack_key" > "$temp_file"
    chmod 600 "$temp_file"
    mv -f "$temp_file" "$RUNTIME_ENV"
}

printf '%s\n' '=== Starting Tijeri Platform ==='
printf '%s\n' '[1/5] Checking configuration and starting bundled services...'
docker compose -f "$COMPOSE_FILE" config --quiet || die "Compose configuration is invalid; review .env and TLS paths."
docker compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

printf '%s\n' '[2/5] Waiting for core services...'
wait_for postgres Postgres 180 3 docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U tijeri -d tijeri
wait_for nats NATS 180 3 docker compose -f "$COMPOSE_FILE" exec -T nats wget -qO- http://localhost:8222/healthz

printf '%s\n' '[3/5] Waiting for integrations...'
wait_for defectdojo-nginx DefectDojo 600 5 curl --connect-timeout 2 --max-time 5 -fsS http://127.0.0.1:8081/login
wait_for dtrack-apiserver Dependency-Track 900 5 docker compose -f "$COMPOSE_FILE" exec -T dtrack-apiserver wget -q -O /dev/null http://localhost:8080/api/v1/health
wait_for wazuh-indexer 'Wazuh indexer' 300 5 docker compose -f "$COMPOSE_FILE" exec -T wazuh-indexer bash -c 'exec 3<>/dev/tcp/localhost/9200'

printf '  Initializing Wazuh indexer security'
if ! docker compose -f "$COMPOSE_FILE" exec -T wazuh-indexer sh -lc 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -p 9200 -icl >/dev/null 2>&1'; then
    printf '\n'
    docker compose -f "$COMPOSE_FILE" logs --tail=80 wazuh-indexer >&2
    die "Wazuh indexer security initialization failed."
fi
printf ' done\n'

printf '%s\n' '[4/5] Preparing integration credentials...'
DOJO_KEY="$(read_env_value "$RUNTIME_ENV" DEFECTDOJO_API_KEY)"
if [[ -z "$DOJO_KEY" ]]; then
    DOJO_KEY="$(docker compose -f "$COMPOSE_FILE" exec -T defectdojo-uwsgi python manage.py drf_create_token admin 2>/dev/null | grep -o -E '[a-f0-9]{40}' | head -n 1 || true)"
fi
[[ -n "$DOJO_KEY" ]] || die "Could not provision DefectDojo API credentials; inspect DefectDojo logs and configure the account."

DTRACK_KEY="${DTRACK_API_KEY:-$(read_env_value "$RUNTIME_ENV" DTRACK_API_KEY)}"
if [[ -z "$DTRACK_KEY" ]]; then
    DTRACK_KEY="$(read_env_value .env DTRACK_API_KEY)"
fi
[[ -n "$DTRACK_KEY" ]] || die "Set DTRACK_API_KEY in deploy/compose/.env after creating a least-privilege Dependency-Track team key."
persist_runtime_keys "$DOJO_KEY" "$DTRACK_KEY"

printf '%s\n' '[5/5] Starting the orchestrator...'
docker compose -f "$COMPOSE_FILE" --profile orc up -d --build --no-deps --force-recreate tijeri-orchestrator
wait_for tijeri-orchestrator 'Tijeri HTTPS API readiness' 180 3 curl --connect-timeout 2 --max-time 5 --resolve "$SERVER_NAME:8080:127.0.0.1" -fsS "https://$SERVER_NAME:8080/ready"

printf '\n%s\n' '=== Tijeri services are ready ==='
printf '  Tijeri API:        https://%s:8080\n' "$SERVER_NAME"
printf '  DefectDojo admin:  http://127.0.0.1:8081 (local host only)\n'
printf '  Dependency-Track:  http://127.0.0.1:8083 (local host only)\n'
printf '\nLogs: docker compose -f deploy/compose/%s logs -f tijeri-orchestrator\n' "$COMPOSE_FILE"
printf 'Stop: ./stop.sh\n'
