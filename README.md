# NPM Certificate Manager

This project is a small certificate manager for Nginx Proxy Manager (NPM). It monitors custom certificates, evaluates expiration dates and can renew custom certificates via the NPM API using a local Root CA.

Important design decisions:

- No direct volume access to NPM's internal certificate files.
- No automatic Nginx reload is triggered by the application.
- The manager delegates authentication to NPM's own `/api/tokens` endpoint.
- The Root CA private key is stored outside the Git repo and never exposed through the UI or API.
- The scheduler uses a dedicated NPM service account; user sessions are separate and in-memory only.

## Production Docker Compose

```bash
cp .env.example .env
# edit .env and set NPM_SERVICE_IDENTITY / NPM_SERVICE_SECRET and SESSION_SECRET
mkdir -p data secrets
# place your CA files in ./secrets/ca.key and ./secrets/ca.crt

docker compose up --build -d
```

## Docker run

```bash
docker run -d --name npm-cert-manager \
  --network npm_default \
  -p 8080:8000 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/secrets:/app/secrets" \
  -e NPM_URL="http://nginx-proxy-manager:81/api" \
  -e NPM_SERVICE_IDENTITY="service@example.com" \
  -e NPM_SERVICE_SECRET="super-secret" \
  -e SESSION_SECRET="change-me" \
  -e DATA_DIR="/app/data" \
  -e CA_KEY_PATH="/app/secrets/ca.key" \
  -e CA_CERT_PATH="/app/secrets/ca.crt" \
  npm-cert-manager:latest
```

## Development Compose

```bash
docker compose -f docker-compose.dev.yml up --build
```

This starts a local NPM instance for testing, along with the Certificate Manager.

## Environment variables

See `.env.example` for the complete list.

## Security notes

- Never commit `ca.key` or `ca.crt` to Git.
- Keep the CA key in a secure, backed-up secret store or bind mount.
- Do not log certificate content or private keys.
- Use dedicated NPM service credentials for scheduler automation.

## Root CA initialization

If `ca.key` and `ca.crt` do not exist yet, the dashboard shows a prominent `Root CA erzeugen` button. It creates a local Root CA in the configured directory, mirroring the legacy bash-script behavior (but using Python `cryptography` instead of `openssl` shell calls).

## Manual renewal

Use the web UI to trigger renewals manually. After a successful upload, the app records a `reload_required` state and shows a warning. It does not trigger a reload because the NPM source code does not expose a safe direct reload API for custom certificates in the supported way.
