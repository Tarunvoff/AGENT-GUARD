# ActShield Deployment Guide

## Deployment Modes

### Local Development

```bash
pip install actshield
actshield serve
```

Default behavior:
- API binds to `127.0.0.1:8000`
- Dashboard binds to `127.0.0.1:3000`
- No authentication required
- SQLite storage

### Team / Staging

```bash
actshield serve --host 0.0.0.0 --port 3000 --api-port 8000
```

> **Requires:** Network-level access control (VPN, firewall, or reverse proxy) before exposing to any network. Do not expose without this.

### Production

For production deployment, place ActShield behind a reverse proxy (nginx, Caddy, Traefik) with:

1. **Authentication** — OAuth 2.0 / OIDC or API key at the proxy layer
2. **TLS termination** — HTTPS only
3. **Network isolation** — Restrict API endpoint to internal network
4. **Rate limiting** — Apply at proxy layer

Example Caddy configuration:

```
actshield.internal.example.com {
    basicauth {
        admin $2a$...
    }
    reverse_proxy 127.0.0.1:3000
}

actshield-api.internal.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

---

## Storage

### SQLite (local/development)

```yaml
storage:
  backend: sqlite
  path: actshield.db
```

No additional configuration required. Suitable for single-node deployments, development, and CI/CD.

### PostgreSQL (production)

```yaml
storage:
  backend: postgres
  url: postgresql://user:pass@host:5432/actshield
```

Or via environment variable:

```bash
ACTSHIELD_STORAGE_URL=postgresql://user:pass@host:5432/actshield
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ACTSHIELD_MODE` | Enforcement mode (strict/monitor/audit) | `strict` |
| `ACTSHIELD_AI_PROVIDER` | AI provider name | `ai_secura` |
| `ACTSHIELD_AI_FAILURE_MODE` | What happens when AI fails | `fail_safe` |
| `ACTSHIELD_APIRIS_ENABLED` | Enable APIRIS | `true` |
| `ACTSHIELD_STORAGE_BACKEND` | Storage backend | `sqlite` |
| `ACTSHIELD_STORAGE_URL` | Database URL (postgres) | — |
| `ACTSHIELD_DASHBOARD_HOST` | Dashboard bind address | `127.0.0.1` |
| `ACTSHIELD_OFFENSIVE_MODE` | Offensive engine mode | `local_only` |
| `OPENAI_API_KEY` | OpenAI API key (if using openai provider) | — |
| `GOOGLE_API_KEY` | Gemini API key (if using gemini provider) | — |
| `ANTHROPIC_API_KEY` | Anthropic API key (if using anthropic provider) | — |

---

## Security Checklist for Deployment

Before deploying ActShield in a production environment:

- [ ] Dashboard is behind an authenticating reverse proxy
- [ ] TLS is enabled (HTTPS only)
- [ ] `ACTSHIELD_MODE=strict` is set
- [ ] Storage backend is PostgreSQL with appropriate access controls
- [ ] API keys are in environment variables, not configuration files committed to version control
- [ ] Offensive mode is `local_only` (this is the default and only supported mode)
- [ ] Log output is shipped to a SIEM or structured log aggregator
- [ ] Network firewall restricts direct access to ports 3000 and 8000
- [ ] Dashboard URL is not publicly indexed (robots.txt + network isolation)

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: ActShield Security Gate
  run: |
    pip install actshield
    actshield gate evaluate --min-score 85 --json
  env:
    ACTSHIELD_MODE: strict
    ACTSHIELD_STORAGE_URL: ${{ secrets.ACTSHIELD_DB_URL }}
```

Exit codes:
- `0` — All security gates passed
- `1` — Security failure (gate threshold not met)
- `2` — System or configuration error

---

## Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app

RUN pip install actshield[dashboard]

ENV ACTSHIELD_MODE=strict
ENV ACTSHIELD_DASHBOARD_HOST=0.0.0.0   # Put behind nginx with auth

EXPOSE 8000 3000

CMD ["actshield", "serve", "--host", "0.0.0.0"]
```

> Deploy the above behind an authenticating reverse proxy. Do not expose port 3000 or 8000 directly to the internet.
