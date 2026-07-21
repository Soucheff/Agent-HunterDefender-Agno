# Hunter Defender Agent

Interactive identity security analysis agent built with Python and Agno. The first milestone
uses Ollama for inference and will consume the existing Hunter Defender MCP through delegated
Microsoft Entra Agent ID authentication.

## Current increment

- Typed Ollama configuration
- `doctor` command for endpoint and model readiness
- Manual capability tests for warm requests, JSON Schema output and tool calling
- Browser-based MSAL login with automatic PKCE and macOS Keychain token cache
- Microsoft Entra Agent ID sidecar client for delegated authorization
- Agno Streamable HTTP MCP adapter restricted to read-only identity tools
- Deterministic, versioned identity risk scoring and report schemas
- Bounded Agno identity specialist factory using the remote Ollama model

## Setup

```bash
uv sync
cp .env.example .env
uv run hunter-defender doctor
tests/manual/test_ollama.sh
```

## Entra configuration

Before running a live login, configure these values in `.env`:

```dotenv
AZURE_TENANT_ID=<tenant-guid>
ENTRA_CLI_CLIENT_ID=<public-client-app-guid>
ENTRA_AGENT_IDENTITY_CLIENT_ID=<agent-identity-client-guid>
ENTRA_USER_SCOPE=api://<blueprint-app-guid>/access_as_user
ENTRA_MCP_SCOPE=api://<mcp-resource-app-guid>/Mcp.Access
HUNTER_DEFENDER_MCP_URL=http://127.0.0.1:8000/mcp
ENTRA_SIDECAR_URL=http://127.0.0.1:5000
ENTRA_SIDECAR_SERVICE_NAME=HunterDefenderMcp
```

The CLI app registration must be a public desktop/mobile client with `http://localhost` as a
redirect URI. MSAL opens the system browser and applies PKCE automatically. No client secret
belongs in this application.

```bash
uv run hunter-defender login
uv run hunter-defender logout
```

The sidecar must remain bound to loopback or the same private container network. Never publish
its token acquisition API through an ingress or load balancer.

On macOS, the client connects to `127.0.0.1` and sends `Host: localhost`. This avoids the native
AirTunes service that can own IPv6 `localhost:5000` while satisfying the sidecar host filter.

The compose file runs the sidecar with `ASPNETCORE_ENVIRONMENT=Development` on purpose. Outside
Development the sidecar enables `UseLocalCallerRestriction`, which only accepts loopback source
IPs and returns HTTP 403 for every non-health endpoint. With the agent on the host and the sidecar
in Docker, NAT rewrites the source IP to the bridge gateway, so that check rejects valid requests.
The Docker port binding already restricts access to `127.0.0.1`, so loopback-only access is still
enforced. In a production pod, run the agent and sidecar in the same pod over localhost and use
`ASPNETCORE_ENVIRONMENT=Production` so the restriction applies correctly.

The delegated agent On-Behalf-Of flow acquires the MCP token as the Agent Identity on behalf of
the user, so the Agent Identity itself must hold delegated consent to the MCP `Mcp.Access` scope.
`scripts/provision-entra.ps1` grants this automatically. The resulting downstream token has
`aud=<mcp>`, `scp=Mcp.Access`, `azp=<agent-identity>`, and `oid=<user>`.

Provision or reconcile all required Entra resources and update `.env`:

```bash
pwsh -NoProfile -File scripts/provision-entra.ps1 \
	-TenantId '<tenant-id>' \
	-McpAppId '<mcp-resource-app-id>'
```

The script is idempotent. Use `-RotateBlueprintSecret` only when intentionally replacing the
90-day local development credential. Start the sidecar with:

```bash
docker compose --env-file .env -f compose.sidecar.yaml up -d
uv run hunter-defender doctor
```

## Quality checks

```bash
uv run pytest
uv run ruff check .
uv run mypy
```

The Ollama API has no native authentication. Keep port `11434` private and restrict it at the
firewall to the machine running this agent.
