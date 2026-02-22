# creddy-dockerhub

Creddy plugin for Docker Hub access tokens with repository scoping.

## Installation

```bash
creddy plugin install dockerhub
```

## Configuration

```bash
creddy backend add dockerhub \
  --username "myuser" \
  --password "dckr_pat_..."   # Personal access token with admin scope
```

## Scopes

| Scope | Description |
|-------|-------------|
| `dockerhub:*` | Full access to all repositories |
| `dockerhub:<namespace>/*` | Access to all repos in namespace |
| `dockerhub:<namespace>/<repo>` | Access to specific repository |
| `dockerhub:<namespace>/<repo>:read` | Pull-only access |
| `dockerhub:<namespace>/<repo>:write` | Push and pull access |

## Usage

```bash
# Get credentials
TOKEN=$(creddy get dockerhub)
echo $TOKEN | docker login -u myuser --password-stdin

# Repository-scoped token
TOKEN=$(creddy get dockerhub --scope "dockerhub:myorg/myimage")

# Read-only token
TOKEN=$(creddy get dockerhub --scope "dockerhub:myorg/myimage:read")
```

## Requirements

- Docker Hub account
- Personal Access Token with "Read, Write, Delete" or admin permissions

## How It Works

1. Creddy authenticates with Docker Hub using your credentials
2. Creates a scoped Personal Access Token via the Docker Hub API
3. Returns the token to the agent
4. On TTL expiry or revocation, deletes the token

## License

Apache 2.0
