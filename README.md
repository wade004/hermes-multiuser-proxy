# Hermes Multi-User Proxy

Multi-user reverse proxy for [Hermes WebUI](https://github.com/nesquena/hermes-webui) with per-user profile isolation.

## Features

- **Username + password login** — per-user credentials, no shared password
- **Auto profile binding** — login automatically activates the user's Hermes profile
- **Profile isolation** — users cannot see or switch to other users' profiles
- **Admin role** — admin users retain full profile switching ability
- **Zero modification** to hermes-webui — proxy sits in front, webui stays untouched
- **User management CLI** — create, update, delete users from command line
- **WebSocket proxy** — full streaming support transparently proxied

## Architecture

```
User Browser (:8787)
    ↓
hermes-multiuser-proxy  ← custom login page, multi-user auth
    ↓ internal
hermes-webui (:8788)    ← untouched, localhost only
    ↓
hermes-agent
```

## Quick Start

### 1. Install dependencies

```bash
cd hermes-multiuser-proxy
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env: set WEBUI_PORT to match your hermes-webui's actual port
```

### 3. Create admin user

```bash
python manage.py create admin yourpassword default admin
```

### 4. Create regular users (each bound to a Hermes profile)

```bash
# First create the Hermes profile
hermes profile create user-zhangsan

# Then create the proxy user bound to that profile
python manage.py create zhangsan password123 user-zhangsan user
```

### 5. Start the proxy

```bash
python proxy.py
```

### 6. Change hermes-webui to localhost-only

Update hermes-webui to listen on a different port (e.g., 8788) and bind to 127.0.0.1:

```bash
# In hermes-webui .env
HERMES_WEBUI_PORT=8788
HERMES_WEBUI_HOST=127.0.0.1
```

Then access via the proxy at `http://your-server:8787/proxy/login`.

## User Management

```bash
# List all users
python manage.py list

# Create a user (role: user or admin)
python manage.py create <username> <password> <profile> [role]

# Update a user
python manage.py update <username> --password newpw --profile new-profile --role admin

# Delete a user
python manage.py delete <username>
```

## How It Works

1. User visits the proxy login page and enters username + password
2. Proxy verifies credentials against `~/.hermes/webui/proxy_users.json`
3. On success, proxy sets two cookies:
   - `proxy_session` — tracks the proxy login session
   - `hermes_profile` — auto-binds the user's assigned Hermes profile
4. All subsequent requests are proxied to hermes-webui with the profile cookie injected
5. Non-admin users: the `hermes_profile` cookie is always forced to their assigned profile
6. Admin users: can freely set/switch the `hermes_profile` cookie (original WebUI behavior)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_HOST` | `0.0.0.0` | Proxy listen address |
| `PROXY_PORT` | `8787` | Proxy listen port |
| `WEBUI_HOST` | `127.0.0.1` | Upstream webui address |
| `WEBUI_PORT` | `8788` | Upstream webui port |
| `SESSION_TTL` | `604800` | Session lifetime in seconds (7 days) |
| `PROXY_DATA_DIR` | `~/.hermes/webui` | Data directory for users/sessions |

## Status

✅ Core implementation complete — ready for testing.
