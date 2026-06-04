# Hermes Multi-User Proxy

Multi-user reverse proxy for [Hermes WebUI](https://github.com/nesquena/hermes-webui) with per-user profile isolation.

## Features

- Username + password login (per-user credentials)
- Auto-bind Hermes profile on login (no manual profile switching)
- Profile isolation — users cannot see or access other users' profiles
- Admin role — can switch between all profiles
- Zero modification to hermes-webui source code

## Architecture

```
User Browser (:8787)
    ↓
hermes-multiuser-proxy (custom login, multi-user auth)
    ↓ internal
hermes-webui (:8788, localhost only)
    ↓
hermes-agent
```

## Status

🚧 Planning phase — not yet implemented.
