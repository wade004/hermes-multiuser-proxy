"""
Multi-user reverse proxy for Hermes WebUI.
Sits in front of hermes-webui, handles per-user authentication,
and auto-binds Hermes profiles on login.
"""
import asyncio
import logging
import os
from pathlib import Path

import aiohttp
from aiohttp import web

import users

logger = logging.getLogger("proxy")

# ── Configuration ───────────────────────────────────────────────────────────

PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8787"))
WEBUI_HOST = os.environ.get("WEBUI_HOST", "127.0.0.1")
WEBUI_PORT = int(os.environ.get("WEBUI_PORT", "8788"))
WEBUI_URL = f"http://{WEBUI_HOST}:{WEBUI_PORT}"

SESSION_COOKIE = "proxy_session"
PROFILE_COOKIE = "hermes_profile"  # must match hermes-webui's cookie name

STATIC_DIR = Path(__file__).parent / "static"

# Paths that don't require auth
PUBLIC_PATHS = {
    "/proxy/login",
    "/proxy/api/login",
    "/proxy/health",
    "/health",
    "/favicon.ico",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_client_ip(request: web.Request) -> str:
    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or \
           request.remote or "unknown"


def _get_session_token(request: web.Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _get_authenticated_user(request: web.Request) -> str | None:
    """Return username if valid session, None otherwise."""
    token = _get_session_token(request)
    if not token:
        return None
    return users.verify_session(token)


def _is_admin(request: web.Request) -> bool:
    token = _get_session_token(request)
    if not token:
        return False
    username = users.verify_session(token)
    if not username:
        return False
    user = users.get_user(username)
    return user is not None and user["role"] == "admin"


# ── Login page & API ────────────────────────────────────────────────────────

async def handle_login_page(request: web.Request) -> web.Response:
    """Serve the custom login page."""
    if _get_authenticated_user(request):
        raise web.HTTPFound("/")
    html = (STATIC_DIR / "login.html").read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html")


async def handle_login_api(request: web.Request) -> web.Response:
    """Handle login POST. Returns JSON."""
    ip = _get_client_ip(request)

    if not users.check_rate_limit(ip):
        return web.json_response(
            {"ok": False, "error": "Too many attempts. Try again later."},
            status=429,
        )

    try:
        body = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid request"}, status=400)

    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return web.json_response(
            {"ok": False, "error": "Username and password required"}, status=400
        )

    users.record_login_attempt(ip)
    user_info = users.authenticate(username, password)

    if not user_info:
        return web.json_response({"ok": False, "error": "Invalid credentials"}, status=401)

    users.clear_rate_limit(ip)

    # Create session
    token = users.create_session(username)

    # Build response with cookies
    resp = web.json_response({
        "ok": True,
        "username": username,
        "role": user_info["role"],
        "profile": user_info["profile"],
    })

    # Set session cookie
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=users.SESSION_TTL,
        httponly=True,
        samesite="Lax",
        path="/",
    )

    # Set profile cookie so hermes-webui auto-binds the user's profile
    if user_info["role"] != "admin":
        resp.set_cookie(
            PROFILE_COOKIE,
            user_info["profile"],
            max_age=users.SESSION_TTL,
            httponly=True,
            samesite="Lax",
            path="/",
        )

    return resp


async def handle_logout(request: web.Request) -> web.Response:
    """Clear session and redirect to login."""
    token = _get_session_token(request)
    if token:
        users.invalidate_session(token)
    resp = web.Response(status=302, headers={"Location": "/proxy/login"})
    resp.del_cookie(SESSION_COOKIE, path="/")
    resp.del_cookie(PROFILE_COOKIE, path="/")
    return resp


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "hermes-multiuser-proxy"})


# ── User management API (admin only) ────────────────────────────────────────

async def handle_users_list(request: web.Request) -> web.Response:
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response(users.list_users())


async def handle_users_create(request: web.Request) -> web.Response:
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid request"}, status=400)

    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    profile = (body.get("profile") or "").strip()
    role = (body.get("role") or "user").strip()

    if not username or not password or not profile:
        return web.json_response({"error": "username, password, profile required"}, status=400)

    if role not in ("admin", "user"):
        return web.json_response({"error": "role must be admin or user"}, status=400)

    if users.create_user(username, password, profile, role):
        return web.json_response({"ok": True})
    return web.json_response({"error": "username already exists"}, status=409)


async def handle_users_delete(request: web.Request) -> web.Response:
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    username = request.match_info["username"]
    if users.delete_user(username):
        return web.json_response({"ok": True})
    return web.json_response({"error": "user not found"}, status=404)


async def handle_users_update(request: web.Request) -> web.Response:
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    username = request.match_info["username"]
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid request"}, status=400)

    kwargs = {}
    for key in ("password", "profile", "role"):
        if key in body:
            kwargs[key] = body[key]

    if users.update_user(username, **kwargs):
        return web.json_response({"ok": True})
    return web.json_response({"error": "user not found"}, status=404)


# ── Reverse proxy ───────────────────────────────────────────────────────────

# Paths to intercept (our own routes, not forwarded to webui)
INTERCEPT_PREFIXES = (
    "/proxy/",
    "/proxy/api/",
)


async def _proxy(request: web.Request) -> web.StreamResponse:
    """Forward request to hermes-webui with profile cookie injection."""
    # Check auth
    username = _get_authenticated_user(request)
    if not username:
        # API requests get 401, page requests get redirect
        if request.path.startswith("/api/"):
            return web.json_response({"error": "unauthorized"}, status=401)
        raise web.HTTPFound(f"/proxy/login?next={request.path}")

    # Build upstream URL
    path = request.path
    if request.query_string:
        path += "?" + request.query_string

    url = f"{WEBUI_URL}{path}"

    # Build headers — forward most headers from client
    headers = {}
    for key, val in request.headers.items():
        key_lower = key.lower()
        if key_lower in ("host", "transfer-encoding"):
            continue
        headers[key] = val

    # Inject profile cookie for non-admin users
    user_info = users.get_user(username)
    if user_info and user_info["role"] != "admin":
        profile = user_info["profile"]
        # Merge with existing cookies, replacing any hermes_profile
        existing_cookies = headers.get("Cookie", "")
        parts = [p.strip() for p in existing_cookies.split(";") if p.strip()]
        parts = [p for p in parts if not p.startswith(f"{PROFILE_COOKIE}=")]
        parts.append(f"{PROFILE_COOKIE}={profile}")
        headers["Cookie"] = "; ".join(parts)
    elif user_info and user_info["role"] == "admin":
        # Admin: keep whatever profile cookie they set (or default)
        pass

    # Read request body
    body = await request.read() if request.method in ("POST", "PUT", "PATCH") else None

    # Forward via aiohttp client session
    session = request.app["client_session"]
    try:
        async with session.request(
            method=request.method,
            url=url,
            headers=headers,
            data=body,
            timeout=aiohttp.ClientTimeout(total=300),
            allow_redirects=False,
        ) as upstream_resp:
            # Check if this is a WebSocket upgrade
            if _is_websocket_upgrade(request):
                return await _proxy_websocket(request, url, headers)

            # Build response
            resp = web.StreamResponse(
                status=upstream_resp.status,
                headers=_filter_response_headers(upstream_resp.headers),
            )

            # Forward Set-Cookie from upstream (but not hermes_profile for non-admin)
            for cookie_name, morsel in upstream_resp.cookies.items():
                if user_info and user_info["role"] != "admin" and cookie_name == PROFILE_COOKIE:
                    continue  # skip upstream's profile cookie for non-admin
                resp.set_cookie(
                    morsel.key,
                    morsel.value,
                    max_age=morsel.get("max-age", ""),
                    expires=morsel.get("expires", ""),
                    path=morsel.get("path", "/"),
                    httponly=morsel.get("httponly", False),
                    samesite=morsel.get("samesite", "Lax"),
                )

            await resp.prepare(request)

            async for chunk in upstream_resp.content.iter_any():
                await resp.write(chunk)

            await resp.write_eof()
            return resp

    except aiohttp.ClientError as e:
        logger.error("Upstream error: %s", e)
        return web.Response(
            text="Backend unavailable",
            status=502,
        )


def _is_websocket_upgrade(request: web.Request) -> bool:
    return (
        request.headers.get("Upgrade", "").lower() == "websocket"
        and request.headers.get("Connection", "").lower() == "upgrade"
    )


async def _proxy_websocket(request: web.Request, url: str, headers: dict) -> web.WebSocketResponse:
    """Proxy WebSocket connection to upstream."""
    ws_server = web.WebSocketResponse()
    await ws_server.prepare(request)

    session = request.app["client_session"]
    ws_client = await session.ws_connect(url, headers=headers, timeout=300)

    async def forward(src, dst):
        try:
            async for msg in src:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING):
                    break
        except Exception:
            pass

    await asyncio.gather(
        forward(ws_client, ws_server),
        forward(ws_server, ws_client),
    )
    return ws_server


def _filter_response_headers(headers) -> dict:
    """Filter out hop-by-hop headers."""
    skip = {"transfer-encoding", "connection", "keep-alive"}
    return {k: v for k, v in headers.items() if k.lower() not in skip}


# ── Intercept routes ────────────────────────────────────────────────────────

async def _intercept(request: web.Request) -> web.StreamResponse | None:
    """Handle our own routes. Return None to pass through to proxy."""
    path = request.path

    # Proxy management routes
    if path == "/proxy/login" or path == "/proxy/login/":
        return await handle_login_page(request)
    if path == "/proxy/api/login" and request.method == "POST":
        return await handle_login_api(request)
    if path == "/proxy/logout":
        return await handle_logout(request)
    if path == "/proxy/health":
        return await handle_health(request)

    # Admin user management API
    if path == "/proxy/api/users" and request.method == "GET":
        return await handle_users_list(request)
    if path == "/proxy/api/users" and request.method == "POST":
        return await handle_users_create(request)

    # /proxy/api/users/{username}
    if path.startswith("/proxy/api/users/"):
        parts = path.split("/")
        if len(parts) == 5:
            username = parts[4]
            if request.method == "DELETE":
                return await handle_users_delete(request)
            if request.method in ("PUT", "PATCH"):
                request.match_info["username"] = username
                return await handle_users_update(request)

    return None


# ── App factory ─────────────────────────────────────────────────────────────

async def _on_startup(app: web.Application) -> None:
    app["client_session"] = aiohttp.ClientSession()


def create_app() -> web.Application:
    app = web.Application(client_max_size=100 * 1024 * 1024)  # 100MB

    # Route: intercept our own paths, proxy everything else
    app.router.add_route("*", "/proxy/{path:.*}", _route_handler)
    app.router.add_route("*", "/{path:.*}", _route_handler)
    app.router.add_route("*", "/", _route_handler)

    # Lifecycle
    app.on_startup.append(_on_startup)
    app.on_shutdown.append(_on_shutdown)

    return app


async def _route_handler(request: web.Request) -> web.StreamResponse:
    """Unified route handler: intercept our routes, proxy the rest."""
    result = await _intercept(request)
    if result is not None:
        return result
    return await _proxy(request)


async def _on_shutdown(app: web.Application) -> None:
    await app["client_session"].close()


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    print(f"🚀 Hermes Multi-User Proxy")
    print(f"   Listening:    {PROXY_HOST}:{PROXY_PORT}")
    print(f"   Upstream:     {WEBUI_URL}")
    print(f"   Login:        http://localhost:{PROXY_PORT}/proxy/login")
    print()

    app = create_app()
    web.run_app(app, host=PROXY_HOST, port=PROXY_PORT, print=None)


if __name__ == "__main__":
    main()
