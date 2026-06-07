"""
Multi-user reverse proxy for Hermes WebUI.
Sits in front of hermes-webui, handles per-user authentication,
and auto-binds Hermes profiles on login.
"""
import asyncio
import json
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

# JS snippet injected into every HTML response to add a logout button.
# Placed next to the settings gear button in both desktop rail and mobile sidebar.
_LOGOUT_INJECT_SCRIPT = """
<script>
(function(){
  if(window.__proxyLogoutInjected) return;
  window.__proxyLogoutInjected = true;
  // Force profile label update from API (the WebUI's own boot.js may fail
  // to update it due to race conditions or SSE errors)
  function fixProfileLabel(){
    try{
      fetch('/api/profile/active',{credentials:'include',headers:{'Content-Type':'application/json'}})
        .then(function(r){return r.json();})
        .then(function(d){
          if(d&&d.name){
            var lbl=document.getElementById('profileChipLabel');
            if(lbl) lbl.textContent=d.name;
            if(window.S) S.activeProfile=d.name;
          }
        }).catch(function(){});
    }catch(e){}
  }
  // Run after DOM ready, with a small delay to let boot.js finish first
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',function(){setTimeout(fixProfileLabel,500);});
  } else {
    setTimeout(fixProfileLabel,500);
  }
  // Also run periodically in case boot.js resets it
  setInterval(fixProfileLabel,5000);
  var _logoutSvg='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
  function addLogoutBtn(){
    var injected=false;
    // Desktop rail: insert after the settings button
    var railSettings=document.querySelector('.rail button.rail-btn[data-panel="settings"]');
    if(railSettings&&!railSettings.parentElement.querySelector('.proxy-logout-btn')){
      var btn=document.createElement('button');
      btn.className='rail-btn proxy-logout-btn has-tooltip';
      btn.setAttribute('data-tooltip','退出登录');
      btn.setAttribute('aria-label','Sign Out');
      btn.innerHTML=_logoutSvg;
      btn.style.cssText='cursor:pointer';
      btn.onclick=function(){window.location.href='/proxy/logout'};
      railSettings.parentElement.insertBefore(btn,railSettings.nextSibling);
      injected=true;
    }
    // Mobile sidebar: insert after the settings button
    var sideSettings=document.querySelector('.sidebar-nav button[data-panel="settings"]');
    if(sideSettings&&!sideSettings.parentElement.querySelector('.sidebar-nav .proxy-logout-btn')){
      var btn2=document.createElement('button');
      btn2.className='nav-tab proxy-logout-btn has-tooltip has-tooltip--bottom';
      btn2.setAttribute('data-tooltip','退出登录');
      btn2.setAttribute('data-label','Logout');
      btn2.setAttribute('aria-label','Sign Out');
      btn2.innerHTML=_logoutSvg;
      btn2.style.cssText='cursor:pointer';
      btn2.onclick=function(){window.location.href='/proxy/logout'};
      sideSettings.parentElement.insertBefore(btn2,sideSettings.nextSibling);
      injected=true;
    }
    if(!injected) setTimeout(addLogoutBtn,1000);
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',addLogoutBtn);
  } else {
    addLogoutBtn();
  }
})();
</script>
"""

# Paths that don't require auth
PUBLIC_PATHS = {
    "/proxy/login",
    "/proxy/api/login",
    "/proxy/health",
    "/health",
    "/favicon.ico",
}

logging.basicConfig(
    level=logging.DEBUG,
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
    ua = request.headers.get("User-Agent", "")
    user_info = users.authenticate(username, password)

    if not user_info:
        return web.json_response({"ok": False, "error": "Invalid credentials"}, status=401)

    users.clear_rate_limit(ip)
    users.record_login(username, ip, ua)

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
    """Clear session, wipe browser state, and redirect to login."""
    token = _get_session_token(request)
    if token:
        users.invalidate_session(token)
    # Serve a page that clears localStorage (to remove stale session IDs)
    # then redirects to login. This prevents cross-user session leakage.
    html = """<!DOCTYPE html>
<html><head><script>
try{localStorage.clear();sessionStorage.clear();}catch(e){}
window.location.href='/proxy/login';
</script></head><body>Logging out...</body></html>"""
    resp = web.Response(text=html, content_type="text/html")
    resp.del_cookie(SESSION_COOKIE, path="/")
    resp.del_cookie(PROFILE_COOKIE, path="/")
    return resp


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "hermes-multiuser-proxy"})


async def handle_admin_page(request: web.Request) -> web.Response:
    """Serve the admin user management page (admin only)."""
    # Check authentication first
    username = _get_authenticated_user(request)
    if not username:
        raise web.HTTPFound("/proxy/login?next=/proxy/admin")
    # Check admin role
    user = users.get_user(username)
    if not user or user["role"] != "admin":
        return web.Response(
            text="""<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>403 Forbidden</title>
            <style>body{background:#1a1a2e;color:#e8e8f0;font-family:sans-serif;
            display:flex;align-items:center;justify-content:center;height:100vh}
            .box{text-align:center}h1{font-size:48px;color:#e94560;margin-bottom:8px}
            p{color:#8888aa}a{color:#7cb9ff;text-decoration:none}</style></head>
            <body><div class="box"><h1>403</h1><p>权限不足，仅管理员可访问</p>
            <p><a href="/">← 返回首页</a></p></div></body></html>""",
            status=403,
            content_type="text/html",
        )
    html = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html")


# ── User management API (admin only) ────────────────────────────────────────

async def handle_users_list(request: web.Request) -> web.Response:
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    users_dict = users.list_users()
    users_list = [
        {"username": u, **info}
        for u, info in users_dict.items()
    ]
    return web.json_response({"users": users_list})


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


async def handle_login_log(request: web.Request) -> web.Response:
    """Return recent login log entries (admin only)."""
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    limit = int(request.query.get("limit", "50"))
    limit = min(limit, 200)
    log = users.get_login_log(limit=limit)
    return web.json_response({"log": log})


async def handle_request_log(request: web.Request) -> web.Response:
    """Return recent request log entries (admin only)."""
    if not _is_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    limit = int(request.query.get("limit", "50"))
    limit = min(limit, 500)
    log = users.get_request_log(limit=limit)
    return web.json_response({"log": log})


# ── Token usage fetcher ─────────────────────────────────────────────────────

async def _fetch_token_usage(client_session: aiohttp.ClientSession, session_id: str) -> None:
    """Background task: wait for agent to finish, then fetch token usage."""
    await asyncio.sleep(30)  # wait for agent to process
    try:
        url = f"{WEBUI_URL}/api/session/usage?session_id={session_id}"
        async with client_session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                data = await resp.json()
                inp = int(data.get("input_tokens", 0))
                out = int(data.get("output_tokens", 0))
                if inp > 0 or out > 0:
                    users.update_request_tokens(session_id, inp, out)
                    logger.info("TOKENS [%s] in=%d out=%d", session_id, inp, out)
    except Exception as e:
        logger.debug("Token fetch failed for %s: %s", session_id, e)


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

    # Set X-Forwarded-Host so hermes-webui can validate CSRF origin
    headers["X-Forwarded-Host"] = request.headers.get("Host", "")

    # Inject profile cookie for all authenticated users
    user_info = users.get_user(username)
    if user_info:
        profile = user_info["profile"]
        # Rebuild Cookie header: keep all cookies EXCEPT hermes_profile,
        # then add the correct hermes_profile for this user.
        # Use case-insensitive search to handle HTTP/2 lowercase headers.
        existing_cookies = ""
        for hk, hv in headers.items():
            if hk.lower() == "cookie":
                existing_cookies = hv
                break
        parts = [p.strip() for p in existing_cookies.split(";") if p.strip()]
        parts = [p for p in parts if not p.lower().startswith(f"{PROFILE_COOKIE}=")]
        parts.append(f"{PROFILE_COOKIE}={profile}")
        # Always set as "Cookie" (canonical case)
        headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        headers["Cookie"] = "; ".join(parts)
        logger.debug("PROXY [%s] %s → injecting hermes_profile=%s", username, path, profile)

    # Read request body (not needed for WebSocket or GET)
    body = await request.read() if request.method in ("POST", "PUT", "PATCH") else None

    # ── Chat request logging ──
    # Intercept POST /api/chat/start to log user requests
    _chat_logged = False
    _chat_session_id = ""
    if request.method == "POST" and request.path == "/api/chat/start" and body:
        try:
            chat_body = json.loads(body)
            msg = str(chat_body.get("message", "")).strip()
            _chat_session_id = str(chat_body.get("session_id", ""))
            if msg:
                users.record_request(username, msg, _chat_session_id)
                _chat_logged = True
                logger.info("CHAT [%s] session=%s msg=%s", username, _chat_session_id, msg[:80])
        except Exception:
            pass

    # After forwarding, schedule token usage fetch for chat requests
    if _chat_logged and _chat_session_id:
        asyncio.create_task(
            _fetch_token_usage(request.app["client_session"], _chat_session_id)
        )

    # Handle WebSocket upgrade BEFORE making HTTP request
    if _is_websocket_upgrade(request):
        return await _proxy_websocket(request, url, headers)

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

            # Check if we should inject the logout button script
            ct = (upstream_resp.headers.get("Content-Type") or "").lower()
            is_html = "text/html" in ct

            if is_html:
                # Buffer HTML response so we can inject the logout script
                body_bytes = await upstream_resp.read()
                # Decompress if needed (proxy uses auto_decompress=False)
                encoding = (upstream_resp.headers.get("Content-Encoding") or "").lower()
                if encoding in ("gzip", "deflate"):
                    import zlib
                    if encoding == "gzip":
                        body_bytes = zlib.decompress(body_bytes, zlib.MAX_WBITS | 16)
                    else:
                        body_bytes = zlib.decompress(body_bytes)
                body_text = body_bytes.decode("utf-8", errors="replace")
                if "</body>" in body_text:
                    body_text = body_text.replace("</body>", _LOGOUT_INJECT_SCRIPT + "</body>")
                elif "</html>" in body_text:
                    body_text = body_text.replace("</html>", _LOGOUT_INJECT_SCRIPT + "</html>")
                else:
                    body_text += _LOGOUT_INJECT_SCRIPT
                encoded = body_text.encode("utf-8")
                resp.headers["Content-Length"] = str(len(encoded))
                # We decoded the body, so strip compression header
                resp.headers.pop("Content-Encoding", None)
                await resp.prepare(request)
                await resp.write(encoded)
            else:
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
    if path == "/proxy/admin" or path == "/proxy/admin/":
        return await handle_admin_page(request)
    if path == "/proxy/api/users" and request.method == "GET":
        return await handle_users_list(request)
    if path == "/proxy/api/users" and request.method == "POST":
        return await handle_users_create(request)
    if path == "/proxy/api/login-log" and request.method == "GET":
        return await handle_login_log(request)
    if path == "/proxy/api/request-log" and request.method == "GET":
        return await handle_request_log(request)

    # /proxy/api/users/{username}
    if path.startswith("/proxy/api/users/"):
        parts = path.split("/")
        if len(parts) == 5:
            username = parts[4]
            request.match_info["username"] = username
            if request.method == "DELETE":
                return await handle_users_delete(request)
            if request.method in ("PUT", "PATCH"):
                return await handle_users_update(request)

    return None


# ── App factory ─────────────────────────────────────────────────────────────

async def _on_startup(app: web.Application) -> None:
    # force_close=True: disable HTTP connection pooling to prevent response
    # body leakage between requests (aiohttp with auto_decompress=False can
    # leave unconsumed bytes that corrupt subsequent requests on the same conn).
    connector = aiohttp.TCPConnector(force_close=True)
    # auto_decompress=False: forward gzip responses as-is to the browser.
    # Without this, aiohttp decompresses the body but we still forward the
    # Content-Encoding: gzip header, causing browsers to fail parsing CSS/JS.
    app["client_session"] = aiohttp.ClientSession(
        auto_decompress=False,
        connector=connector,
    )


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
