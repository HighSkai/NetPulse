"""What every request passes before it reaches a page (plan sections 35 to 37).

In order:

1. The Host header must name this NetPulse (netpulse.access.allowed_host).
2. A POST must carry the page's CSRF token, and must not come from another site.
3. Until the first administrator exists, everything leads to setup, and setup
   is only served to the PC NetPulse runs on.
4. The session cookie says who is asking. No session: the sign-in page.
5. The route's own rule decides whether that account may. Every route states
   one with @access; a route that states none is closed to everyone but an
   administrator, so forgetting the line fails safe.

The rules are checked here, on the server, for every request. Templates hide
the controls an account cannot use, but that is only tidiness.
"""

from __future__ import annotations

import secrets
from urllib.parse import quote, urlsplit

from flask import Response, abort, current_app, g, redirect, request, session, url_for
from flask.sessions import SecureCookieSessionInterface

from netpulse.access import AccessControl, AccessSettings, allowed_host, host_of, load_settings
from netpulse.accounts import SESSION_ABSOLUTE_DAYS, User
from netpulse.auth import Auth, Identity, is_loopback

CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SESSION_COOKIE = "netpulse_session"

# Access rules a route can state besides a permission.
PUBLIC = "public"  # no session needed: sign-in, setup, and what they load
SIGNED_IN = "signed-in"  # any account that is not disabled

# Reached without a session, or before setup is done.
SETUP_ENDPOINTS = {"netpulse.setup", "netpulse.finish_setup", "static"}
PASSWORD_ENDPOINTS = {"netpulse.account", "netpulse.change_password", "netpulse.logout", "static"}

CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'self'",
    "script-src 'self'",
    # Stylesheets only from NetPulse itself. Elements may set custom properties
    # in a style attribute (a bar's width); nothing else is ever written into one.
    "style-src 'self'",
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
))


def access(rule: str):
    """State who may use a route: PUBLIC, SIGNED_IN, or a netpulse.accounts.Permission."""

    def mark(view):
        view.netpulse_access = rule
        return view

    return mark


class SchemeAwareSessions(SecureCookieSessionInterface):
    """Flask's signed cookie (the CSRF token and one-time messages), named and flagged by scheme.

    Over HTTPS the cookie is Secure and carries the __Host- prefix, which a
    browser only accepts from this exact host over HTTPS. Over HTTP it has a
    plain name, so the two never overwrite each other on one machine.
    """

    def get_cookie_name(self, app) -> str:
        return "__Host-netpulse_csrf" if request.is_secure else "netpulse_csrf"

    def get_cookie_secure(self, app) -> bool:
        return request.is_secure


def session_cookie_name() -> str:
    return f"__Host-{SESSION_COOKIE}" if request.is_secure else SESSION_COOKIE


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        session_cookie_name(), token, max_age=SESSION_ABSOLUTE_DAYS * 86400, httponly=True, samesite="Lax",
        secure=request.is_secure, path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(session_cookie_name(), path="/", httponly=True, samesite="Lax", secure=request.is_secure)


def get_auth() -> Auth:
    return current_app.extensions["netpulse.auth"]


def get_access() -> AccessControl:
    return current_app.extensions["netpulse.access"]


def access_settings() -> AccessSettings:
    """The stored network access settings, read once a request."""
    if "access_settings" not in g:
        from netpulse.web.app import get_store

        g.access_settings = load_settings(get_store())
    return g.access_settings


def client_ip() -> str:
    """The address the connection came from. Forwarding headers are not trusted: NetPulse is not
    meant to sit behind a proxy, and a header anyone can send must not pick whose limit a sign-in counts against."""
    return request.remote_addr or ""


def identity() -> Identity | None:
    return g.get("identity")


def current_user() -> User | None:
    found = identity()
    return found.user if found is not None else None


def can(permission: str) -> bool:
    """Whether the signed-in account may do what the permission names. For templates and views."""
    user = current_user()
    return user is not None and user.can(permission)


def actor() -> str:
    """The signed-in username, for the audit log."""
    user = current_user()
    return user.username if user is not None else "-"


def csrf_token() -> str:
    token = session.get(CSRF_FIELD)
    if token is None:
        token = secrets.token_urlsafe(32)
        session[CSRF_FIELD] = token
    return token


def safe_next(target: str | None) -> str | None:
    """A path on this NetPulse to go to after signing in, or None. Never another site."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    if any(ord(ch) < 32 for ch in target) or len(target) > 500:
        return None
    return target


def is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


# The checks, in the order they run.


def check_host() -> None:
    """Refuse a request for a name this NetPulse does not answer to (DNS rebinding)."""
    header = request.headers.get("Host", "")
    computer = get_access().computer
    host = host_of(header)
    # The usual cases need no database: an address, localhost, this PC's name.
    if allowed_host(header, AccessSettings(), computer):
        return
    if not allowed_host(header, access_settings(), computer):
        abort(400, description=f"This NetPulse does not answer to the name {host[:100]}. "
                               "An administrator can add it under settings, access.")


def check_csrf() -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # A browser says where a POST came from. One from another site is refused
    # before its token is even looked at.
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if source and source != "null":
        parts = urlsplit(source)
        if parts.netloc.lower() != request.host.lower():
            abort(400, description="That request came from another site and was refused.")
    sent = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER) or ""
    expected = session.get(CSRF_FIELD, "")
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400, description="Missing or invalid CSRF token. Reload the page and try again.")


def _to_sign_in():
    """Send a request without a session to the sign-in page, in the way its kind can follow."""
    target = url_for("netpulse.login")
    if is_htmx():
        # A fragment that polls: tell HTMX to take the whole page to sign-in.
        return Response("Signed out.", status=401, headers={"HX-Redirect": target})
    if request.method != "GET":
        abort(401)
    wanted = safe_next(request.full_path.rstrip("?"))
    return redirect(f"{target}?next={quote(wanted, safe='/?&=')}" if wanted and wanted != "/" else target)


def gate():
    """Setup first, then who is asking, then whether they may."""
    from netpulse.web.app import get_store

    endpoint = request.endpoint
    if endpoint == "static":
        return None
    auth, store = get_auth(), get_store()
    # Asked of the database until the answer is yes, and never again: NetPulse does not
    # let its last administrator go, so once set up it stays set up.
    if not current_app.extensions.get("netpulse.setup_done"):
        if auth.needs_setup(store):
            if endpoint not in SETUP_ENDPOINTS:
                return redirect(url_for("netpulse.setup"))
            if not is_loopback(client_ip()):
                abort(403, description="NetPulse has not been set up yet. Finish setup in a browser on the PC it runs on.")
            return None
        current_app.extensions["netpulse.setup_done"] = True
    g.identity = auth.identify(store, request.cookies.get(session_cookie_name()), client_ip())
    if endpoint is None:
        # No such page. Say so only to someone signed in; anyone else gets the sign-in page.
        return None if g.identity is not None else _to_sign_in()
    view = current_app.view_functions.get(endpoint)
    rule = getattr(view, "netpulse_access", None)
    if rule == PUBLIC:
        return None
    if g.identity is None:
        return _to_sign_in()
    user = g.identity.user
    if user.must_change_password and endpoint not in PASSWORD_ENDPOINTS:
        return redirect(url_for("netpulse.account"))
    if rule == SIGNED_IN:
        return None
    if rule is None:
        # A route that states no rule: only an administrator, whatever it does.
        if not user.is_admin:
            abort(403)
        return None
    if not user.can(rule):
        abort(403, description="Your account may not do that. An administrator can change what it may do.")
    return None


def security_headers(response: Response) -> Response:
    headers = response.headers
    headers["X-Frame-Options"] = "DENY"
    headers["X-Content-Type-Options"] = "nosniff"
    headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    headers["Referrer-Policy"] = "same-origin"
    headers["Cross-Origin-Opener-Policy"] = "same-origin"
    headers["Cross-Origin-Resource-Policy"] = "same-origin"
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    if request.endpoint != "static":
        # Pages hold network details: a shared computer's cache must not keep them.
        headers.setdefault("Cache-Control", "no-store")
    return response
