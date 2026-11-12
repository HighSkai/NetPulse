"""First-run setup, signing in and out, and one's own account (plan sections 36 and 37).

- Setup is served only until the first administrator exists, and only to the
  PC NetPulse runs on. It makes that administrator and signs them in.
- Signing in answers the same way for an unknown username, a wrong password
  and a disabled account, and stops checking after too many failures.
- The account page is where anyone changes their own password and ends their
  own sessions. An account with a temporary password sees nothing else until
  it has chosen its own.

Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from flask import abort, flash, make_response, redirect, render_template, request, session, url_for

from netpulse.accounts import PASSWORD_MIN, SESSION_ABSOLUTE_DAYS, SESSION_IDLE_DAYS, AccountError
from netpulse.auth import LoginFailed, Throttled
from netpulse.web.app import get_store
from netpulse.web.forms import Refusable
from netpulse.web.security import (
    PUBLIC,
    SIGNED_IN,
    access,
    clear_session_cookie,
    client_ip,
    get_auth,
    identity,
    safe_next,
    set_session_cookie,
)
from netpulse.web.views import bp


@dataclass
class AccountForm(Refusable):
    """Setup's fields and the password form's. Passwords are never sent back to the page."""

    username: str = ""
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("username", r"username"), ("current", r"current"), ("confirm", r"do not match"), ("password", r"password"))


def _user_agent() -> str:
    return (request.headers.get("User-Agent") or "")[:200]


# First-run setup (plan section 37)


@bp.get("/setup")
@access(PUBLIC)
def setup():
    if not get_auth().needs_setup(get_store()):
        return redirect(url_for(".overview"))
    return render_template("setup.html", form=AccountForm(), password_min=PASSWORD_MIN)


@bp.post("/setup")
@access(PUBLIC)
def finish_setup():
    auth, store = get_auth(), get_store()
    if not auth.needs_setup(store):
        abort(403, description="Setup has already been completed. Sign in instead.")
    form = AccountForm(username=request.form.get("username", "").strip())
    password = request.form.get("password", "")
    try:
        if password != request.form.get("confirm", ""):
            raise AccountError("the two passwords do not match")
        user = auth.create_first_admin(store, form.username, password)
    except AccountError as exc:
        return render_template("setup.html", form=form.fail(exc), password_min=PASSWORD_MIN), 422
    store.audit(user.username, "set up NetPulse", "first administrator", ip=client_ip())
    _, token = auth.login(store, user.username, password, client_ip(), _user_agent())
    session.clear()
    response = make_response(redirect(url_for(".access_page", welcome="yes")))
    set_session_cookie(response, token)
    return response


# Signing in and out (plan section 36)


@bp.get("/login")
@access(PUBLIC)
def login():
    if identity() is not None:
        return redirect(safe_next(request.args.get("next")) or url_for(".overview"))
    return render_template("login.html", form=AccountForm(), next=safe_next(request.args.get("next")) or "")


@bp.post("/login")
@access(PUBLIC)
def sign_in():
    form = AccountForm(username=request.form.get("username", "").strip()[:64])
    target = safe_next(request.form.get("next"))
    try:
        found, token = get_auth().login(
            get_store(), form.username, request.form.get("password", ""), client_ip(), _user_agent()
        )
    except Throttled as exc:
        page = render_template("login.html", form=form.fail(str(exc)), next=target or "")
        return page, 429, {"Retry-After": str(exc.retry_after_s)}
    except LoginFailed as exc:
        return render_template("login.html", form=form.fail(str(exc)), next=target or ""), 401
    # A new CSRF token for the signed-in session: nothing from before signing in carries over.
    session.clear()
    response = make_response(redirect(url_for(".account") if found.user.must_change_password else target or url_for(".overview")))
    set_session_cookie(response, token)
    return response


@bp.post("/logout")
@access(SIGNED_IN)
def logout():
    get_auth().logout(get_store(), identity(), client_ip())
    session.clear()
    response = make_response(redirect(url_for(".login")))
    clear_session_cookie(response)
    return response


# One's own account


def _account_page(form: AccountForm | None = None, status: int = 200):
    found = identity()
    now = datetime.now(UTC)
    page = render_template(
        "account.html", form=form or AccountForm(), user=found.user, current=found.session,
        sessions=get_store().sessions_of(found.user.id, now=now), password_min=PASSWORD_MIN,
        idle_days=SESSION_IDLE_DAYS, absolute_days=SESSION_ABSOLUTE_DAYS,
    )
    return page, status


@bp.get("/account")
@access(SIGNED_IN)
def account():
    """Who is signed in, what they may do, their sessions, and the form to change their password."""
    return _account_page()


@bp.post("/account/password")
@access(SIGNED_IN)
def change_password():
    found = identity()
    new = request.form.get("password", "")
    try:
        if new != request.form.get("confirm", ""):
            raise AccountError("the two new passwords do not match")
        get_auth().change_password(get_store(), found, request.form.get("current", ""), new)
    except AccountError as exc:
        return _account_page(AccountForm().fail(exc), 422)
    get_store().audit(found.user.username, "changed own password", ip=client_ip())
    flash("Password changed. Your other sessions were signed out.")
    return redirect(url_for(".account"))


@bp.post("/account/sessions/<int:session_id>/revoke")
@access(SIGNED_IN)
def revoke_own_session(session_id: int):
    """End one of one's own sessions. Ending the current one signs out."""
    found, store = identity(), get_store()
    try:
        target = store.get_session(session_id)
    except KeyError:
        abort(404)
    if target.user_id != found.user.id:
        abort(404)  # someone else's: as far as this account can tell, there is no such session
    store.revoke_session(session_id)
    store.audit(found.user.username, "ended own session", ip=client_ip())
    if session_id == found.session.id:
        session.clear()
        response = make_response(redirect(url_for(".login")))
        clear_session_cookie(response)
        return response
    flash("That session was signed out.")
    return redirect(url_for(".account"))


@bp.post("/account/sessions/revoke-others")
@access(SIGNED_IN)
def revoke_other_sessions():
    found, store = identity(), get_store()
    ended = store.revoke_sessions_of(found.user.id, except_session=found.session.id)
    store.audit(found.user.username, "ended own other sessions", detail=str(ended), ip=client_ip())
    flash(f"Signed out {ended} other {'session' if ended == 1 else 'sessions'}.")
    return redirect(url_for(".account"))
