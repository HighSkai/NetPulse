"""Administration: accounts, network access and the audit log (plan sections 35, 38 and 44).

- Users: make accounts, set their role and extra permissions, disable them,
  end their sessions, reset their password to a temporary one, delete them.
  NetPulse never lets the last administrator who can sign in be removed.
- Access: whether other devices on the network can reach this NetPulse, on
  which address and port, and with which certificate. Saving applies it at
  once; the page then says where NetPulse can be reached.
- Audit: who did what, newest first.

Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from flask import Response, abort, flash, redirect, render_template, request, url_for

from netpulse.access import (
    ALL_INTERFACES,
    AccessSettings,
    NameState,
    Tls,
    check_names,
    is_private,
    load_settings,
    save_settings,
    urls,
    validate_settings,
)
from netpulse.accounts import PASSWORD_MIN, AccountError, Permission, Role, User
from netpulse.crypto.tls import TlsError, authority_pem, covered_by_authority, issue_server_certificate
from netpulse.domain import ValidationError
from netpulse.netinfo import NetworkInfoUnavailable
from netpulse.network import Category
from netpulse.web.app import audit, get_network, get_store
from netpulse.web.forms import Refusable
from netpulse.web.security import SIGNED_IN, access, access_settings, current_user, get_access, get_auth
from netpulse.web.views import bp

AUDIT_PAGE = 100


@dataclass
class UserForm(Refusable):
    username: str = ""
    role: str = Role.VIEWER
    permissions: tuple[str, ...] = ()
    disabled: bool = False
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("username", r"username"), ("password", r"password"), ("role", r"role|administrator"), ("permissions", r"permission"))

    @classmethod
    def from_request(cls) -> UserForm:
        return cls(
            username=request.form.get("username", "").strip(),
            role=request.form.get("role", Role.VIEWER),
            permissions=tuple(request.form.getlist("permissions")),
            disabled=request.form.get("disabled") == "yes",
        )


def _user_or_404(user_id: int) -> User:
    try:
        return get_store().get_user(user_id)
    except KeyError:
        abort(404)


def _users_page(form: UserForm | None = None, *, handed: tuple[User, str] | None = None, status: int = 200):
    """handed is (account, its temporary password), shown once, on the page that answers the request."""
    store = get_store()
    now = datetime.now(UTC)
    users = store.users()
    page = render_template(
        "users.html", form=form or UserForm(), users=users, roles=Role.LABELS, handed=handed,
        sessions={user.id: len(store.sessions_of(user.id, now=now)) for user in users}, password_min=PASSWORD_MIN,
    )
    return page, status


@bp.get("/settings/users")
@access(Permission.USERS_MANAGE)
def users_page():
    return _users_page()


@bp.post("/settings/users")
@access(Permission.USERS_MANAGE)
def create_user():
    """A new account. Without a password typed for it, it gets a temporary one, shown once."""
    form = UserForm.from_request()
    typed = request.form.get("password", "")
    password = typed or get_auth().temporary_password()
    try:
        user = get_auth().create_user(get_store(), form.username, password, form.role, form.permissions, must_change=True)
    except AccountError as exc:
        return _users_page(form.fail(exc), status=422)
    audit("created account", user.username, user.role_label)
    return _users_page(handed=(user, password))


def _user_page(user: User, form: UserForm | None = None, *, handed: str | None = None, status: int = 200):
    store = get_store()
    page = render_template(
        "user.html", user=user, roles=Role.LABELS, handed=handed, me=current_user(),
        form=form or UserForm(user.username, user.role, tuple(user.permissions), not user.active),
        sessions=store.sessions_of(user.id, now=datetime.now(UTC)),
    )
    return page, status


@bp.get("/settings/users/<int:user_id>")
@access(Permission.USERS_MANAGE)
def user_page(user_id: int):
    return _user_page(_user_or_404(user_id))


@bp.post("/settings/users/<int:user_id>")
@access(Permission.USERS_MANAGE)
def update_user(user_id: int):
    """Role, extra permissions, and disabled or not. Losing rights or being disabled ends the account's sessions."""
    user = _user_or_404(user_id)
    form = UserForm.from_request()
    form.username = user.username
    try:
        if user.id == current_user().id and (form.disabled or form.role != Role.ADMIN):
            raise AccountError("role: you cannot disable or demote the account you are signed in with")
        saved = get_store().update_user(user_id, role=form.role, permissions=form.permissions, disabled=form.disabled)
    except AccountError as exc:
        return _user_page(user, form.fail(exc), status=422)
    detail = f"{saved.role_label}{', disabled' if not saved.active else ''}"
    if saved.permissions:
        detail += f"; may {', '.join(sorted(saved.permissions))}"
    audit("changed account", saved.username, detail)
    flash(f"Saved {saved.username}.")
    return redirect(url_for(".users_page"))


@bp.post("/settings/users/<int:user_id>/password")
@access(Permission.USERS_MANAGE)
def reset_user_password(user_id: int):
    """A temporary password for an account that lost its own. Its sessions end, and it must choose a new one."""
    user = _user_or_404(user_id)
    if user.id == current_user().id:
        abort(400, description="Change your own password on the account page.")
    password = get_auth().temporary_password()
    get_auth().set_password(get_store(), user, password, must_change=True)
    audit("reset password", user.username)
    return _user_page(get_store().get_user(user_id), handed=password)


@bp.post("/settings/users/<int:user_id>/sessions/revoke")
@access(Permission.USERS_MANAGE)
def revoke_user_sessions(user_id: int):
    user = _user_or_404(user_id)
    ended = get_store().revoke_sessions_of(user_id)
    audit("ended sessions", user.username, str(ended))
    flash(f"Signed {user.username} out of {ended} {'session' if ended == 1 else 'sessions'}.")
    return redirect(url_for(".user_page", user_id=user_id))


@bp.post("/settings/users/<int:user_id>/delete")
@access(Permission.USERS_MANAGE)
def delete_user(user_id: int):
    user = _user_or_404(user_id)
    try:
        if user.id == current_user().id:
            raise AccountError("you cannot delete the account you are signed in with")
        if request.form.get("confirm") != "yes":
            raise AccountError("tick the box to confirm: the account is deleted for good")
        get_store().delete_user(user_id)
    except AccountError as exc:
        return _user_page(user, UserForm(user.username, user.role, tuple(user.permissions), not user.active).fail(exc), status=422)
    audit("deleted account", user.username)
    flash(f"Deleted the account {user.username}.")
    return redirect(url_for(".users_page"))


# Network access (plan section 38)


@dataclass
class AccessForm(Refusable):
    lan: bool = False
    bind: str = ALL_INTERFACES
    port: str = "5000"
    tls: str = Tls.LOCAL
    cert_path: str = ""
    key_path: str = ""
    names: str = ""
    error: str | None = None
    error_field: str | None = None

    FIELDS = (
        ("port", r"^port"), ("bind", r"^interface"), ("confirm_public", r"^confirm"), ("names", r"^names"),
        ("cert_path", r"certificate|key"), ("tls", r"encryption"),
    )

    @classmethod
    def of(cls, settings: AccessSettings) -> AccessForm:
        return cls(
            settings.lan, settings.bind, str(settings.port), settings.tls, settings.cert_path, settings.key_path,
            " ".join(settings.names),
        )

    @classmethod
    def from_request(cls) -> AccessForm:
        get = request.form.get
        return cls(
            get("lan") == "yes", get("bind", ALL_INTERFACES), get("port", "").strip(), get("tls", Tls.LOCAL),
            get("cert_path", "").strip(), get("key_path", "").strip(), get("names", "").strip(),
        )


def _interfaces() -> tuple[list[tuple[str, str]], dict[str, str]]:
    """([(address, label)], {address on a network Windows marks Public: its adapter}): this PC's
    IPv4 addresses, named as the network page names their adapters when Windows can be asked."""
    control = get_access()
    labels: dict[str, str] = {}
    public: dict[str, str] = {}
    try:
        for adapter in get_network().read().adapters:
            for address in adapter.addresses:
                labels[str(address.ip)] = f"{adapter.name} · {address.ip} · {(adapter.category or 'network').capitalize()}"
                if adapter.category == Category.PUBLIC:
                    public[str(address.ip)] = adapter.name
    except NetworkInfoUnavailable:
        pass
    for address in control.addresses():
        labels.setdefault(address, address)
    return sorted(labels.items(), key=lambda item: (not is_private(item[0]), item[0])), public


def _access_page(form: AccessForm | None = None, *, applying: bool = False, status: int = 200):
    control = get_access()
    settings = access_settings()
    choices, public = _interfaces()
    live = control.status()
    effective = settings if live.port_override is None else AccessSettings(**{**settings.__dict__, "port": live.port_override})
    addresses = [a for a, _ in choices]
    # Only a name that leads to this PC is offered as a link (plan section 38).
    names = check_names(settings.names, control.look_up(settings.names), addresses) if settings.names else []
    # Listening on a network Windows marks Public: the firewall rule for Private networks lets nothing in.
    blocked = {
        address: adapter for address, adapter in public.items()
        if settings.lan and settings.bind in (ALL_INTERFACES, address)
    }
    page = render_template(
        "access.html", form=form or AccessForm.of(settings), settings=settings, status=live, choices=choices,
        public=public, blocked=blocked, names=names, name_state=NameState,
        lan_address=settings.bind if settings.bind != ALL_INTERFACES else next(
            (a for a in addresses if is_private(a)), "this PC's address"
        ),
        urls=urls(effective, addresses, control.computer, [n.name for n in names if n.state == NameState.HERE]),
        computer=control.computer,
        applying=applying, welcome=request.args.get("welcome") == "yes", tls=Tls, all_interfaces=ALL_INTERFACES,
        port=effective.port, now=datetime.now(UTC),
        uncovered=[name for name in settings.names if not covered_by_authority(name, control.computer)],
    )
    return page, status


@bp.get("/settings/access")
@access(Permission.SETTINGS_MANAGE)
def access_page():
    """Whether other devices can reach this NetPulse, where, and how to trust its certificate."""
    return _access_page()


@bp.post("/settings/access")
@access(Permission.SETTINGS_MANAGE)
def save_access():
    form = AccessForm.from_request()
    control = get_access()
    choices, public = _interfaces()
    current = load_settings(get_store())
    try:
        new = validate_settings(request.form, [a for a, _ in choices], public=public, current=current)
        if new.lan and new.tls == Tls.LOCAL:
            refused = [name for name in new.names if not covered_by_authority(name, control.computer)]
            if refused:
                raise ValidationError(
                    f"names: NetPulse's own certificate cannot cover {refused[0]}. Use a name ending in .lan, "
                    ".local or .home.arpa, or a certificate of your own"
                )
    except ValidationError as exc:
        return _access_page(form.fail(exc), status=422)
    save_settings(get_store(), new)
    if new.lan:
        detail = f"on, {new.scheme} on {new.bind} port {new.port}"
    else:
        detail = f"off, this PC only, port {new.port}"
    audit("changed network access", detail=detail)
    control.request_apply()
    # Answered as a page, not a redirect: the address being redirected to may be about to change.
    return _access_page(applying=True)


@bp.post("/settings/access/certificate")
@access(Permission.SETTINGS_MANAGE)
def renew_certificate():
    """Make NetPulse's own server certificate again, for this PC's names and addresses as they are now."""
    control = get_access()
    settings = load_settings(get_store())
    if control.tls_folder is None:
        abort(503, description="This NetPulse was started without a folder for its certificates.")
    try:
        issue_server_certificate(control.tls_folder, control.computer, [*settings.names, *control.addresses()])
    except TlsError as exc:
        flash(f"No new certificate: {exc}.", "error")
        return redirect(url_for(".access_page"))
    audit("made a new HTTPS certificate")
    control.request_apply()
    flash("Made a new certificate. Devices that trust NetPulse's authority trust it already.")
    return redirect(url_for(".access_page"))


@bp.get("/settings/access/authority.crt")
@access(SIGNED_IN)
def authority_certificate():
    """NetPulse's certificate authority, to install on a device so its browser trusts this NetPulse.
    The certificate only, which every HTTPS answer already carries; never its key."""
    folder = get_access().tls_folder
    try:
        if folder is None:
            raise TlsError("no certificate folder")
        pem = authority_pem(folder)
    except TlsError:
        abort(404)
    return Response(
        pem, mimetype="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="netpulse-authority.crt"'},
    )


# The audit log (plan section 44)


@bp.get("/settings/audit")
@access(Permission.USERS_MANAGE)
def audit_page():
    before = request.args.get("before", "")
    entries = get_store().audit_entries(AUDIT_PAGE + 1, int(before) if before.isdigit() else None)
    return render_template(
        "audit.html", entries=entries[:AUDIT_PAGE], older=entries[AUDIT_PAGE - 1].id if len(entries) > AUDIT_PAGE else None,
    )
