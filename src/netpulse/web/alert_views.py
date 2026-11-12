"""Alerts (plan section 41): what is wrong now and what was, acknowledging,
and, for those who may, the rules and the notification channels.

The alert engine opens and closes alerts after each check round; nothing here
does. A channel's secret (a webhook's address, a mail password) is stored so
it can be used, and never sent back to a page: an edit form shows where it
points and leaves the secret empty, which keeps it.

Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import abort, flash, redirect, render_template, request, url_for

from netpulse.accounts import Permission
from netpulse.alerts import DELAYS_MIN, SMTP_SECURITY, AlertRules, ChannelKind, Severity, validate_channel
from netpulse.domain import ValidationError
from netpulse.web.app import audit, get_alerts, get_store
from netpulse.web.security import SIGNED_IN, access, actor, can
from netpulse.web.views import bp

HISTORY = 100


@bp.get("/alerts")
@access(SIGNED_IN)
def alerts_page():
    store = get_store()
    return render_template(
        "alerts.html", open=store.open_alerts(), recent=store.recent_alerts(HISTORY), now=datetime.now(UTC),
        notifications=store.notifications(20) if can(Permission.ALERTS_MANAGE) else [],
        channels=len(store.channels()), rules=store.alert_rules(),
    )


@bp.post("/alerts/<int:alert_id>/ack")
@access(Permission.ALERTS_ACK)
def ack_alert(alert_id: int):
    """Acknowledge an alert: say that someone has seen it. It stays open until its cause ends."""
    try:
        alert = get_store().ack_alert(alert_id, actor())
    except KeyError:
        abort(404)
    audit("acknowledged alert", alert.subject, alert.label)
    return redirect(url_for(".alerts_page"))


@bp.post("/alerts/ack-all")
@access(Permission.ALERTS_ACK)
def ack_all_alerts():
    store = get_store()
    pending = [alert for alert in store.open_alerts() if not alert.acked]
    for alert in pending:
        store.ack_alert(alert.id, actor())
    if pending:
        audit("acknowledged alerts", detail=str(len(pending)))
    return redirect(url_for(".alerts_page"))


# Rules and channels


def _settings_page(*, error: str | None = None, error_kind: str | None = None, typed=None, status: int = 200):
    store = get_store()
    page = render_template(
        "alert_settings.html", rules=store.alert_rules(), channels=store.channels(), delays=DELAYS_MIN,
        kinds=ChannelKind.LABELS, severities=Severity.LABELS, security=SMTP_SECURITY, error=error,
        error_kind=error_kind, typed=typed or {}, notifications=store.notifications(20),
    )
    return page, status


@bp.get("/settings/alerts")
@access(Permission.ALERTS_MANAGE)
def alert_settings():
    return _settings_page()


@bp.post("/settings/alerts")
@access(Permission.ALERTS_MANAGE)
def save_alert_rules():
    """What alerts and when a message goes out. A box left unticked is off."""
    form = request.form
    rules = AlertRules.of({
        **{name: form.get(name) == "yes" for name in ("down", "degraded", "new_host", "monitoring", "recovery")},
        "delay_min": form.get("delay_min", "0"), "group_at": form.get("group_at", "3"),
    })
    get_store().save_alert_rules(rules)
    audit("changed alert rules")
    flash("Saved the alert rules.")
    return redirect(url_for(".alert_settings"))


def _channel_or_404(channel_id: int):
    try:
        return get_store().get_channel(channel_id)
    except KeyError:
        abort(404)


def _typed() -> dict:
    """What was typed into a channel form, without its secrets, to show again when it is refused."""
    return {key: value for key, value in request.form.items() if key not in ("csrf_token", "url", "password")}


@bp.post("/settings/alerts/channels")
@access(Permission.ALERTS_MANAGE)
def add_channel():
    kind = request.form.get("kind", "")
    try:
        config = validate_channel(kind, request.form)
        channel = get_store().save_channel(
            None, request.form.get("name", ""), kind, config, enabled=True,
            min_severity=request.form.get("min_severity", Severity.WARNING),
        )
    except ValidationError as exc:
        message = str(exc)
        return _settings_page(error=message[:1].upper() + message[1:], error_kind=kind, typed=_typed(), status=422)
    audit("added notification channel", channel.name, channel.kind)
    flash(f"Added {channel.name}. Send a test message to check it.")
    return redirect(url_for(".alert_settings"))


@bp.get("/settings/alerts/channels/<int:channel_id>")
@access(Permission.ALERTS_MANAGE)
def channel_page(channel_id: int):
    return render_template(
        "channel.html", channel=_channel_or_404(channel_id), severities=Severity.LABELS, security=SMTP_SECURITY,
        error=None, typed={},
    )


@bp.post("/settings/alerts/channels/<int:channel_id>")
@access(Permission.ALERTS_MANAGE)
def update_channel(channel_id: int):
    """Change a channel. A secret left empty keeps the one stored."""
    channel = _channel_or_404(channel_id)
    try:
        config = validate_channel(channel.kind, request.form, existing=channel.config)
        saved = get_store().save_channel(
            channel_id, request.form.get("name", ""), channel.kind, config,
            enabled=request.form.get("enabled") == "yes",
            min_severity=request.form.get("min_severity", Severity.WARNING),
        )
    except ValidationError as exc:
        message = str(exc)
        page = render_template(
            "channel.html", channel=channel, severities=Severity.LABELS, security=SMTP_SECURITY,
            error=message[:1].upper() + message[1:], typed=_typed(),
        )
        return page, 422
    audit("changed notification channel", saved.name)
    flash(f"Saved {saved.name}.")
    return redirect(url_for(".alert_settings"))


@bp.post("/settings/alerts/channels/<int:channel_id>/test")
@access(Permission.ALERTS_MANAGE)
def test_channel(channel_id: int):
    """Send one test message now and say whether it went."""
    channel = _channel_or_404(channel_id)
    engine = get_alerts()
    if engine is None:
        abort(503, description="This NetPulse was started without its alert engine, so nothing can be sent.")
    error = engine.send_test(channel)
    get_store().record_notification(channel, "Test message from NetPulse", error)
    if error is None:
        flash(f"Sent a test message through {channel.name}.")
    else:
        flash(f"The test message through {channel.name} did not go: {error}.", "error")
    return redirect(url_for(".alert_settings"))


@bp.post("/settings/alerts/channels/<int:channel_id>/delete")
@access(Permission.ALERTS_MANAGE)
def delete_channel(channel_id: int):
    channel = _channel_or_404(channel_id)
    get_store().delete_channel(channel_id)
    audit("deleted notification channel", channel.name)
    flash(f"Deleted {channel.name}.")
    return redirect(url_for(".alert_settings"))
