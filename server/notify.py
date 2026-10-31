"""Opt-in email worker. Cron reuses the existing consent and delivery outbox."""
from email.message import EmailMessage
from email.utils import formatdate
import fcntl
import json
import re
import secrets
import smtplib
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from app import (BOX, CONFIG, DATA, ORIGIN, VERSION, NoRedirect, database,
                 email_delivery_available, live_metadata, offline_after,
                 notification_target, smtp_available, w_mail_profile)


def delivery_metadata():
    if CONFIG.get("email_provider", "smtp") == "w-mail":
        return {"provider": "w-mail", **w_mail_profile(), "operation_id": "wm_" + secrets.token_hex(16),
                "post_started": False, "lookups": 0, "next_at": 0}
    return {"provider": "smtp"}


def message_content(item):
    recipient = notification_target(item["space_id"], item["recipient"])
    english = item["notification_locale"] == "en"
    label = ("reporting restored" if item["state"] == "online" else "report overdue") if english else ("恢复上报" if item["state"] == "online" else "上报已超时")
    name = "".join(character for character in item["name"] if ord(character) >= 32 and ord(character) != 127)[:80]
    management = ORIGIN + "/manage/" + BOX.seal("manage", {"id": item["space_id"]})
    text = f"Device: {name}\nStatus: {label}\n\nAn overdue report means the receiver did not receive data on schedule; it does not identify the cause of a host failure.\nView space: {management}\n\nThis management link still requires sign-in or your private recovery key. Disable notifications in the space's email settings." if english else f"设备：{name}\n状态：{label}\n\n超时表示接收端未按预期收到采集数据，不代表已经确定主机故障原因。\n查看空间：{management}\n\n此管理地址仍需要登录或私密恢复口令。你可在空间的邮箱设置中关闭通知。"
    return recipient, f"W Monitor · {name} {label}", text


def mail_log(meta, status, code):
    # Never include the envelope, subject, body, management link or raw errors.
    print(json.dumps({"event": "mail.delivery.state", "project_id": "w-monitor-public",
                      "event_id": meta["operation_id"], "attempt_id": meta["operation_id"],
                      "job_id": meta.get("job_id"), "provider_id": meta.get("provider_id"),
                      "status": status, "code": code}), file=sys.stderr)


def receipt_status(body, meta, target, event_type):
    expected_context = {"eventId": meta["operation_id"], "attemptId": meta["operation_id"], "eventType": event_type}
    recipient = "user:" + target["userId"] if isinstance(target, dict) else target.strip().lower()
    if (not isinstance(body, dict) or body.get("mailboxId") != meta["mailbox_id"] or
            (not isinstance(body.get("actor"), dict) or body["actor"].get("kind") != "project" or body["actor"].get("projectId") != meta["project_id"]) or
            not re.fullmatch(r"[a-f0-9]{32}", str(body.get("id", ""))) or
            (meta.get("job_id") and meta["job_id"] != body["id"]) or
            body.get("operationId") != meta["operation_id"] or body.get("context") != expected_context or
            (body.get("recipientUserId") != target["userId"] if isinstance(target, dict) else "recipientUserId" in body) or
            body.get("status") not in ("queued", "submitting", "submitted", "unknown", "failed", "cancelled")):
        return "unknown", "mail_receipt_invalid"
    provider = body.get("providerId")
    if provider is not None and (not isinstance(provider, str) or not re.fullmatch(r"<[A-Za-z0-9_.-]{1,128}@(agentmail|botmail)\.myfastools\.com>", provider)):
        return "unknown", "mail_receipt_invalid"
    recipients = body.get("recipients")
    if not isinstance(recipients, dict) or set(recipients) != {recipient} or not isinstance(recipients[recipient], dict):
        return "unknown", "mail_receipt_invalid"
    state = recipients[recipient].get("status")
    if state not in ("queued", "delivered", "bounced", "failed", "rejected", "deferred", "complained"):
        return "unknown", "mail_receipt_invalid"
    review = body.get("review")
    if review is not None:
        if (not isinstance(review, dict) or review.get("state") not in ("pending", "approved", "rejected") or
                review.get("reason") != "platform_frequency" or type(review.get("requestedAt")) is not int or
                any(key in review and type(review[key]) is not int for key in ("decidedAt",))):
            return "unknown", "mail_receipt_invalid"
        meta["review"] = {key: review[key] for key in ("state", "reason", "requestedAt", "decidedAt") if key in review}
    meta["job_id"], meta["provider_id"] = body["id"], provider
    meta["submission_status"], meta["recipient_status"] = body["status"], state
    if state == "delivered" and provider:
        return "delivered", "mail_delivered"
    if state in ("bounced", "failed", "rejected", "complained") or body["status"] in ("failed", "cancelled"):
        return "failed", "mail_provider_failed"
    if body["status"] == "submitted" and provider:
        return "provider_accepted", "mail_provider_accepted"
    return "unknown", "mail_submission_unknown"


def deliver_w_mail(db, item, meta, now):
    if meta.get("complete") or meta.get("next_at", 0) > now:
        return
    if item["created_at"] + 2 * 86400 <= now or meta.get("lookups", 0) >= 6:
        meta["complete"], meta["code"] = True, "mail_receipt_deadline_elapsed"
        meta["updated_at"] = meta["completed_at"] = now
        db.execute("UPDATE notification_outbox SET status=CASE WHEN status='provider_accepted' THEN status ELSE 'unknown' END,delivery=? WHERE id=?", (json.dumps(meta), item["id"]))
        mail_log(meta, item["status"] if item["status"] == "provider_accepted" else "unknown", "mail_receipt_deadline_elapsed")
        return
    profile = w_mail_profile()
    if not profile or any(meta.get(key) != value for key, value in profile.items()):
        meta["next_at"], meta["code"] = min(now + 300, item["created_at"] + 2 * 86400), "mail_config_changed"
        db.execute("UPDATE notification_outbox SET delivery=? WHERE id=?", (json.dumps(meta), item["id"]))
        mail_log(meta, "unknown", "mail_config_changed")
        return  # Never repoint an old operation at another service or mailbox.
    first = not meta.get("post_started")
    if first and CONFIG.get("email_provider", "smtp") != "w-mail":
        return  # An inactive profile may reconcile, never initiate a send.
    try:
        target = notification_target(item["space_id"], item["recipient"])
        if first and not isinstance(target, dict):
            meta["complete"], meta["code"], meta["completed_at"] = True, "mail_identity_rebind_required", now
            db.execute("UPDATE notification_outbox SET status='superseded',delivery=? WHERE id=?", (json.dumps(meta), item["id"]))
            mail_log(meta, "superseded", "mail_identity_rebind_required")
            return
        payload = None
        if first:
            target, subject, text = message_content(item)
            payload = json.dumps({"recipientUserId": target["userId"], "subject": subject, "text": text,
                                  "context": {"eventId": meta["operation_id"], "attemptId": meta["operation_id"],
                                              "eventType": "monitor.host." + item["state"]}}).encode()
        old = item["delivery"]
        meta["post_started"], meta["updated_at"] = True, now
        meta["next_at"] = min(now + 300, item["created_at"] + 2 * 86400)
        if not first:
            meta["lookups"] += 1
        # This autocommit is the no-resubmit boundary, before any network call.
        changed = db.execute("UPDATE notification_outbox SET status='unknown',delivery=?,attempts=attempts+?,attempted_at=CASE WHEN ? THEN ? ELSE attempted_at END WHERE id=? AND delivery=?",
                             (json.dumps(meta), int(first), int(first), now, item["id"], old)).rowcount
        if not changed:
            return
        db.commit()
        request = Request(profile["url"] + "/api/v1/mailboxes/" + profile["mailbox_id"] + "/sends", data=payload,
                          method="POST" if first else "GET", headers={"Authorization": "Bearer " + CONFIG["w_mail_api_key"],
                          "X-W-Project-Id": profile["project_id"], "Idempotency-Key": meta["operation_id"],
                          "Content-Type": "application/json", "User-Agent": "W-Monitor-Public/" + VERSION})
        try:
            # No proxy, redirects or automatic retries can forward this credential.
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
                raw = response.read(32769)
                if len(raw) > 32768:
                    raise ValueError("Receipt too large")
                state, code = receipt_status(json.loads(raw), meta, target, "monitor.host." + item["state"])
        except HTTPError as error:
            state, code = "unknown", {401: "mail_auth_rejected", 403: "mail_scope_rejected", 404: "mail_operation_not_visible", 429: "mail_rate_limited"}.get(error.code, "mail_http_unknown")
        except Exception:
            state, code = "unknown", "mail_transport_unknown"
        meta["updated_at"] = int(time.time())
        if state in ("delivered", "failed"):
            meta["complete"], meta["completed_at"] = True, meta["updated_at"]
        meta["code"] = code
        db.execute("UPDATE notification_outbox SET status=?,delivery=? WHERE id=? AND status='unknown'", (state, json.dumps(meta), item["id"]))
        mail_log(meta, state, code)
    except Exception:
        mail_log(meta, "unknown", "mail_local_operation_failed")


def main():
    from metrics import collect_uptime
    availability = collect_uptime()
    configured = email_delivery_available()
    with open(DATA / "notifications.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"already_running": True}
        now = int(time.time())
        with database() as db:
            rows = db.execute("SELECT d.id,d.name,d.space_id,s.email FROM devices d JOIN spaces s ON s.id=d.space_id WHERE s.notifications_enabled=1 AND s.email IS NOT NULL").fetchall() if configured else []
            metadata, available = live_metadata(rows) if rows else ({}, True)
            db.execute("BEGIN IMMEDIATE")
            for device in rows:
                try:
                    target = notification_target(device["space_id"], device["email"])
                except ValueError:
                    continue
                if (CONFIG.get("email_provider", "smtp") == "w-mail") != isinstance(target, dict):
                    continue  # A provider switch requires explicit rebinding.
                meta = metadata.get(device["id"])
                if not isinstance(meta, dict) or type(meta.get("received_at")) is not int:
                    continue  # Missing Redis data is unknown, never an outage.
                state = "online" if meta["received_at"] >= now - offline_after(meta) else "offline"
                previous = db.execute("SELECT * FROM notification_state WHERE device_id=?", (device["id"],)).fetchone()
                if not previous:
                    db.execute("INSERT INTO notification_state(device_id,state) VALUES(?,?)", (device["id"], state))
                elif previous["state"] != state:
                    if db.execute("SELECT COUNT(*) FROM notification_outbox WHERE status IN ('pending','sending') OR (status IN ('unknown','provider_accepted') AND COALESCE(json_extract(delivery,'$.complete'),0)=0)").fetchone()[0] >= 2000:
                        continue
                    revision = previous["revision"] + 1
                    db.execute("INSERT OR IGNORE INTO notification_outbox(space_id,device_id,revision,state,recipient,created_at,delivery) VALUES(?,?,?,?,?,?,?)", (device["space_id"], device["id"], revision, state, device["email"], now, json.dumps(delivery_metadata())))
                    db.execute("UPDATE notification_state SET state=?,revision=? WHERE device_id=?", (state, revision, device["id"]))
            db.execute("UPDATE notification_outbox SET status=CASE WHEN attempts<2 THEN 'pending' ELSE 'failed' END WHERE status='sending' AND attempted_at<?", (now - 120,))
            # Delivery history and unresolved tombstones are retained. Closed
            # records do not occupy the active queue. NULL history stays SMTP.
            db.commit()
        sent, failed, transport = 0, 0, None
        deadline = time.monotonic() + 35
        try:
            with database() as db:
                pending = db.execute("SELECT o.*,d.name,s.email,s.notifications_enabled,s.notification_locale,n.state AS latest_state FROM notification_outbox o JOIN devices d ON d.id=o.device_id JOIN spaces s ON s.id=o.space_id LEFT JOIN notification_state n ON n.device_id=o.device_id WHERE ((o.status='pending' AND o.attempts<2 AND COALESCE(json_extract(o.delivery,'$.next_at'),0)<=?) OR (o.status IN ('unknown','provider_accepted') AND COALESCE(json_extract(o.delivery,'$.complete'),0)=0 AND COALESCE(json_extract(o.delivery,'$.next_at'),0)<=?)) AND (json_extract(o.delivery,'$.provider')='w-mail' OR ?) ORDER BY o.id LIMIT 8", (now, now, int(smtp_available()))).fetchall()
                for item in pending:
                    if time.monotonic() >= deadline:
                        break
                    meta = json.loads(item["delivery"]) if item["delivery"] else {"provider": "smtp"}
                    posted = meta.get("post_started") is True
                    if not posted:
                        if not available:
                            continue
                        if not item["notifications_enabled"] or item["email"] != item["recipient"] or item["latest_state"] != item["state"]:
                            db.execute("UPDATE notification_outbox SET status='superseded' WHERE id=?", (item["id"],))
                            continue
                        today = now - now % 86400
                        total = db.execute("SELECT COUNT(*) FROM notification_outbox WHERE attempted_at>=? AND attempts>0", (today,)).fetchone()[0]
                        personal = db.execute("SELECT COUNT(*) FROM notification_outbox WHERE space_id=? AND attempted_at>=? AND attempts>0", (item["space_id"], today)).fetchone()[0]
                        if total >= 50 or personal >= 5:
                            continue
                    if meta["provider"] == "w-mail":
                        deliver_w_mail(db, item, meta, now)
                        continue
                    if not smtp_available():
                        continue
                    db.execute("UPDATE notification_outbox SET status='sending',attempts=attempts+1,attempted_at=? WHERE id=?", (now, item["id"]))
                    try:
                        recipient, subject, text = message_content(item)
                        if not isinstance(recipient, str):
                            db.execute("UPDATE notification_outbox SET status='superseded' WHERE id=?", (item["id"],))
                            continue
                        if transport is None:
                            transport = smtplib.SMTP(CONFIG["smtp_host"], int(CONFIG.get("smtp_port", 587)), timeout=5)
                            transport.ehlo()
                            transport.starttls(context=ssl.create_default_context())
                            transport.ehlo()
                            transport.login(CONFIG["smtp_user"], CONFIG["smtp_password"])
                        message = EmailMessage()
                        message["From"], message["To"] = CONFIG["smtp_from"], recipient
                        message["Subject"], message["Date"] = subject, formatdate(localtime=False)
                        message["Message-ID"] = f"<wm-public-{item['id']}@{urlsplit(ORIGIN).hostname}>"
                        message.set_content(text)
                        transport.send_message(message)
                        db.execute("UPDATE notification_outbox SET status='sent' WHERE id=?", (item["id"],))
                        sent += 1
                    except Exception:
                        db.execute("UPDATE notification_outbox SET status=CASE WHEN attempts>=2 THEN 'failed' ELSE 'pending' END WHERE id=?", (item["id"],))
                        failed += 1
                        break  # A failing relay must not fan out more attempts.
        finally:
            if transport:
                try:
                    transport.quit()
                except OSError:
                    transport.close()
        return {"sent": sent, "failed": failed, "dynamic_available": available, "configured": configured, "availability": availability}


if __name__ == "__main__":
    print(json.dumps(main()))
