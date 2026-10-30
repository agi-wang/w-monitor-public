"""Opt-in offline/recovery email worker. Run once per minute from account Cron.

Telemetry stays in Redis. SQLite holds notification consent, encrypted contact
information and the bounded delivery outbox needed to avoid losing queued mail.
"""
from email.message import EmailMessage
from email.utils import formatdate
import fcntl
import json
import smtplib
import ssl
import time
from urllib.parse import urlsplit

from app import BOX, CACHE, CONFIG, DATA, ORIGIN, database, live_metadata, offline_after


def main():
    from metrics import collect_uptime
    availability = collect_uptime()
    required = ("smtp_host", "smtp_user", "smtp_password", "smtp_from")
    if not all(CONFIG.get(key) for key in required):
        return {"configured": False, "availability": availability}
    with open(DATA / "notifications.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"already_running": True}
        now = int(time.time())
        with database() as db:
            rows = db.execute("SELECT d.id,d.name,d.space_id,s.email FROM devices d JOIN spaces s ON s.id=d.space_id WHERE s.notifications_enabled=1 AND s.email IS NOT NULL").fetchall()
            metadata, available = live_metadata(rows)
            if not available:
                return {"dynamic_available": False}
            db.execute("BEGIN IMMEDIATE")
            for device in rows:
                meta = metadata.get(device["id"])
                if not isinstance(meta, dict) or type(meta.get("received_at")) is not int:
                    continue  # Missing Redis data is unknown, never an outage.
                state = "online" if meta["received_at"] >= now - offline_after(meta) else "offline"
                previous = db.execute("SELECT * FROM notification_state WHERE device_id=?", (device["id"],)).fetchone()
                if not previous:
                    db.execute("INSERT INTO notification_state(device_id,state) VALUES(?,?)", (device["id"], state))
                elif previous["state"] != state:
                    if db.execute("SELECT COUNT(*) FROM notification_outbox WHERE status IN ('pending','sending')").fetchone()[0] >= 2000:
                        continue
                    revision = previous["revision"] + 1
                    db.execute("INSERT OR IGNORE INTO notification_outbox(space_id,device_id,revision,state,recipient,created_at) VALUES(?,?,?,?,?,?)", (device["space_id"], device["id"], revision, state, device["email"], now))
                    db.execute("UPDATE notification_state SET state=?,revision=? WHERE device_id=?", (state, revision, device["id"]))
            db.execute("UPDATE notification_outbox SET status=CASE WHEN attempts<2 THEN 'pending' ELSE 'failed' END WHERE status='sending' AND attempted_at<?", (now - 120,))
            db.execute("DELETE FROM notification_outbox WHERE id IN (SELECT id FROM notification_outbox WHERE status NOT IN ('pending','sending') AND created_at<? LIMIT 128)", (now - 30 * 86400,))
            db.commit()
        sent, failed = 0, 0
        transport = None
        try:
            with database() as db:
                pending = db.execute("SELECT o.*,d.name,s.email,s.notifications_enabled,s.notification_locale,n.state AS latest_state FROM notification_outbox o JOIN devices d ON d.id=o.device_id JOIN spaces s ON s.id=o.space_id JOIN notification_state n ON n.device_id=o.device_id WHERE o.status='pending' AND o.attempts<2 ORDER BY o.id LIMIT 8").fetchall()
                for item in pending:
                    if not item["notifications_enabled"] or item["email"] != item["recipient"] or item["latest_state"] != item["state"]:
                        db.execute("UPDATE notification_outbox SET status='superseded' WHERE id=?", (item["id"],))
                        continue
                    today = now - now % 86400
                    total = db.execute("SELECT COUNT(*) FROM notification_outbox WHERE attempted_at>=? AND attempts>0", (today,)).fetchone()[0]
                    personal = db.execute("SELECT COUNT(*) FROM notification_outbox WHERE space_id=? AND attempted_at>=? AND attempts>0", (item["space_id"], today)).fetchone()[0]
                    if total >= 50 or personal >= 5:
                        continue
                    db.execute("UPDATE notification_outbox SET status='sending',attempts=attempts+1,attempted_at=? WHERE id=?", (now, item["id"]))
                    try:
                        recipient = BOX.open("notification-email:" + item["space_id"], item["recipient"])
                        if not isinstance(recipient, str) or "\r" in recipient or "\n" in recipient:
                            raise ValueError("Invalid verified recipient")
                        if transport is None:
                            transport = smtplib.SMTP(CONFIG["smtp_host"], int(CONFIG.get("smtp_port", 587)), timeout=5)
                            transport.ehlo()
                            transport.starttls(context=ssl.create_default_context())
                            transport.ehlo()
                            transport.login(CONFIG["smtp_user"], CONFIG["smtp_password"])
                        english = item["notification_locale"] == "en"
                        label = ("reporting restored" if item["state"] == "online" else "report overdue") if english else ("恢复上报" if item["state"] == "online" else "上报已超时")
                        name = "".join(character for character in item["name"] if ord(character) >= 32 and ord(character) != 127)[:80]
                        message = EmailMessage()
                        message["From"], message["To"] = CONFIG["smtp_from"], recipient
                        message["Subject"] = f"W Monitor · {name} {label}"
                        message["Date"] = formatdate(localtime=False)
                        message["Message-ID"] = f"<wm-public-{item['id']}@{urlsplit(ORIGIN).hostname}>"
                        management = ORIGIN + "/manage/" + BOX.seal("manage", {"id": item["space_id"]})
                        message.set_content(f"Device: {name}\nStatus: {label}\n\nAn overdue report means the receiver did not receive data on schedule; it does not identify the cause of a host failure.\nView space: {management}\n\nThis management link still requires sign-in or your private recovery key. Disable notifications in the space's email settings." if english else f"设备：{name}\n状态：{label}\n\n超时表示接收端未按预期收到采集数据，不代表已经确定主机故障原因。\n查看空间：{management}\n\n此管理地址仍需要登录或私密恢复口令。你可在空间的邮箱设置中关闭通知。")
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
        return {"sent": sent, "failed": failed, "dynamic_available": True}


if __name__ == "__main__":
    print(json.dumps(main()))
