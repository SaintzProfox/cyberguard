"""
Notification service: email and Telegram alerts
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Send email notifications via SMTP."""

    def send(self, to_email: str, subject: str, html_body: str) -> bool:
        if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.warning("SMTP not configured, skipping email")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
            msg["To"] = to_email
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.EMAILS_FROM_EMAIL, to_email, msg.as_string())
            logger.info(f"Email sent to {to_email}: {subject}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    def send_alert_email(self, to_email: str, title: str, message: str, severity: str) -> bool:
        severity_colors = {
            "CRITICAL": "#ef4444", "HIGH": "#f97316",
            "MEDIUM": "#f59e0b", "LOW": "#eab308", "INFO": "#3b82f6",
        }
        color = severity_colors.get(severity, "#06b6d4")

        html = f"""
        <html><body style="font-family:sans-serif;background:#0f172a;color:#f1f5f9;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#1e293b;border-radius:12px;padding:24px;border:1px solid #334155;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
              <span style="background:#06b6d4;color:white;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:bold;">
                🛡️ CyberGuard Alert
              </span>
              <span style="background:{color}22;color:{color};padding:4px 10px;border-radius:20px;font-size:11px;font-weight:bold;border:1px solid {color}44;">
                {severity}
              </span>
            </div>
            <h2 style="color:#f1f5f9;margin:0 0 12px 0;font-size:18px;">{title}</h2>
            <p style="color:#94a3b8;line-height:1.6;margin:0 0 20px 0;">{message}</p>
            <a href="{settings.NEXTAUTH_URL if hasattr(settings, 'NEXTAUTH_URL') else '#'}/dashboard/alerts"
               style="background:#06b6d4;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;">
              View in Dashboard →
            </a>
            <p style="color:#475569;font-size:11px;margin-top:20px;">
              CyberGuard Security Platform — You're receiving this because you have alerts enabled.
            </p>
          </div>
        </body></html>
        """
        return self.send(to_email, f"[CyberGuard] {severity}: {title}", html)


class TelegramService:
    """Send Telegram notifications via bot."""

    def __init__(self):
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.base_url = f"https://api.telegram.org/bot{self.token}" if self.token else None

    def send_message(self, chat_id: str, message: str) -> bool:
        if not self.token or not self.base_url:
            logger.warning("Telegram not configured, skipping")
            return False
        try:
            import httpx
            response = httpx.post(
                f"{self.base_url}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=10,
            )
            if response.status_code == 200:
                logger.info(f"Telegram message sent to {chat_id}")
                return True
            logger.error(f"Telegram API error: {response.text}")
            return False
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False

    def send_alert(self, chat_id: str, title: str, message: str, severity: str) -> bool:
        icons = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}
        icon = icons.get(severity, "⚠️")
        text = f"{icon} *CyberGuard Alert — {severity}*\n\n*{title}*\n\n{message}"
        return self.send_message(chat_id, text)


# Singletons
email_service = EmailService()
telegram_service = TelegramService()
