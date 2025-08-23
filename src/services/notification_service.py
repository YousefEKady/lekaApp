"""Notification Service for Leka-App SaaS Edition.

Handles email and Telegram notifications for leak alerts and system notifications.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import aiosmtplib
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from src.database.models import User, Company, Notification, NotificationStatus
from src.database.connection import get_db
from src.config.config import config

logger = logging.getLogger(__name__)


class EmailConfig(BaseModel):
    """Email configuration settings."""
    smtp_host: str = "smtp.gmail.com"  # TODO: Change to production SMTP server in production
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    from_email: str
    use_tls: bool = True
    use_ssl: bool = False


class TelegramConfig(BaseModel):
    """Telegram bot configuration settings."""
    bot_token: str
    chat_id: Optional[str] = None
    api_url: str = "https://api.telegram.org/bot"  # TODO: Change to production Telegram API URL in production


class NotificationTemplate(BaseModel):
    """Notification template for different types of alerts."""
    subject: str
    html_body: str
    text_body: str
    telegram_message: str


class LeakAlert(BaseModel):
    """Leak alert data structure."""
    company_name: str
    domain: str
    leak_count: int
    leak_details: List[Dict[str, Any]]
    detected_at: datetime
    severity: str = "medium"


class NotificationService:
    """Service for handling all types of notifications."""
    
    def __init__(self, email_config: Optional[EmailConfig] = None, telegram_config: Optional[TelegramConfig] = None):
        self.email_config = email_config or config.get_email_config()
        self.telegram_config = telegram_config or (
            {
                "bot_token": config.TELEGRAM_API_ID,
                "chat_id": config.TELEGRAM_CHANNEL_ID,
                "api_url": "https://api.telegram.org/bot"
            } if config.validate_telegram_config() else None
        )
        self.templates = self._load_templates()
        
    def _load_templates(self) -> Dict[str, NotificationTemplate]:
        """Load notification templates for different alert types."""
        return {
            "leak_alert": NotificationTemplate(
                subject="🚨 Security Alert: Leaked Credentials Detected for {domain}",
                html_body="""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="margin: 0; font-size: 24px;">🚨 Security Alert</h1>
                            <p style="margin: 10px 0 0 0; font-size: 16px;">Leaked credentials detected</p>
                        </div>
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
                            <h2 style="color: #dc3545; margin-top: 0;">Alert Details</h2>
                            <p><strong>Company:</strong> {company_name}</p>
                            <p><strong>Domain:</strong> {domain}</p>
                            <p><strong>Leaked Credentials Found:</strong> {leak_count}</p>
                            <p><strong>Detection Time:</strong> {detected_at}</p>
                            <p><strong>Severity:</strong> <span style="color: #dc3545; font-weight: bold;">{severity}</span></p>
                            
                            <h3 style="color: #495057;">Recommended Actions:</h3>
                            <ul style="color: #6c757d;">
                                <li>Immediately reset passwords for affected accounts</li>
                                <li>Enable two-factor authentication if not already active</li>
                                <li>Monitor accounts for suspicious activity</li>
                                <li>Review and update security policies</li>
                            </ul>
                            
                            <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px;">
                                <p style="margin: 0; color: #856404;"><strong>Note:</strong> This is an automated alert from Leka-App. Please log in to your dashboard for detailed information.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """,
                text_body="""
🚨 SECURITY ALERT: Leaked Credentials Detected

Company: {company_name}
Domain: {domain}
Leaked Credentials Found: {leak_count}
Detection Time: {detected_at}
Severity: {severity}

RECOMMENDED ACTIONS:
- Immediately reset passwords for affected accounts
- Enable two-factor authentication if not already active
- Monitor accounts for suspicious activity
- Review and update security policies

This is an automated alert from Leka-App.
Please log in to your dashboard for detailed information.
                """,
                telegram_message="""
🚨 *SECURITY ALERT*

*Company:* {company_name}
*Domain:* {domain}
*Leaked Credentials:* {leak_count}
*Time:* {detected_at}
*Severity:* {severity}

⚠️ Immediate action required!
Log in to your Leka-App dashboard for details.
                """
            ),
            "welcome": NotificationTemplate(
                subject="Welcome to Leka-App - Your Account is Ready!",
                html_body="""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0;">
                            <h1 style="margin: 0; font-size: 24px;">Welcome to Leka-App!</h1>
                            <p style="margin: 10px 0 0 0; font-size: 16px;">Your security monitoring starts now</p>
                        </div>
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
                            <h2 style="color: #28a745; margin-top: 0;">Account Created Successfully</h2>
                            <p>Hello {company_name},</p>
                            <p>Your Leka-App account has been successfully created. You can now start monitoring your domains for potential security breaches.</p>
                            
                            <h3 style="color: #495057;">Next Steps:</h3>
                            <ol style="color: #6c757d;">
                                <li>Log in to your dashboard</li>
                                <li>Add your company domains</li>
                                <li>Configure notification preferences</li>
                                <li>Review security recommendations</li>
                            </ol>
                            
                            <div style="margin-top: 20px; text-align: center;">
                                <a href="#" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Access Dashboard</a>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """,
                text_body="""
Welcome to Leka-App!

Hello {company_name},

Your Leka-App account has been successfully created. You can now start monitoring your domains for potential security breaches.

Next Steps:
1. Log in to your dashboard
2. Add your company domains
3. Configure notification preferences
4. Review security recommendations

Thank you for choosing Leka-App for your security monitoring needs.
                """,
                telegram_message="""
🎉 *Welcome to Leka-App!*

Hello {company_name}!

Your account is ready. Start monitoring your domains for security breaches.

📋 *Next Steps:*
1️⃣ Log in to dashboard
2️⃣ Add your domains
3️⃣ Configure notifications
4️⃣ Review security tips
                """
            )
        }
    
    async def send_leak_alert(self, user_email: str, company_name: str, leak_alert: LeakAlert) -> bool:
        """Send leak alert notification via email and optionally Telegram."""
        try:
            template = self.templates["leak_alert"]
            
            # Format template with leak data
            context = {
                "company_name": company_name,
                "domain": leak_alert.domain,
                "leak_count": leak_alert.leak_count,
                "detected_at": leak_alert.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "severity": leak_alert.severity.upper()
            }
            
            # Send email
            email_sent = await self._send_email(
                to_email=user_email,
                subject=template.subject.format(**context),
                html_body=template.html_body.format(**context),
                text_body=template.text_body.format(**context)
            )
            
            # Send Telegram if configured
            telegram_sent = True
            if self.telegram_config:
                telegram_sent = await self._send_telegram(
                    message=template.telegram_message.format(**context)
                )
            
            # Log notification
            await self._log_notification(
                user_email=user_email,
                notification_type="leak_alert",
                status="sent" if email_sent and telegram_sent else "failed",
                details=context
            )
            
            return email_sent and telegram_sent
            
        except Exception as e:
            logger.error(f"Failed to send leak alert: {str(e)}")
            return False
    
    async def send_welcome_notification(self, user_email: str, company_name: str) -> bool:
        """Send welcome notification to new users."""
        try:
            template = self.templates["welcome"]
            context = {"company_name": company_name}
            
            # Send email
            email_sent = await self._send_email(
                to_email=user_email,
                subject=template.subject.format(**context),
                html_body=template.html_body.format(**context),
                text_body=template.text_body.format(**context)
            )
            
            # Send Telegram if configured
            telegram_sent = True
            if self.telegram_config:
                telegram_sent = await self._send_telegram(
                    message=template.telegram_message.format(**context)
                )
            
            # Log notification
            await self._log_notification(
                user_email=user_email,
                notification_type="welcome",
                status="sent" if email_sent and telegram_sent else "failed",
                details=context
            )
            
            return email_sent and telegram_sent
            
        except Exception as e:
            logger.error(f"Failed to send welcome notification: {str(e)}")
            return False
    
    async def _send_email(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send email using SMTP."""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.email_config.from_email
            message["To"] = to_email
            
            # Add text and HTML parts
            text_part = MIMEText(text_body, "plain")
            html_part = MIMEText(html_body, "html")
            
            message.attach(text_part)
            message.attach(html_part)
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.email_config.smtp_host,
                port=self.email_config.smtp_port,
                username=self.email_config.smtp_username,
                password=self.email_config.smtp_password,
                use_tls=self.email_config.use_tls
            )
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    async def _send_telegram(self, message: str, chat_id: Optional[str] = None) -> bool:
        """Send Telegram message."""
        if not self.telegram_config:
            return True
            
        try:
            import httpx
            
            target_chat_id = chat_id or self.telegram_config.chat_id
            if not target_chat_id:
                logger.warning("No Telegram chat ID configured")
                return False
            
            url = f"{self.telegram_config.api_url}{self.telegram_config.bot_token}/sendMessage"
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json={
                        "chat_id": target_chat_id,
                        "text": message,
                        "parse_mode": "Markdown"
                    }
                )
                
                if response.status_code == 200:
                    logger.info(f"Telegram message sent successfully to {target_chat_id}")
                    return True
                else:
                    logger.error(f"Failed to send Telegram message: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {str(e)}")
            return False
    
    async def _log_notification(self, user_email: str, notification_type: str, status: str, details: Dict[str, Any]) -> None:
        """Log notification to database."""
        try:
            async with get_db() as db:
                # Find user
                user = db.query(User).filter(User.email == user_email).first()
                if not user:
                    logger.warning(f"User not found for email: {user_email}")
                    return
                
                # Create notification record
                notification = Notification(
                    user_id=user.id,
                    company_id=user.company_id,
                    type=notification_type,
                    status=NotificationStatus.SENT if status == "sent" else NotificationStatus.FAILED,
                    message=f"{notification_type} notification",
                    metadata=details
                )
                
                db.add(notification)
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log notification: {str(e)}")
    
    async def get_notification_history(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get notification history for a user."""
        try:
            async with get_db() as db:
                notifications = (
                    db.query(Notification)
                    .filter(Notification.user_id == user_id)
                    .order_by(Notification.created_at.desc())
                    .limit(limit)
                    .all()
                )
                
                return [
                    {
                        "id": notif.id,
                        "type": notif.type,
                        "status": notif.status.value,
                        "message": notif.message,
                        "created_at": notif.created_at.isoformat(),
                        "metadata": notif.metadata
                    }
                    for notif in notifications
                ]
                
        except Exception as e:
            logger.error(f"Failed to get notification history: {str(e)}")
            return []
    
    async def test_email_connection(self) -> bool:
        """Test email configuration."""
        try:
            # Test SMTP connection
            smtp = aiosmtplib.SMTP(
                hostname=self.email_config.smtp_host,
                port=self.email_config.smtp_port,
                use_tls=self.email_config.use_tls
            )
            
            await smtp.connect()
            await smtp.login(self.email_config.smtp_username, self.email_config.smtp_password)
            await smtp.quit()
            
            logger.info("Email connection test successful")
            return True
            
        except Exception as e:
            logger.error(f"Email connection test failed: {str(e)}")
            return False
    
    async def test_telegram_connection(self) -> bool:
        """Test Telegram bot configuration."""
        if not self.telegram_config:
            return True
            
        try:
            import httpx
            
            url = f"{self.telegram_config.api_url}{self.telegram_config.bot_token}/getMe"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    bot_info = response.json()
                    logger.info(f"Telegram bot connection successful: {bot_info.get('result', {}).get('username')}")
                    return True
                else:
                    logger.error(f"Telegram connection test failed: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram connection test failed: {str(e)}")
            return False


# Notification service instance (to be initialized with config)
notification_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """Get notification service instance."""
    global notification_service
    if notification_service is None:
        raise RuntimeError("Notification service not initialized")
    return notification_service


def initialize_notification_service(email_config: EmailConfig, telegram_config: Optional[TelegramConfig] = None) -> None:
    """Initialize notification service with configuration."""
    global notification_service
    notification_service = NotificationService(email_config, telegram_config)