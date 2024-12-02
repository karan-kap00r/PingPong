from fastapi import Request
from pingpongx.services.auth_middleware import require_auth
from pingpongx.services.kafka_consumer import consume_notifications
from pingpongx.services.redis_service import add_to_queue
from pingpongx.services.kafka_producer import send_event
from pingpongx.services.firestore_service import save_notification_log, get_user_preferences, update_user_preferences
from pingpongx.utils import generate_notification_id
from pingpongx.utils import validate_phone_number, validate_email
import time
import os

MAILGUN_EMAIL = os.getenv("MAILGUN_EMAIL", "pingpongreply02@gmail.com")
MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "")


class PingPong:
    """PingPong notification service."""

    def __init__(self, sender=None, receiver=None, message="", channels=None, mailgun_api_key=None, mailgun_domain=None, mailgun_email=None, twilio_account_sid=None, twilio_auth_token=None, twilio_phone_number=None):
        self.sender = sender
        self.receiver = receiver
        self.message = message
        self.channels = channels
        self.mailgun_api_key = mailgun_api_key
        self.mailgun_domain = mailgun_domain
        self.mailgun_email = mailgun_email
        self.twilio_account_sid = twilio_account_sid
        self.twilio_phone_number = twilio_phone_number
        self.twilio_auth_token = twilio_auth_token

    async def send_notification(self):
        try:

            user_id = self.receiver
            username = self.sender
            message = self.message
            channel_list = self.channels
            message_sent_for_channel = []

            if not username or username.strip() == "":
                return {"success": False, "message": f"Please login and try again."}

            if user_id == "" or message == "" or len(channel_list) < 1 or user_id.strip() == "" or message.strip() == "":
                return {"success": False, "message": f"Invalid user_id or message: {user_id} and {message}"}

            username = username.strip().lower()
            user_id = user_id.strip().lower()
            message = message.strip()

            if username == user_id:
                return {"success": False, "message": f"You can't send notification to yourself!"}

            for i in channel_list:
                if i not in ["email", "sms"]:
                    return {"success": False, "message": f"Invalid channel: {i}. Choose from ['email', 'sms']"}

                if i == "email" and validate_email(user_id) is False:
                    return {"success": False, "message": f"Invalid email address: {user_id} as user_id"}

                if i == "sms" and validate_phone_number(user_id) is False:
                    return {"success": False, "message": f"Invalid phone number: {user_id} as user_id"}

                if i == "email" and (self.mailgun_email is None or self.mailgun_domain is None or self.mailgun_email is None):
                    return {"success": False, "message": f"Invalid or missing Mailgun credentials."}

                if i == "sms" and (self.twilio_auth_token is None or self.twilio_phone_number is None or self.twilio_account_sid is None):
                    return {"success": False, "message": f"Invalid or missing Twilio credentials."}

            for channel in channel_list:
                publish = await publish_notification(user_id=user_id, message=message, channel=channel, username=username)
                if publish.get("success") is True:
                    consume = await consume_notifications(receiver=user_id, sender=username, mailgun_api_key=self.mailgun_api_key, mailgun_domain=self.mailgun_domain, mailgun_email=self.mailgun_email, twilio_account_sid=self.twilio_account_sid, twilio_auth_token=self.twilio_auth_token, twilio_phone_number=self.twilio_phone_number)
                    if consume.get("success") is True:
                        message_sent_for_channel.append(channel)

            if message_sent_for_channel and len(message_sent_for_channel) > 0:
                return {"success": True, "message": f"Notification sent to {user_id}."}
            return {"success": False, "message": f"Notification failed to {user_id}."}
        except Exception as e:
            return {"success": False, "message": f"Notification failed due to :{e}"}


@require_auth
async def notify(request: Request, data: dict = None, username: str = None):
    """api method to send notifications"""
    try:
        sender = username
        if data is None:
            return {"success": False, "message": f"Please login and try again with valid payload."}

        receiver = data.get("user_id", "")
        message = data.get("message", "")
        channel_list = data.get("channel", [])
        service = PingPong(sender=sender, receiver=receiver, message=message, channels=channel_list, mailgun_api_key=MAILGUN_API_KEY, mailgun_domain=MAILGUN_DOMAIN, mailgun_email=MAILGUN_EMAIL, twilio_account_sid=TWILIO_ACCOUNT_SID, twilio_auth_token=TWILIO_AUTH_TOKEN, twilio_phone_number=TWILIO_PHONE_NUMBER)
        response = await service.send_notification()
        return response
    except Exception as e:
        return {"success": False, "message": f"Notification failed due to :{e}"}


async def publish_notification(user_id: str, message: str, channel: str, username: str):
    """Send a notification to a user via the specified channel."""

    try:
        user_preferences = await get_user_preferences(user_id)
        if not user_preferences:
            await update_user_preferences(user_id, {"email": True, "sms": True})

        preferences = user_preferences.get("preferences", {})
        if not preferences.get(channel, False):
            return {"success": False, "message": f"User {user_id} hasn't opted for {channel} notifications."}

        notification_data = {"user_id": user_id, "message": message, "channel": channel, "sent_by": username, "timestamp": time.time()}
        redis_status = await add_to_queue(user_id, notification_data)
        if redis_status:
            kafka_status = await send_event(user_id, f"Notification sent to {user_id} via {channel}")
            if kafka_status:
                await save_notification_log(user_id, {"id": generate_notification_id(), "message": message,"sent_by": username, "channel": channel})
                return {"success": True, "message": f"Notification queued successfully for channel: {channel}"}

        return {"success": False, "message": "Notification queued failed"}
    except Exception as e:
        return {"success": False, "message": f"Notification queued failed due to :{e}"}

