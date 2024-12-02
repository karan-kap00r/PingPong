from pingpongx.services.email_service import MailgunEmailService
from kafka import KafkaConsumer
from pingpongx.utils import validate_email, validate_phone_number, sanitize_topic_name
from pingpongx.services.push_service import send_push_notification
from pingpongx.services.redis_service import get_from_queue, read_from_queue, delete_data_by_msg
from pingpongx.services.sms_service import SmsService
import json
import time
import os

TOPIC_NAME = os.getenv('TOPIC_NAME')
REDIS_TIME_LIMIT = os.getenv("REDIS_TIME_LIMIT")


async def process_message(user_id: str, message_data, username: str, mailgun_api_key=None, mailgun_domain=None, mailgun_email=None, twilio_account_sid=None, twilio_auth_token=None, twilio_phone_number=None):
    try:
        channel = message_data.get('channel')
        notification_message = message_data.get('message')
        success = False

        if not all(key in message_data for key in ['user_id', 'channel', 'message']):
            print(f"Malformed message: {message_data}")
            return False

        if "email" in channel and user_id and mailgun_api_key and mailgun_domain and mailgun_email:
            if validate_email(user_id) is False:
                print(f"Invalid email address: {user_id} as user_id")
                return False

            email_subject = f"PingPong from {username}"
            email_body = f"Notification sent to {user_id} via {channel}: {notification_message}"
            mailgun_instance = MailgunEmailService(mailgun_api_key, mailgun_domain, mailgun_email)
            send_email_success, send_email_status = await mailgun_instance.send_email(user_id, email_subject, email_body)
            if send_email_status == 200 and send_email_success:
                success = True

        if "sms" in channel and user_id and twilio_account_sid and twilio_auth_token and twilio_phone_number:
            if validate_phone_number(user_id) is False:
                print(f"Invalid phone number: {user_id} as user_id")
                return False
            sms_instance = SmsService(twilio_account_sid, twilio_auth_token, twilio_phone_number)
            success = sms_instance.send_sms(user_id, notification_message)

        if channel == "push":
            title = f"Notification for User {user_id}"
            body = notification_message
            response = send_push_notification([""], title, body)
            if response:
                print(f"Push notification sent successfully to user {user_id}")
                success = True
            else:
                print(f"Failed to send push notification to user {user_id}")

        return success
    except Exception as e:
        print(f"Failed to process message: {e}")
        return False


async def consume_notifications(receiver: str, sender: str, mailgun_api_key=None, mailgun_domain=None, mailgun_email=None, twilio_account_sid=None, twilio_auth_token=None, twilio_phone_number=None):
    """Continuously fetch and process messages from the Redis queue."""
    try:
        print("\n-----------------------------------\nAbout to consume messages from Redis queue")

        topic_name = sanitize_topic_name(TOPIC_NAME)
        consumer = KafkaConsumer(
            topic_name,  # Your Kafka topic name
            bootstrap_servers='kafka:9092',  # Kafka broker address
            group_id='notification-group',
            auto_offset_reset='earliest',  # To consume from the beginning
            enable_auto_commit=False,
            api_version=(0, 10, 1)
        )
        messages = await read_from_queue(username=sender)

        for message in messages:
            if message:
                message = json.loads(message)
                notification_timestamp = message.get("timestamp", 0)
                current_time = time.time()

                if current_time - notification_timestamp <= int(REDIS_TIME_LIMIT):
                    process_status = await process_message(user_id=receiver, message_data=message, username=sender, mailgun_api_key=mailgun_api_key, mailgun_domain=mailgun_domain, mailgun_email=mailgun_email, twilio_account_sid=twilio_account_sid, twilio_auth_token=twilio_auth_token, twilio_phone_number=twilio_phone_number)
                    if process_status:
                        redis_data = await get_from_queue(username=sender)
                        consumer.commit()
                    else:
                        return {"success": False, "message": "unable to consume notifications."}
                else:
                    print(f"Deleting messages from Redis that are {REDIS_TIME_LIMIT} seconds old")
                    await delete_data_by_msg(user_id=receiver, msg=message)
            else:
                print("No messages to process, waiting...\n-----------------------------------\n")

        return {"success": True, "message": "notifications consumed"}
    except Exception as e:
        print(f"Failed to process message: {e}")
        return {"success": False, "message": f"Failed to consume notifications due to {e}"}

