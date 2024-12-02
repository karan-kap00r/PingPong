import requests
import os

ONESIGNAL_APP_ID = os.getenv("ONESIGNAL_APP_ID")
ONESIGNAL_API_KEY = os.getenv("ONESIGNAL_API_KEY")


def send_push_notification(user_ids, title, message, data=None):
    """Sends push notifications using OneSignal."""
    url = "https://api.onesignal.com/notifications?c=push"

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Key {ONESIGNAL_API_KEY}"
    }

    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_player_ids": user_ids,
        "headings": {"en": title},
        "contents": {"en": message},
        "data": data or {}
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print(f"Push notification sent successfully: {response.json()}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending push notification: {e}")
        return None
