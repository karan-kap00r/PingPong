from google.cloud import firestore
import datetime
import os

db = firestore.Client.from_service_account_json("firebase_credentials.json")
USER_PREFERENCE = os.environ.get("FIRESTORE_USER_PREFERENCE", "user_preferences")
NOTIFICATION = os.getenv("FIRESTORE_NOTIFICATION", "notifications")


async def get_user_preferences(user_id: str):
    """Retrieve user notification preferences from Firestore."""
    try:
        doc = db.collection(USER_PREFERENCE).document(user_id).get()
        if doc.exists:
            return doc.to_dict()
        else:
            return {
                "user_id": user_id,
                "preferences": {"email": True, "sms": True, "push": True},
                "last_updated": None
            }

    except Exception as e:
        print(f"Error retrieving user preferences: {e}")
        return None


async def save_notification_log(user_id: str, notification: dict):
    """Save a notification log to Firestore."""
    try:
        user_doc = db.collection(NOTIFICATION).document(user_id)
        if user_doc.get().exists:
            user_doc.update({"notifications": firestore.ArrayUnion([notification])})
        else:
            user_doc.set({
                "user_id": user_id,
                "notifications": [notification],
                "created_at": datetime.datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"Error saving notification log: {e}")


async def update_user_preferences(user_id, preferences):
    """Update the notification preferences for a user."""
    try:
        doc_ref = db.collection(USER_PREFERENCE).document(user_id)
        doc_ref.set({
            "user_id": user_id,
            "preferences": preferences,
            "last_updated": datetime.datetime.utcnow().isoformat()
        })
        print(f"Preferences updated for user {user_id}")
        return True
    except Exception as e:
        print(f"Error updating user preferences: {e}")
        return False


async def delete_user_preferences(user_id):
    """Delete the notification preferences for a user."""
    try:
        db.collection(USER_PREFERENCE).document(user_id).delete()
        print(f"Preferences deleted for user {user_id}")
        return True
    except Exception as e:
        print(f"Error deleting user preferences: {e}")
        return False
