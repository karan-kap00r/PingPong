from pingpongx.services.firestore_service import get_user_preferences, update_user_preferences


class UserPreferences:

    def __init__(self, user_id=None, email=True, sms=True):
        self.user_id = user_id
        self.preferences = {"sms": sms, "email": email}

    async def get_preferences(self):
        """Get user preferences for notifications."""
        if self.user_id.strip() == "":
            return {"success": False, "message": "Somthing wrong with User Id"}

        user_id = self.user_id.strip().lower()
        preferences = await get_user_preferences(user_id)
        if not preferences:
            return {"success": False, "message": "User preferences not found"}
        return preferences

    async def update_preferences(self):
        """Update user preferences for notifications."""

        if self.user_id.strip() == "":
            return {"success": False, "message": "Somthing wrong with User Id"}
        if self.preferences == {}:
            preferences = {"sms": True, "email": True}

        user_id = self.user_id.strip().lower()
        success = await update_user_preferences(user_id, self.preferences)
        if not success:
            return {"success": False, "message": "Failed to update preferences"}
        return {"success": True, "message": "Preferences updated successfully"}


async def get_preferences_service(user_id: str):
    """API to get user preferences for notifications."""
    service = UserPreferences(user_id)
    return await service.get_preferences()


async def update_preferences_service(user_id: str, preferences: dict):
    """API to update user preferences for notifications."""
    service = UserPreferences(user_id, email=preferences.get("email", True), sms=preferences.get("sms", True))
    return await service.update_preferences()
