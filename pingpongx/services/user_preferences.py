from pingpongx.services.firestore_service import get_user_preferences, update_user_preferences, delete_user_preferences


async def get_preferences(user_id: str):
    """Get user preferences for notifications."""
    if user_id.strip() == "":
        return {"success": False, "message": "Somthing wrong with User Id"}

    user_id = user_id.strip().lower()
    preferences = await get_user_preferences(user_id)
    if not preferences:
        return {"success": False, "message": "User preferences not found"}
    return preferences


async def update_preferences(user_id: str, preferences: dict):
    """Update user preferences for notifications."""

    if user_id.strip() == "":
        return {"success": False, "message": "Somthing wrong with User Id"}
    if preferences == {}:
        preferences = {"sms": True, "email": True}

    user_id = user_id.strip().lower()
    success = await update_user_preferences(user_id, preferences)
    if not success:
        return {"success": False, "message": "Failed to update preferences"}
    return {"success": True, "message": "Preferences updated successfully"}


async def delete_preferences(user_id: str):
    """Delete user preferences for notifications."""
    if user_id.strip() == "":
        return {"success": False, "message": "Somthing wrong with User Id"}

    user_id = user_id.strip().lower()
    success = await delete_user_preferences(user_id)
    if not success:
        return {"success": False, "message": "Failed to delete preferences"}
    return {"success": True, "message": "Preferences deleted successfully"}

