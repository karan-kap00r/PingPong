from fastapi import APIRouter
from pingpongx.services import user_preferences

router = APIRouter()

router.add_api_route('/get/{user_id}', user_preferences.get_preferences, methods=["GET"])
router.add_api_route('/update/{user_id}', user_preferences.update_preferences, methods=["PUT"])
