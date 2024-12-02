from fastapi import APIRouter
from pingpongx.services.auth_service import signup, login

router = APIRouter()

router.add_api_route('/login', login, methods=["POST"])
router.add_api_route('/signup', signup, methods=["POST"])