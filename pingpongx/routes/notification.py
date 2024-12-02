from fastapi import APIRouter
from pingpongx.services.notification import notify

router = APIRouter()

router.add_api_route('/send', notify, methods=["POST"])

