from fastapi import FastAPI
from starlette.templating import Jinja2Templates
from pingpongx.routes.notification import router as notification_router
from pingpongx.routes.user_preferences import router as preferences_router
from pingpongx.routes.auth_routes import router as auth_router

docs_config = {
    "openapi_url": None,
    "docs_url": None,
    "redoc_url": None
}

app = FastAPI(
    title="PingPong",
    version="v0.1",
    description="You can send mail & sms notifications across the world using PingPong.",
    contact={"name": "Karan Kapoor", "email": "pingpongreply02@gmail.com"},
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    **docs_config
    )

templates = Jinja2Templates(directory="py_pingpong/templates")


app.include_router(notification_router, prefix="/notifications")
app.include_router(preferences_router, prefix="/preferences")
app.include_router(auth_router, prefix="/auth")
