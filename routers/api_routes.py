from fastapi import APIRouter
from . import system_routes
from . import account_routes
from . import service_routes
from . import sms_routes
try:
    from utils.auth_core import router as email_router
    from utils.auth_core import code_pool, cache_lock, generate_payload
except Exception:
    import threading

    email_router = APIRouter()
    code_pool = {}
    cache_lock = threading.Lock()

    def generate_payload(*_args, **_kwargs):
        return ""

router = APIRouter()

router.include_router(system_routes.router)
router.include_router(account_routes.router)
router.include_router(service_routes.router)
router.include_router(sms_routes.router)
router.include_router(email_router)
