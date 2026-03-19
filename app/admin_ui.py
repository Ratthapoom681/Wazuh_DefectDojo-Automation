from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .config import AppConfig, save_config


router = APIRouter()
ADMIN_HTML_PATH = Path(__file__).with_name("admin_assets") / "admin.html"

_get_config: Callable[[], AppConfig] | None = None
_reload_runtime_config: Callable[[AppConfig], None] | None = None
_get_dojo_options: Callable[[], dict[str, list[dict[str, Any]]]] | None = None


def configure_admin(
    get_config: Callable[[], AppConfig],
    reload_runtime_config: Callable[[AppConfig], None],
    get_dojo_options: Callable[[], dict[str, list[dict[str, Any]]]],
) -> None:
    global _get_config, _reload_runtime_config, _get_dojo_options
    _get_config = get_config
    _reload_runtime_config = reload_runtime_config
    _get_dojo_options = get_dojo_options


def _require_runtime() -> tuple[
    Callable[[], AppConfig],
    Callable[[AppConfig], None],
    Callable[[], dict[str, list[dict[str, Any]]]],
]:
    if _get_config is None or _reload_runtime_config is None or _get_dojo_options is None:
        raise RuntimeError("Admin UI runtime is not configured.")
    return _get_config, _reload_runtime_config, _get_dojo_options


@router.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return ADMIN_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/api/config")
async def admin_get_config():
    get_config, _, _ = _require_runtime()
    return JSONResponse(get_config().model_dump(mode="json"))


@router.post("/admin/api/config")
async def admin_save_config(request: Request):
    _, reload_runtime_config, _ = _require_runtime()
    payload = await request.json()
    try:
        new_config = AppConfig(**payload)
        save_config(new_config)
        reload_runtime_config(new_config)
        return JSONResponse({"status": "saved"})
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)


@router.get("/admin/api/dojo-options")
async def admin_dojo_options():
    _, _, get_dojo_options = _require_runtime()
    try:
        return JSONResponse(get_dojo_options())
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=502)
