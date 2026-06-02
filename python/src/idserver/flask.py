"""Flask integration for IdServer.

Install with the ``flask`` extra::

    pip install "idserver-client[flask]"

Basic usage::

    from flask import Flask
    from idserver import IdServerClient
    from idserver.flask import IdServerAuth, login_required, role_required

    app = Flask(__name__)
    app.secret_key = "change-me"  # required for session storage

    idserver = IdServerClient(
        authority="https://mytenant.signward.com",
        client_id="my-webapp",
        client_secret="...",
    )
    auth = IdServerAuth(idserver, post_login_redirect="/")
    app.register_blueprint(auth.blueprint, url_prefix="/auth")

    @app.route("/")
    def home():
        return "Hello!"

    @app.route("/profile")
    @login_required
    def profile():
        user = auth.current_user()
        return f"Hi {user.email}"

    @app.route("/admin")
    @role_required("admin")
    def admin():
        return "Admin area"
"""

from __future__ import annotations

import asyncio
from functools import wraps
from typing import Any, Callable
from urllib.parse import urljoin

try:
    from flask import Blueprint, abort, current_app, redirect, request, session, url_for
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Flask is not installed. Install it with: pip install 'idserver-client[flask]'"
    ) from exc

from idserver.client import IdServerClient
from idserver.exceptions import IdServerError
from idserver.models import User

_SESSION_KEY = "_idserver"
"""Session key under which tokens + user claims are stored."""


def _run(coro: Any) -> Any:
    """Run an async coroutine in a sync context."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Already inside a running loop (e.g. async Flask) — create a nested one
    return asyncio.get_event_loop().run_until_complete(coro)


class IdServerAuth:
    """Flask helper providing a login/logout/callback Blueprint and session glue.

    The Blueprint exposes three routes (names are relative to the prefix you
    register it under):

    - ``GET  /login``    — start the OIDC flow (redirects to the authorize endpoint)
    - ``GET  /callback`` — handle the authorize code, exchange for tokens, store in session
    - ``GET  /logout``   — clear the session and redirect to the IdServer end_session endpoint
    """

    def __init__(
        self,
        client: IdServerClient,
        *,
        post_login_redirect: str = "/",
        post_logout_redirect: str | None = None,
        blueprint_name: str = "idserver",
        login_endpoint: str = "login",
        logout_endpoint: str = "logout",
        callback_endpoint: str = "callback",
    ):
        self.client = client
        self.post_login_redirect = post_login_redirect
        self.post_logout_redirect = post_logout_redirect
        self.login_endpoint_name = login_endpoint
        self.logout_endpoint_name = logout_endpoint
        self.callback_endpoint_name = callback_endpoint

        bp = Blueprint(blueprint_name, __name__)
        bp.add_url_rule(f"/{login_endpoint}", view_func=self._login_view, endpoint=login_endpoint)
        bp.add_url_rule(f"/{callback_endpoint}", view_func=self._callback_view, endpoint=callback_endpoint)
        bp.add_url_rule(f"/{logout_endpoint}", view_func=self._logout_view, endpoint=logout_endpoint)
        self.blueprint = bp

    # --- Session helpers ------------------------------------------------------

    @staticmethod
    def _get_state() -> dict[str, Any] | None:
        return session.get(_SESSION_KEY)

    def current_user(self) -> User | None:
        """Return the authenticated user from the session, or ``None``."""
        state = self._get_state()
        if not state or "claims" not in state:
            return None
        return User.from_claims(state["claims"])

    def is_authenticated(self) -> bool:
        return self._get_state() is not None

    def access_token(self) -> str | None:
        state = self._get_state()
        return state.get("access_token") if state else None

    def refresh_token_value(self) -> str | None:
        state = self._get_state()
        return state.get("refresh_token") if state else None

    def id_token(self) -> str | None:
        state = self._get_state()
        return state.get("id_token") if state else None

    # --- Views ----------------------------------------------------------------

    def _callback_url(self) -> str:
        return urljoin(request.host_url, url_for(f"{self.blueprint.name}.{self.callback_endpoint_name}"))

    def _login_view(self):
        return_to = request.args.get("returnTo") or self.post_login_redirect
        url, verifier = self.client.authorize_url_with_pkce(
            redirect_uri=self._callback_url(),
            state=return_to,
        )
        session["_idserver_pkce"] = verifier
        session["_idserver_state"] = return_to
        return redirect(url)

    def _callback_view(self):
        code = request.args.get("code")
        if not code:
            error = request.args.get("error", "missing_code")
            abort(400, description=f"OIDC callback error: {error}")

        state = request.args.get("state")
        expected_state = session.pop("_idserver_state", None)
        if expected_state is not None and state != expected_state:
            abort(400, description="OIDC state mismatch")

        verifier = session.pop("_idserver_pkce", None)

        try:
            tokens = _run(self.client.exchange_code(
                code,
                redirect_uri=self._callback_url(),
                code_verifier=verifier,
            ))
            user = _run(self.client.validate_token(tokens.access_token))
        except IdServerError as exc:
            current_app.logger.warning("IdServer login failed: %s", exc)
            abort(400, description=f"Login failed: {exc}")

        session[_SESSION_KEY] = {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "id_token": tokens.id_token,
            "claims": user.claims,
        }

        return redirect(state or self.post_login_redirect)

    def _logout_view(self):
        id_token_hint = self.id_token()
        session.pop(_SESSION_KEY, None)

        post_logout = self.post_logout_redirect or urljoin(request.host_url, "/")
        try:
            url = _run(self.client.end_session_url(
                id_token_hint=id_token_hint,
                post_logout_redirect_uri=post_logout,
            ))
        except IdServerError:
            # Fall back to local logout if discovery fails
            return redirect(post_logout)
        return redirect(url)


# --- Decorators ---------------------------------------------------------------


def _get_auth() -> IdServerAuth:
    auth = current_app.extensions.get("idserver_auth") if hasattr(current_app, "extensions") else None
    if auth is None:
        raise RuntimeError(
            "IdServerAuth not registered. Call `auth.init_app(app)` or set "
            "`app.extensions['idserver_auth'] = auth`."
        )
    return auth


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    """Require an authenticated session. Redirects to the login endpoint otherwise."""

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):
        state = session.get(_SESSION_KEY)
        if state is None:
            auth = _get_auth()
            return redirect(url_for(
                f"{auth.blueprint.name}.{auth.login_endpoint_name}",
                returnTo=request.path,
            ))
        return view(*args, **kwargs)

    return wrapper


def role_required(
    *roles: str,
    require_all: bool = False,
    include_custom: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Require the authenticated user to have specific roles. 403 otherwise."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any):
            state = session.get(_SESSION_KEY)
            if state is None:
                auth = _get_auth()
                return redirect(url_for(
                    f"{auth.blueprint.name}.{auth.login_endpoint_name}",
                    returnTo=request.path,
                ))
            user = User.from_claims(state.get("claims", {}))
            check = user.has_all_roles if require_all else user.has_any_role
            if not check(*roles, include_custom=include_custom):
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def init_app(app: Any, auth: IdServerAuth) -> None:
    """Register an :class:`IdServerAuth` instance on the Flask app so the
    ``login_required`` / ``role_required`` decorators can look it up."""
    if not hasattr(app, "extensions") or app.extensions is None:
        app.extensions = {}
    app.extensions["idserver_auth"] = auth
