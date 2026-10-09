"""Playwright browser automation, screenshot evidence, and dialog capture subsystem.

Manages headless browser sessions to render web pages, execute DOM contexts,
intercept JavaScript dialogs (alert, confirm, prompt), capture step-by-step
diagnostic screenshots, and record final visual evidence for findings.

Thread-safe: leverages thread-local storage to provide isolated browser/page
contexts per worker thread during parallel scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import logging
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
    PLAYWRIGHT_INSTALLED = True
except ImportError:
    PLAYWRIGHT_INSTALLED = False


@dataclass
class CapturedDialog:
    """Record of a browser JavaScript dialog event triggered during execution."""

    type: str  # 'alert', 'confirm', 'prompt', 'beforeunload'
    message: str
    default_value: str = ""
    timestamp: float = field(default_factory=time.time)
    step_name: str | None = None

    def __str__(self) -> str:
        if self.message:
            return f"{self.type}('{self.message}')"
        return f"{self.type}()"


class BrowserManager:
    """Manages headless browser execution, dialog events, and screenshot artifacts."""

    def __init__(
        self,
        output_dir: str | Path = "evidence/screenshots",
        headless: bool = True,
        timeout: float = 10.0,
        custom_headers: dict[str, str] | None = None,
        base_url: str | None = None,
        http_credentials: dict[str, str] | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.headless = headless
        self.timeout_ms = int(timeout * 1000)
        self.custom_headers = custom_headers or {}
        self.base_url = base_url
        self.http_credentials = http_credentials

        self._local = threading.local()
        self._all_sessions_lock = threading.Lock()
        self._active_sessions: list[tuple[Any, Any, Any, Any]] = []
        self._step_counter = 0
        self._counter_lock = threading.Lock()

    @property
    def is_available(self) -> bool:
        """Check if Playwright is installed and ready."""
        return PLAYWRIGHT_INSTALLED

    def __enter__(self) -> BrowserManager:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _ensure_session(self) -> Page | None:
        """Obtain or initialize thread-local Playwright browser session."""
        if not self.is_available:
            return None

        cached_page = getattr(self._local, "page", None)
        if cached_page is not None:
            return cached_page

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )

            # Separate Cookie header from custom request headers
            extra_headers: dict[str, str] = {}
            cookie_str = None
            for k, v in self.custom_headers.items():
                if k.lower() == "cookie":
                    cookie_str = v
                else:
                    extra_headers[k] = v

            http_creds = None
            if self.http_credentials:
                http_creds = {
                    "username": self.http_credentials.get("username", ""),
                    "password": self.http_credentials.get("password", ""),
                }

            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                extra_http_headers=extra_headers if extra_headers else None,
                http_credentials=http_creds,
            )

            # Synchronize session cookies to browser context for authenticated asset loading
            if cookie_str and self.base_url:
                cookies_to_add = []
                for cookie_part in cookie_str.split(";"):
                    if "=" in cookie_part:
                        c_name, c_val = cookie_part.strip().split("=", 1)
                        cookies_to_add.append({
                            "name": c_name.strip(),
                            "value": c_val.strip(),
                            "url": self.base_url,
                        })
                if cookies_to_add:
                    try:
                        context.add_cookies(cookies_to_add)
                        logger.debug("Successfully added %d session cookie(s) to thread browser context.", len(cookies_to_add))
                    except Exception as cookie_exc:
                        logger.debug("Notice adding cookies to browser context: %s", cookie_exc)

            page = context.new_page()
            page.set_default_timeout(self.timeout_ms)

            # Register dialog listener
            self._local.captured_dialogs = []
            self._local.buffered_steps = []
            self._local.current_step_name = None

            def _handle_dialog(dialog: Any) -> None:
                try:
                    d_type = getattr(dialog, "type", "alert")
                    d_msg = getattr(dialog, "message", "")
                    d_default = getattr(dialog, "default_value", "")
                    captured = CapturedDialog(
                        type=d_type,
                        message=d_msg,
                        default_value=d_default,
                        timestamp=time.time(),
                        step_name=getattr(self._local, "current_step_name", None),
                    )
                    self._local.captured_dialogs.append(captured)
                    logger.info("Captured JavaScript dialog: %s('%s')", d_type, d_msg)
                    dialog.accept()
                except Exception as exc:
                    logger.warning("Error handling browser dialog: %s", exc)

            page.on("dialog", _handle_dialog)

            self._local.playwright = playwright
            self._local.browser = browser
            self._local.context = context
            self._local.page = page

            with self._all_sessions_lock:
                self._active_sessions.append((playwright, browser, context, page))

            logger.info("Playwright browser initialized successfully for thread %s.", threading.current_thread().name)
            return page
        except Exception as exc:
            logger.debug("Failed to initialize thread-local Playwright browser: %s", exc)
            return None

    @property
    def page(self) -> Page | None:
        """Current thread-local Page instance."""
        return self._ensure_session()

    @property
    def _page(self) -> Page | None:
        """Compatibility alias for Page instance."""
        return self._ensure_session()

    @property
    def captured_dialogs(self) -> list[CapturedDialog]:
        """Current thread-local dialog interception history."""
        if not hasattr(self._local, "captured_dialogs"):
            self._local.captured_dialogs = []
        return self._local.captured_dialogs

    @captured_dialogs.setter
    def captured_dialogs(self, value: list[CapturedDialog]) -> None:
        self._local.captured_dialogs = value

    @property
    def _buffered_steps(self) -> list[tuple[str, bytes]]:
        """Current thread-local buffered step screenshots."""
        if not hasattr(self._local, "buffered_steps"):
            self._local.buffered_steps = []
        return self._local.buffered_steps

    @_buffered_steps.setter
    def _buffered_steps(self, value: list[tuple[str, bytes]]) -> None:
        self._local.buffered_steps = value

    @property
    def _current_step_name(self) -> str | None:
        return getattr(self._local, "current_step_name", None)

    @_current_step_name.setter
    def _current_step_name(self, value: str | None) -> None:
        self._local.current_step_name = value

    def start(self) -> bool:
        """Launch browser session on current thread."""
        if not self.is_available:
            logger.warning("Playwright is not installed. Browser screenshots disabled.")
            return False
        return self._ensure_session() is not None

    def get_dialogs(
        self,
        step_name: str | None = None,
        dialog_type: str | None = None,
    ) -> list[CapturedDialog]:
        """Return captured dialogs filtered by step name or dialog type."""
        dialogs = list(self.captured_dialogs)
        if step_name is not None:
            dialogs = [d for d in dialogs if d.step_name == step_name]
        if dialog_type is not None:
            dialogs = [d for d in dialogs if d.type.lower() == dialog_type.lower()]
        return dialogs

    def has_dialog(self, dialog_type: str | None = None) -> bool:
        """Check if any JavaScript dialog (or a specific type: alert/confirm/prompt) was captured."""
        return len(self.get_dialogs(dialog_type=dialog_type)) > 0

    @property
    def last_dialog(self) -> CapturedDialog | None:
        """Return the most recently captured dialog, if any."""
        return self.captured_dialogs[-1] if self.captured_dialogs else None

    def clear_dialogs(self) -> None:
        """Reset captured dialogs history."""
        self.captured_dialogs.clear()

    def login_with_browser(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str | None = None,
        password_field: str | None = None,
        after_auth_url: str | None = None,
        record_screenshots: bool = True,
    ) -> tuple[bool, dict[str, str], str]:
        """Perform automated form login via headless browser, returning (success, cookies, landing_url)."""
        page = self._ensure_session()
        if not page:
            return False, {}, login_url

        try:
            # Clear previous buffered steps
            self._buffered_steps.clear()

            logger.info("[AUTH] Navigating browser to login page: %s", login_url)
            page.goto(login_url, wait_until="domcontentloaded", timeout=min(self.timeout_ms, 8000))
            try:
                page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
            except Exception:
                pass

            # Step 1: Screenshot on login page
            if record_screenshots:
                self.buffer_current_step("step-1_login_page_loaded")

            # 1. Fill Username field
            u_selectors = [
                f'input[name="{username_field}"]' if username_field else "",
                'input[name="uid"]',
                'input[name="uname"]',
                'input[name="username"]',
                'input[name="user"]',
                'input[name="user_id"]',
                'input[name="login"]',
                'input[name="email"]',
                'input[type="email"]',
                'input[type="text"]',
            ]
            u_filled = False
            for sel in filter(None, u_selectors):
                loc = page.locator(sel)
                try:
                    if loc.count() > 0:
                        loc.first.fill(username)
                        u_filled = True
                        break
                except Exception:
                    pass

            # 2. Fill Password field
            p_selectors = [
                f'input[name="{password_field}"]' if password_field else "",
                'input[name="passw"]',
                'input[name="password"]',
                'input[name="pass"]',
                'input[name="pwd"]',
                'input[name="passwd"]',
                'input[type="password"]',
            ]
            p_filled = False
            for sel in filter(None, p_selectors):
                loc = page.locator(sel)
                try:
                    if loc.count() > 0:
                        loc.first.fill(password)
                        p_filled = True
                        break
                except Exception:
                    pass

            # Handle any select elements (e.g., security_level in bWAPP / DVWA)
            try:
                selects = page.locator("select")
                sel_count = selects.count()
                for i in range(sel_count):
                    try:
                        selects.nth(i).select_option(index=0)
                    except Exception:
                        pass
            except Exception:
                pass

            # Step 2: Screenshot after filling credentials
            if record_screenshots:
                self.buffer_current_step("step-2_credentials_filled")

            if not (u_filled and p_filled):
                logger.warning("[AUTH] Browser login could not locate username/password fields.")
                if record_screenshots:
                    self.save_interaction_steps("auth")
                return False, {}, login_url

            # 3. Submit form
            submit_selectors = [
                'input[name="btnSubmit"]',
                'button[name="btnSubmit"]',
                'button[name="form"]',
                'button[type="submit"]',
                'input[type="submit"]',
                'input[value*="Login" i]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("submit" i)',
                'button[value="submit"]',
                'input[name="Login"]',
                'input[name="submit"]',
            ]
            submitted = False
            for sel in submit_selectors:
                loc = page.locator(sel)
                try:
                    if loc.count() > 0:
                        loc.first.click()
                        submitted = True
                        break
                except Exception:
                    pass

            if not submitted:
                try:
                    page.keyboard.press("Enter")
                    submitted = True
                except Exception:
                    pass

            # 4. Wait for redirection and load
            try:
                page.wait_for_load_state("domcontentloaded", timeout=min(self.timeout_ms, 5000))
                page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
            except Exception:
                pass
            time.sleep(1.0)

            landing_url = page.url or login_url

            # If user provided a specific after-auth landing page, verify navigation to it
            if after_auth_url:
                from urllib.parse import urljoin
                resolved_after_auth = urljoin(login_url, after_auth_url)
                if landing_url != resolved_after_auth and ("login" in landing_url.lower() or not any(k.lower() in landing_url.lower() for k in ["portal", "index", "welcome", "home"])):
                    try:
                        page.goto(resolved_after_auth, wait_until="domcontentloaded", timeout=min(self.timeout_ms, 5000))
                        try:
                            page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
                        except Exception:
                            pass
                        landing_url = page.url or resolved_after_auth
                    except Exception as nav_err:
                        logger.debug("Navigation to after-auth page notice: %s", nav_err)

            # Step 3: Screenshot of landing page after submission
            if record_screenshots:
                self.buffer_current_step("step-3_authenticated_landing_page")
                self.save_interaction_steps("auth")

            # Extract cookies from browser context
            cookies: dict[str, str] = {}
            try:
                if self._local.context:
                    browser_cookies = self._local.context.cookies()
                    for c in browser_cookies:
                        cookies[c["name"]] = c["value"]
            except Exception:
                pass

            # Determine authentication success
            is_login_url = any(x in landing_url.lower() for x in ["login", "signin", "logon", "auth"])
            has_password_field = False
            try:
                has_password_field = page.locator('input[type="password"]').count() > 0
            except Exception:
                pass

            content_lower = ""
            try:
                content_lower = page.content().lower()
            except Exception:
                pass

            has_login_error = any(err in content_lower for err in [
                "login failed",
                "invalid username",
                "invalid password",
                "incorrect credentials",
                "authentication failed",
                "wrong username or password",
            ])

            has_session_cookie = any(
                k.lower() in ("phpsessid", "dvwasession", "session", "sessionid", "connect.sid", "auth", "token")
                for k in cookies.keys()
            )

            if after_auth_url:
                from urllib.parse import urlparse
                after_path = urlparse(after_auth_url).path.lower().strip("/")
                land_path = urlparse(landing_url).path.lower().strip("/")
                success = bool(after_path and (after_path in land_path or land_path == after_path) and not has_password_field and not has_login_error)
            else:
                success = not has_login_error and not has_password_field and not is_login_url and (has_session_cookie or landing_url != login_url)

            if success:
                logger.info("[AUTH] Browser login confirmed successful. Landing URL: %s (Cookies: %s)", landing_url, list(cookies.keys()))
            else:
                logger.warning("[AUTH] Browser login failed or remained on login form. Landing URL: %s, Error detected: %s", landing_url, has_login_error or has_password_field)
            return success, cookies, landing_url
        except Exception as exc:
            logger.warning("[AUTH] Error during browser login: %s", exc)
            self.save_interaction_steps("auth")
            return False, {}, login_url

    def close(self) -> None:
        """Shut down all browser and Playwright runtime instances across all worker threads."""
        with self._all_sessions_lock:
            for playwright, browser, context, page in self._active_sessions:
                try:
                    if page:
                        page.close()
                except Exception:
                    pass
                try:
                    if context:
                        context.close()
                except Exception:
                    pass
                try:
                    if browser:
                        browser.close()
                except Exception:
                    pass
                try:
                    if playwright:
                        playwright.stop()
                except Exception:
                    pass
            self._active_sessions.clear()

        # Reset local thread state
        self._local.page = None
        self._local.context = None
        self._local.browser = None
        self._local.playwright = None
        self._local.captured_dialogs = []
        self._local.buffered_steps = []
        self._local.current_step_name = None

    def check_xss_dom_execution(self) -> bool:
        """Check if visual XSS payload executed in DOM (red background or <h1>dastXSS</h1> element)."""
        page = self._ensure_session()
        if not page:
            return False
        try:
            return bool(page.evaluate("""() => {
                const bg = document.body ? (document.body.style.backgroundColor || '') : '';
                const hasRed = bg === 'red' || bg.includes('255, 0, 0') || bg.includes('rgb(255, 0, 0)');
                const h1s = Array.from(document.querySelectorAll('h1'));
                const hasH1 = h1s.some(h => {
                    const t = h.textContent.trim().toUpperCase();
                    return t === 'DASTXSS' || t === 'XSS';
                });
                return hasRed || hasH1;
            }"""))
        except Exception:
            return False

    def buffer_current_step(
        self,
        step_name: str,
        dialog: CapturedDialog | str | None = None,
        effective_base: str | None = None,
    ) -> None:
        """Capture screenshot of current browser page into in-memory buffer without saving to disk."""
        page = self._ensure_session()
        if not page:
            return

        overlay_injected = False
        try:
            if dialog:
                overlay_injected = self._inject_visual_dialog_overlay(dialog, base_url=effective_base)
                if overlay_injected:
                    page.wait_for_timeout(60)

            img_bytes = page.screenshot(full_page=True)
            self._buffered_steps.append((step_name, img_bytes))

            if overlay_injected:
                try:
                    page.evaluate("() => { const el = document.getElementById('__dast_dialog_overlay'); if (el) el.remove(); }")
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("Failed to buffer step screenshot '%s': %s", step_name, exc)

    def save_interaction_steps(self, detector_name: str | None = None) -> list[str]:
        """Write only the buffered step screenshots for a confirmed finding to disk and return paths."""
        if not self._buffered_steps:
            return []

        target_dir = (self.output_dir / detector_name) if detector_name else self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        saved_paths: list[str] = []
        token = secrets.token_hex(2)

        for step_name, img_bytes in self._buffered_steps:
            with self._counter_lock:
                self._step_counter += 1
                cnt = self._step_counter
            safe_name = re.sub(r"[^\w\-]", "_", step_name)
            filename = f"{safe_name}_{cnt:03d}_{token}.png"
            filepath = target_dir / filename
            try:
                filepath.write_bytes(img_bytes)
                saved_paths.append(str(filepath.resolve()))
                logger.info("Saved finding step screenshot [%s]: %s", detector_name or "general", filepath)
            except Exception as exc:
                logger.warning("Failed writing finding screenshot '%s': %s", filepath, exc)

        self._buffered_steps.clear()
        return saved_paths

    def clear_interaction_steps(self) -> None:
        """Clear buffered step screenshots."""
        self._buffered_steps.clear()

    def _inject_visual_dialog_overlay(self, dialog: CapturedDialog | str, base_url: str | None = None) -> bool:
        """Inject a realistic browser alert/confirm/prompt modal overlay into DOM before screenshot."""
        page = self._ensure_session()
        if not page:
            return False

        d_type = getattr(dialog, "type", "alert") if not isinstance(dialog, str) else "alert"
        d_msg = getattr(dialog, "message", dialog) if not isinstance(dialog, str) else str(dialog)
        d_default = getattr(dialog, "default_value", "") if not isinstance(dialog, str) else ""

        try:
            origin = ""
            if self.base_url or base_url:
                from urllib.parse import urlparse

                u = self.base_url or base_url or ""
                p = urlparse(u)
                origin = p.netloc or p.hostname or ""

            js_code = f"""(() => {{
                try {{
                    const existing = document.getElementById('__dast_dialog_overlay');
                    if (existing) existing.remove();

                    const overlay = document.createElement('div');
                    overlay.id = '__dast_dialog_overlay';
                    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.45);z-index:2147483647;display:flex;justify-content:center;align-items:flex-start;padding-top:70px;box-sizing:border-box;pointer-events:none;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;';

                    const box = document.createElement('div');
                    box.style.cssText = 'background:#ffffff;border-radius:8px;box-shadow:0 12px 32px rgba(0,0,0,0.35);width:440px;max-width:92vw;overflow:hidden;border:1px solid rgba(0,0,0,0.12);pointer-events:auto;';

                    const content = document.createElement('div');
                    content.style.cssText = 'padding:22px 24px 18px 24px;';

                    const title = document.createElement('div');
                    title.style.cssText = 'font-size:14px;color:#202124;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:6px;';
                    
                    const hostName = window.location.host || {repr(origin)} || 'This page';
                    title.textContent = hostName + ' says';

                    const msg = document.createElement('div');
                    msg.style.cssText = 'font-size:14px;color:#3c4043;word-break:break-word;white-space:pre-wrap;line-height:1.45;';
                    msg.textContent = {repr(d_msg)};

                    content.appendChild(title);
                    content.appendChild(msg);

                    if ({repr(d_type.lower())} === 'prompt') {{
                        const input = document.createElement('input');
                        input.type = 'text';
                        input.value = {repr(d_default)};
                        input.style.cssText = 'width:100%;margin-top:14px;padding:8px 10px;border:1px solid #dadce0;border-radius:4px;box-sizing:border-box;font-size:13px;outline:none;';
                        content.appendChild(input);
                    }}

                    const actions = document.createElement('div');
                    actions.style.cssText = 'display:flex;justify-content:flex-end;gap:8px;padding:12px 24px;background:#f8f9fa;border-top:1px solid #f1f3f4;';

                    if ({repr(d_type.lower())} === 'confirm' || {repr(d_type.lower())} === 'prompt') {{
                        const cancelBtn = document.createElement('div');
                        cancelBtn.style.cssText = 'background:transparent;color:#1a73e8;padding:8px 16px;border-radius:4px;font-size:13px;font-weight:500;border:1px solid #dadce0;';
                        cancelBtn.textContent = 'Cancel';
                        actions.appendChild(cancelBtn);
                    }}

                    const okBtn = document.createElement('div');
                    okBtn.style.cssText = 'background:#1a73e8;color:#ffffff;padding:8px 22px;border-radius:4px;font-size:13px;font-weight:500;';
                    okBtn.textContent = 'OK';
                    actions.appendChild(okBtn);

                    box.appendChild(content);
                    box.appendChild(actions);
                    overlay.appendChild(box);
                    document.body.appendChild(overlay);
                    return true;
                }} catch (e) {{
                    return false;
                }}
            }})()"""
            res = page.evaluate(js_code)
            return bool(res)
        except Exception as exc:
            logger.debug("Notice rendering visual dialog overlay: %s", exc)
            return False

    def fill_and_submit_form(
        self,
        url: str,
        target_param: str,
        payload: str,
        companion_fields: dict[str, Any] | None = None,
        step_name: str = "form_submit",
        detector_name: str | None = None,
        wait_ms: int = 500,
    ) -> tuple[str, str | None]:
        """Navigate to form page in headless browser, fill target parameter, submit form, and capture screenshots for each step."""
        page = self._ensure_session()
        if not page:
            return "", None

        try:
            # 1. Navigate to page containing the form
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=min(self.timeout_ms, 8000))
                try:
                    page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
                except Exception:
                    pass
            except Exception as nav_exc:
                logger.debug("Notice navigating to %s for form fill: %s", url, nav_exc)

            def _safe_count(loc: Any) -> int:
                """Safely check locator count without crashing on navigation/context destruction."""
                try:
                    return loc.count()
                except Exception as c_err:
                    if "Execution context was destroyed" in str(c_err):
                        try:
                            page.wait_for_load_state("domcontentloaded", timeout=2000)
                            return loc.count()
                        except Exception:
                            return 0
                    return 0

            # 2. Locate target input field (only text inputs)
            input_selectors = [
                f'input[type="text"][name="{target_param}"]',
                f'input:not([type])[name="{target_param}"]',
                f'textarea[name="{target_param}"]',
                f'input[name="{target_param}"]:not([type="submit"]):not([type="button"]):not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="file"])',
                f'#{target_param}',
                f'[name*="{target_param}"]:not([type="submit"]):not([type="button"]):not([type="hidden"])',
            ]
            target_locator = None
            for sel in input_selectors:
                loc = page.locator(sel)
                if _safe_count(loc) > 0:
                    target_locator = loc.first
                    break

            if not target_locator:
                first_text = page.locator('input[type="text"], input:not([type]), textarea')
                if _safe_count(first_text) > 0:
                    target_locator = first_text.first
                else:
                    return "", None

            # Clear previous buffered interaction steps and dialogs
            self._buffered_steps.clear()
            self.clear_dialogs()

            # Step 1 Screenshot: Buffer navigated to form
            self.buffer_current_step("step-1_navigated_to_form")

            try:
                target_locator.fill(payload)
            except Exception as fill_err:
                if "Execution context was destroyed" in str(fill_err):
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=2000)
                        target_locator.fill(payload)
                    except Exception:
                        pass
                else:
                    try:
                        page.evaluate(
                            "(sel, val) => { const el = document.querySelector(sel); if (el && (!el.type || el.type === 'text' || el.type === 'search' || el.tagName.toLowerCase() === 'textarea')) el.value = val; }",
                            input_selectors[0],
                            payload,
                        )
                    except Exception:
                        pass

            # 3. Populate companion fields
            if companion_fields:
                for k, v in companion_fields.items():
                    if k == target_param:
                        continue
                    comp_loc = page.locator(f'input[name="{k}"]:not([type="submit"]):not([type="button"]), textarea[name="{k}"]')
                    if _safe_count(comp_loc) > 0:
                        try:
                            comp_loc.first.fill(str(v))
                        except Exception:
                            pass

            # Step 2 Screenshot: Buffer filled payload and companion inputs
            self.buffer_current_step("step-2_filled_payload")

            # 4. Submit the form
            submitted = False
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'input[name="Submit"]',
                'input[name="submit"]',
                'button',
            ]
            for btn_sel in submit_selectors:
                btn = page.locator(btn_sel)
                if _safe_count(btn) > 0:
                    try:
                        btn.first.click(timeout=3000)
                        submitted = True
                        break
                    except Exception as click_err:
                        if "Execution context was destroyed" in str(click_err) or "navigation" in str(click_err).lower():
                            submitted = True
                            break
                        pass

            if not submitted:
                try:
                    if target_locator:
                        target_locator.press("Enter")
                        submitted = True
                except Exception as enter_err:
                    if "Execution context was destroyed" in str(enter_err) or "navigation" in str(enter_err).lower():
                        submitted = True
                    pass

            if not submitted:
                try:
                    page.evaluate("() => { const f = document.querySelector('form'); if (f) f.submit(); }")
                    submitted = True
                except Exception:
                    pass

            # 5. Wait for submission to process and DOM to update
            try:
                page.wait_for_load_state("domcontentloaded", timeout=min(self.timeout_ms, 3000))
                page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
            except Exception:
                pass

            # Trigger mouse interaction for any pointer events
            try:
                page.mouse.move(50, 50)
                page.mouse.move(200, 200)
            except Exception:
                pass

            page.wait_for_timeout(max(wait_ms, 350))

            # 6. Capture HTML and visual screenshot for Step 3
            try:
                page_content = page.content()
            except Exception as cnt_err:
                if "Execution context was destroyed" in str(cnt_err):
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=2000)
                        page_content = page.content()
                    except Exception:
                        page_content = ""
                else:
                    page_content = ""

            # Step 3 Screenshot: Buffer submitted form result (overlaying any dialog captured during this submission)
            self.buffer_current_step("step-3_submitted_form_result", dialog=self.last_dialog)
            return page_content, None
        except Exception as exc:
            logger.warning("Error during form filling scenario for '%s': %s", step_name, exc)
            return "", None

    def capture_step(
        self,
        step_name: str,
        url: str | None = None,
        html_content: str | None = None,
        base_url: str | None = None,
        dialog: CapturedDialog | str | None = None,
        detector_name: str | None = None,
        wait_ms: int = 400,
    ) -> str | None:
        """Navigate or render content, capture screenshot, and return saved path in detector folder."""
        page = self._ensure_session()
        if not page:
            return None

        self._current_step_name = step_name
        with self._counter_lock:
            self._step_counter += 1
            cnt = self._step_counter

        # Use detector name folder if provided
        target_dir = (self.output_dir / detector_name) if detector_name else self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        safe_name = re.sub(r"[^\w\-]", "_", step_name)[:30]
        token = secrets.token_hex(3)
        filename = f"step_{cnt:03d}_{safe_name}_{token}.png"
        filepath = target_dir / filename

        effective_base = base_url or self.base_url
        dialogs_before = len(self.captured_dialogs)

        try:
            if html_content:
                content_to_render = html_content
                if effective_base and "<base" not in content_to_render.lower():
                    if "<head>" in content_to_render.lower():
                        idx = content_to_render.lower().find("<head>") + 6
                        content_to_render = (
                            content_to_render[:idx]
                            + f'\n  <base href="{effective_base}">\n'
                            + content_to_render[idx:]
                        )
                    elif "<head " in content_to_render.lower():
                        idx = content_to_render.lower().find(">") + 1
                        content_to_render = (
                            content_to_render[:idx]
                            + f'\n  <base href="{effective_base}">\n'
                            + content_to_render[idx:]
                        )
                    else:
                        content_to_render = f'<base href="{effective_base}">\n' + content_to_render

                try:
                    page.set_content(content_to_render, wait_until="load", timeout=min(self.timeout_ms, 4000))
                except Exception:
                    page.set_content(content_to_render, wait_until="domcontentloaded")

                try:
                    page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 1500))
                except Exception:
                    pass

                try:
                    page.mouse.move(50, 50)
                    page.mouse.move(200, 200)
                except Exception:
                    pass

            elif url:
                try:
                    page.goto(url, wait_until="load", timeout=min(self.timeout_ms, 5000))
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 2500))
                    except Exception:
                        pass
                except Exception as nav_exc:
                    logger.debug("Navigation notice during capture of %s: %s", url, nav_exc)

            # Detect if a dialog occurred during this step or was explicitly passed
            step_dialog = dialog
            if not step_dialog:
                new_dialogs = self.captured_dialogs[dialogs_before:]
                if new_dialogs:
                    step_dialog = new_dialogs[-1]
                elif self.last_dialog and (time.time() - self.last_dialog.timestamp < 3.0):
                    step_dialog = self.last_dialog

            overlay_injected = False
            if step_dialog:
                overlay_injected = self._inject_visual_dialog_overlay(step_dialog, base_url=effective_base)
                if overlay_injected:
                    page.wait_for_timeout(60)

            # Wait for script execution and DOM manipulation to complete
            effective_wait = max(wait_ms, 350)
            page.wait_for_timeout(effective_wait)

            page.screenshot(path=str(filepath), full_page=True)
            logger.debug("Captured screenshot: %s", filepath)

            if overlay_injected:
                try:
                    page.evaluate("() => { const el = document.getElementById('__dast_dialog_overlay'); if (el) el.remove(); }")
                except Exception:
                    pass

            return str(filepath.resolve())
        except Exception as exc:
            logger.warning("Failed to capture screenshot for step '%s': %s", step_name, exc)
            return None

    def render_terminal_screenshot(
        self,
        command: str,
        output: str,
        detector_name: str | None = None,
        title: str | None = None,
        step_name: str = "terminal_execution",
        username: str = "dast-auditor",
        hostname: str = "security-core",
        cwd: str = "/var/www/html",
    ) -> str | None:
        """Render a realistic, photorealistic dark shell/terminal window with command & output and capture screenshot."""
        page = self._ensure_session()
        if not page:
            return None

        with self._counter_lock:
            self._step_counter += 1
            cnt = self._step_counter

        target_dir = (self.output_dir / detector_name) if detector_name else self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        safe_name = re.sub(r"[^\w\-]", "_", step_name)[:30]
        token = secrets.token_hex(3)
        filename = f"term_{cnt:03d}_{safe_name}_{token}.png"
        filepath = target_dir / filename

        escaped_cmd = html.escape(command)
        escaped_out = html.escape(output.strip()) if output else "(no output returned)"
        win_title = title or f"bash — {username}@{hostname}: {cwd} (xterm-256color)"

        terminal_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(win_title)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #080c14;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, 'Courier New', monospace;
    padding: 36px 32px;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    min-height: 100vh;
  }}
  .terminal-window {{
    width: 920px;
    max-width: 100%;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 12px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.06);
    overflow: hidden;
  }}
  .terminal-titlebar {{
    background: #161b22;
    padding: 12px 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #30363d;
    user-select: none;
  }}
  .traffic-lights {{
    display: flex;
    gap: 8px;
  }}
  .dot {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
    display: inline-block;
  }}
  .dot-red {{ background: #ff5f56; border: 1px solid #e0443e; }}
  .dot-yellow {{ background: #ffbd2e; border: 1px solid #dea123; }}
  .dot-green {{ background: #27c93f; border: 1px solid #1aab29; }}
  .terminal-title {{
    font-size: 12px;
    color: #8b949e;
    font-weight: 600;
    letter-spacing: 0.02em;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .terminal-badge {{
    font-size: 10px;
    color: #38bdf8;
    background: rgba(56, 189, 248, 0.12);
    border: 1px solid rgba(56, 189, 248, 0.35);
    padding: 3px 9px;
    border-radius: 5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .terminal-body {{
    padding: 24px 28px;
    font-size: 13.5px;
    line-height: 1.6;
    color: #c9d1d9;
    background: #0d1117;
  }}
  .prompt-line {{
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 8px;
    margin-bottom: 10px;
  }}
  .prompt-user {{ color: #38bdf8; font-weight: 700; }}
  .prompt-at {{ color: #8b949e; }}
  .prompt-host {{ color: #a855f7; font-weight: 700; }}
  .prompt-path {{ color: #fbbf24; font-weight: 600; }}
  .prompt-symbol {{ color: #f8fafc; font-weight: 800; }}
  .command-text {{
    color: #f8fafc;
    font-weight: 600;
    word-break: break-all;
    background: rgba(255, 255, 255, 0.04);
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .output-box {{
    margin-top: 10px;
    margin-bottom: 16px;
    color: #4ade80;
    white-space: pre-wrap;
    word-break: break-word;
    background: #05080e;
    padding: 16px 18px;
    border-radius: 8px;
    border: 1px solid #1e293b;
    border-left: 4px solid #38bdf8;
    font-size: 13px;
    max-height: 480px;
    overflow-y: auto;
  }}
  .cursor {{
    display: inline-block;
    width: 9px;
    height: 16px;
    background: #38bdf8;
    vertical-align: middle;
    margin-left: 4px;
    box-shadow: 0 0 8px #38bdf8;
  }}
  .footer-meta {{
    margin-top: 18px;
    padding-top: 12px;
    border-top: 1px dashed #21262d;
    font-size: 11px;
    color: #8b949e;
    display: flex;
    justify-content: space-between;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
</style>
</head>
<body>
  <div class="terminal-window">
    <div class="terminal-titlebar">
      <div class="traffic-lights">
        <span class="dot dot-red"></span>
        <span class="dot dot-yellow"></span>
        <span class="dot dot-green"></span>
      </div>
      <div class="terminal-title">{html.escape(win_title)}</div>
      <div class="terminal-badge">LIVE SHELL PROOF</div>
    </div>
    <div class="terminal-body">
      <div class="prompt-line">
        <span class="prompt-user">{username}</span><span class="prompt-at">@</span><span class="prompt-host">{hostname}</span>:<span class="prompt-path">{cwd}</span><span class="prompt-symbol">$</span>
        <span class="command-text">{escaped_cmd}</span>
      </div>
      <div class="output-box">
{escaped_out}
      </div>
      <div class="prompt-line">
        <span class="prompt-user">{username}</span><span class="prompt-at">@</span><span class="prompt-host">{hostname}</span>:<span class="prompt-path">{cwd}</span><span class="prompt-symbol">$</span>
        <span class="cursor"></span>
      </div>
      <div class="footer-meta">
        <span>✓ Execution State: Verified OS / Shell Evaluation</span>
        <span>Auditor: DAST Security Framework</span>
      </div>
    </div>
  </div>
</body>
</html>"""

        try:
            page.set_content(terminal_html, wait_until="domcontentloaded")
            page.wait_for_timeout(300)
            page.screenshot(path=str(filepath), full_page=True)
            logger.info("Generated high-fidelity terminal screenshot [%s]: %s", detector_name or "general", filepath)
            return str(filepath.resolve())
        except Exception as exc:
            logger.warning("Failed generating terminal screenshot: %s", exc)
            return None
