"""Target reachability checking and authentication verification module.

Executes pre-flight reachability checks using the curl command (with -u credentials
if supplied) and configures session authentication across HTTP and browser engines.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from dast.models import Target

logger = logging.getLogger(__name__)


def check_reachability_with_curl(
    url: str,
    auth: tuple[str, str] | None = None,
    custom_headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[bool, int, str]:
    """Execute pre-flight reachability check using curl command.

    Args:
        url: Target URL to test.
        auth: Optional (username, password) tuple for -u credentials flag.
        custom_headers: Optional dictionary of extra HTTP headers.
        timeout: Maximum execution timeout in seconds.

    Returns:
        Tuple of (is_reachable: bool, status_code: int, status_message: str).
    """
    curl_bin = shutil.which("curl")

    # Build curl argument list
    curl_args = ["curl", "-s", "-I", "-k", "--max-time", str(max(1, int(timeout)))]

    if auth and len(auth) == 2 and auth[0]:
        curl_args.extend(["-u", f"{auth[0]}:{auth[1]}"])

    if custom_headers:
        for k, v in custom_headers.items():
            curl_args.extend(["-H", f"{k}: {v}"])

    curl_args.append(url)

    # Safe masked command for logging
    if auth and len(auth) == 2 and auth[0]:
        masked_cmd = " ".join(
            ["curl", "-s", "-I", "-k", "--max-time", str(max(1, int(timeout))), "-u", f"{auth[0]}:****", url]
        )
    else:
        masked_cmd = " ".join(curl_args)

    logger.info("[REACHABILITY] Executing pre-flight reachability check: %s", masked_cmd)

    if curl_bin:
        try:
            res = subprocess.run(
                curl_args,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )

            stdout = res.stdout.strip()
            stderr = res.stderr.strip()

            if res.returncode == 0 and stdout:
                # Parse HTTP status code from header output (e.g. "HTTP/1.1 200 OK")
                status_match = re.search(r"HTTP/[\d\.]+\s+(\d{3})(?:\s+(.*))?", stdout)
                if status_match:
                    status_code = int(status_match.group(1))
                    status_text = status_match.group(2) or "OK"
                    logger.info(
                        "[REACHABILITY] Target is reachable via curl -> HTTP %d %s",
                        status_code,
                        status_text,
                    )
                    if status_code == 401:
                        logger.warning(
                            "[AUTH] Target returned HTTP 401 Unauthorized. Please verify credentials."
                        )
                    elif auth and status_code in (200, 301, 302, 303, 307, 308):
                        logger.info(
                            "[AUTH] Credentials for user '%s' successfully accepted (HTTP %d).",
                            auth[0],
                            status_code,
                        )
                    return True, status_code, f"HTTP {status_code} {status_text}"
                else:
                    logger.info("[REACHABILITY] Target responded via curl with return code 0.")
                    return True, 200, "Reachable via curl"
            else:
                logger.warning(
                    "[REACHABILITY] curl command returned non-zero code (%d): %s",
                    res.returncode,
                    stderr or stdout or "No output",
                )
        except Exception as exc:
            logger.warning("[REACHABILITY] curl execution encountered error (%s). Falling back to HTTP probe...", exc)
    else:
        logger.info("[REACHABILITY] curl binary not found on PATH. Using built-in HTTP pre-flight probe...")

    # Fallback to HTTP client reachability check
    try:
        req_auth = (auth[0], auth[1]) if (auth and len(auth) == 2 and auth[0]) else None
        with httpx.Client(verify=False, timeout=timeout, headers=custom_headers, follow_redirects=True) as client:
            resp = client.get(url, auth=req_auth)
            status_code = resp.status_code
            logger.info(
                "[REACHABILITY] HTTP pre-flight probe succeeded -> HTTP %d %s",
                status_code,
                resp.reason_phrase or "",
            )
            if status_code == 401:
                logger.warning("[AUTH] Target returned HTTP 401 Unauthorized.")
            elif auth and status_code in (200, 301, 302, 303, 307, 308):
                logger.info("[AUTH] Credentials for user '%s' accepted (HTTP %d).", auth[0], status_code)
            return True, status_code, f"HTTP {status_code} {resp.reason_phrase or ''}"
    except Exception as exc:
        logger.error("[REACHABILITY] Target '%s' is unreachable: %s", url, exc)
        return False, 0, f"Unreachable: {exc}"


def configure_authentication(
    target: Target,
    client: Any | None = None,
    browser: Any | None = None,
) -> tuple[bool, str]:
    """Configure credentials and authenticate session across client and browser.

    Verifies the landing page after authentication, logs active cookies/page title,
    and returns (is_authenticated, landing_url).

    Args:
        target: Target model containing auth credentials and optional login_url.
        client: HTTPClient instance.
        browser: BrowserManager instance.

    Returns:
        Tuple of (is_authenticated: bool, landing_url: str).
    """
    if not target.auth or len(target.auth) != 2 or not target.auth[0]:
        return False, target.url

    username, password = target.auth[0], target.auth[1]
    logger.info("[AUTH] Configuring credentials for user: '%s'", username)

    # 1. Apply to HTTPClient
    if client:
        if hasattr(client, "auth"):
            client.auth = (username, password)
        if hasattr(client, "_client"):
            client._client.auth = (username, password)
        logger.info("[AUTH] Applied HTTP Basic authentication to HTTPClient.")

    # 2. Apply to BrowserManager if active
    if browser and hasattr(browser, "http_credentials"):
        browser.http_credentials = {"username": username, "password": password}
        logger.info("[AUTH] Applied HTTP credentials to BrowserManager.")

    landing_url = target.url

    # 3. Form-based Login URL if specified
    if target.login_url and client:
        try:
            logger.info("[AUTH] Initiating form-based login at: %s", target.login_url)

            # A. Try browser-based visual form login first if browser is active
            browser_succeeded = False
            if browser and hasattr(browser, "login_with_browser") and getattr(browser, "is_available", False):
                try:
                    b_ok, b_cookies, b_landing = browser.login_with_browser(
                        target.login_url,
                        username,
                        password,
                        after_auth_url=target.after_auth_url,
                    )
                    if b_ok:
                        if b_landing:
                            landing_url = b_landing
                        if b_cookies and hasattr(client, "_client") and hasattr(client._client, "cookies"):
                            for c_name, c_val in b_cookies.items():
                                client._client.cookies.set(c_name, c_val)
                        if browser and hasattr(browser, "custom_headers") and b_cookies:
                            cookie_pairs = [f"{k}={v}" for k, v in b_cookies.items()]
                            browser.custom_headers["Cookie"] = "; ".join(cookie_pairs)
                        browser_succeeded = True
                        logger.info("[AUTH] Browser login succeeded. Landing URL: %s (Cookies: %s)", landing_url, list(b_cookies.keys()))
                    elif b_cookies:
                        if b_landing:
                            landing_url = b_landing
                        if hasattr(client, "_client") and hasattr(client._client, "cookies"):
                            for c_name, c_val in b_cookies.items():
                                client._client.cookies.set(c_name, c_val)
                except Exception as b_login_exc:
                    logger.debug("Browser login attempt notice: %s", b_login_exc)

            # B. If browser login was not run or failed, perform HTTP POST login
            if not browser_succeeded:
                form_inputs: dict[str, str] = {}
                try:
                    pre_resp, _, _ = client.get(target.login_url)
                    if pre_resp and hasattr(pre_resp, "text") and pre_resp.text:
                        soup = BeautifulSoup(pre_resp.text, "html.parser")
                        for inp in soup.find_all(["input", "select", "button"]):
                            inp_name = inp.get("name")
                            if not inp_name:
                                continue
                            inp_val = inp.get("value", "")
                            if inp.name == "select":
                                first_opt = inp.find("option")
                                inp_val = first_opt.get("value", "0") if first_opt else "0"
                            form_inputs[inp_name] = inp_val
                except Exception as pre_exc:
                    logger.debug("Pre-flight login inspection notice: %s", pre_exc)

                login_data = {
                    "username": username,
                    "user": username,
                    "login": username,
                    "uid": username,
                    "uname": username,
                    "email": username,
                    "password": password,
                    "pass": password,
                    "passw": password,
                    "pwd": password,
                    "security_level": "0",
                    "form": "submit",
                    "Login": "Login",
                    "btnSubmit": "Login",
                    "submit": "Submit",
                }
                login_data.update(form_inputs)
                # Ensure target credentials override any blank scraped inputs
                for u_key in ("username", "user", "login", "email", "uid", "uname"):
                    if u_key in form_inputs:
                        login_data[u_key] = username
                for p_key in ("password", "pass", "passw", "pwd"):
                    if p_key in form_inputs:
                        login_data[p_key] = password

                resp, _, _ = client.post(target.login_url, data=login_data)
                if resp and resp.status_code in (200, 301, 302, 303, 307, 308):
                    if "location" in getattr(resp, "headers", {}):
                        from urllib.parse import urljoin
                        landing_url = urljoin(target.login_url, resp.headers["location"])
                    elif hasattr(resp, "url") and resp.url:
                        landing_url = str(resp.url)

            # If user provided after_auth_url, probe and verify landing page
            if target.after_auth_url:
                from urllib.parse import urljoin
                resolved_after_auth = urljoin(target.login_url or target.url, target.after_auth_url)
                try:
                    after_resp, _, _ = client.get(resolved_after_auth)
                    if after_resp and after_resp.status_code in (200, 301, 302, 303, 307, 308):
                        resp_url = getattr(after_resp, "url", None)
                        if resp_url and not str(resp_url).startswith("<MagicMock"):
                            final_after_url = str(resp_url)
                        else:
                            final_after_url = resolved_after_auth
                        after_txt = after_resp.text.lower() if hasattr(after_resp, "text") and after_resp.text else ""
                        after_has_pwd = 'type="password"' in after_txt or "name='pass" in after_txt or 'name="pass' in after_txt or 'name="passw' in after_txt or 'name="pwd' in after_txt
                        if not after_has_pwd:
                            landing_url = final_after_url
                except Exception as land_err:
                    logger.debug("Probing target after_auth_url notice: %s", land_err)

            # Verify authenticated session state
            cookies_list: list[str] = []
            if hasattr(client, "_client") and hasattr(client._client, "cookies"):
                cookies_list = list(client._client.cookies.keys())

            landing_title = ""
            landing_status = 200
            landing_has_login_form = False
            try:
                landing_resp, _, _ = client.get(landing_url)
                if landing_resp:
                    landing_status = landing_resp.status_code
                    if hasattr(landing_resp, "text") and landing_resp.text:
                        txt = landing_resp.text.lower()
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", landing_resp.text, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            landing_title = title_match.group(1).strip()
                        has_pwd = ('type="password"' in txt or "name='password'" in txt or 'name="passw"' in txt or "name='passw'" in txt or "name='pwd'" in txt or 'name="pwd"' in txt)
                        is_login_page = any(k in landing_url.lower() for k in ["login", "signin", "logon", "auth"])
                        has_err = any(err in txt for err in ["login failed", "invalid username", "invalid password", "wrong username", "incorrect credentials", "authentication failed"])
                        if (has_pwd and is_login_page) or has_err:
                            landing_has_login_form = True
            except Exception as land_exc:
                logger.debug("Landing page probe notice: %s", land_exc)

            has_session_cookie = any(
                k.lower() in ("phpsessid", "dvwasession", "session", "sessionid", "connect.sid", "auth", "token", "jsessionid")
                for k in cookies_list
            )

            if target.after_auth_url:
                from urllib.parse import urlparse
                after_p = urlparse(target.after_auth_url).path.lower().strip("/")
                land_p = urlparse(landing_url).path.lower().strip("/")
                is_auth_success = bool(after_p and (after_p in land_p or land_p == after_p) and not landing_has_login_form and landing_status < 400)
            else:
                is_auth_success = bool(not landing_has_login_form and (has_session_cookie or browser_succeeded) and landing_status < 400)

            if not is_auth_success:
                logger.warning(
                    "[AUTH] Form login remained on login page without active session. Landing page: %s (HTTP %d, Title: '%s')",
                    landing_url,
                    landing_status,
                    landing_title or "None",
                )
                return False, target.url

            logger.info(
                "[AUTH] Form login successful. Landing page: %s (HTTP %d, Title: '%s', Active Cookies: %s)",
                landing_url,
                landing_status,
                landing_title or "None",
                cookies_list,
            )

            # Sync cookies to browser manager if present
            if browser and hasattr(browser, "custom_headers") and hasattr(client, "_client") and hasattr(client._client, "cookies"):
                cookie_pairs = [f"{k}={v}" for k, v in client._client.cookies.items()]
                if cookie_pairs:
                    browser.custom_headers["Cookie"] = "; ".join(cookie_pairs)

            # Register auto-reauthentication hook for session recovery mid-scan (Browser + HTTP)
            def _renew_session() -> bool:
                try:
                    logger.info("[AUTH] Mid-scan session expiration detected. Performing automatic re-authentication...")
                    
                    # 1. Try browser-based UI re-authentication if available (without recording duplicate screenshots)
                    if browser and hasattr(browser, "login_with_browser") and getattr(browser, "is_available", False):
                        try:
                            b_ok, b_cookies, b_landing = browser.login_with_browser(
                                target.login_url, username, password, record_screenshots=False
                            )
                            if b_ok and b_cookies:
                                if hasattr(client, "_client") and hasattr(client._client, "cookies"):
                                    for c_name, c_val in b_cookies.items():
                                        client._client.cookies.set(c_name, c_val)
                                logger.info("[AUTH] Mid-scan browser re-authentication successful.")
                                return True
                        except Exception as b_exc:
                            logger.debug("Browser re-auth attempt notice: %s. Falling back to HTTP re-auth...", b_exc)

                    # 2. HTTP POST Re-authentication fallback
                    renew_hidden: dict[str, str] = {}
                    renew_pre, _, _ = client.get(target.login_url)
                    if renew_pre and hasattr(renew_pre, "text") and renew_pre.text:
                        for t_name, t_val in re.findall(r'<input[^>]*type=[\'"]hidden[\'"][^>]*name=[\'"]([^\'"]+)[\'"][^>]*value=[\'"]([^\'"]*)[\'"]', renew_pre.text, re.IGNORECASE):
                            renew_hidden[t_name] = t_val
                        for t_val, t_name in re.findall(r'<input[^>]*value=[\'"]([^\'"]*)[\'"][^>]*name=[\'"]([^\'"]+)[\'"][^>]*type=[\'"]hidden[\'"]', renew_pre.text, re.IGNORECASE):
                            renew_hidden[t_name] = t_val
                    renew_data = dict(login_data)
                    renew_data.update(renew_hidden)
                    renew_resp, _, _ = client.post(target.login_url, data=renew_data)
                    if renew_resp and renew_resp.status_code in (200, 301, 302, 303, 307, 308):
                        if browser and hasattr(browser, "custom_headers") and hasattr(client, "_client") and hasattr(client._client, "cookies"):
                            cookie_pairs = [f"{k}={v}" for k, v in client._client.cookies.items()]
                            if cookie_pairs:
                                browser.custom_headers["Cookie"] = "; ".join(cookie_pairs)
                        logger.info("[AUTH] Mid-scan HTTP re-authentication successful.")
                        return True
                except Exception as renew_exc:
                    logger.warning("[AUTH] Re-authentication failed: %s", renew_exc)
                return False

            client.reauth_callback = _renew_session
            return True, landing_url
        except Exception as exc:
            logger.warning("[AUTH] Form login attempt failed at %s: %s", target.login_url, exc)
            return False, target.url

    # 4. HTTP Basic Auth verification check
    if client:
        try:
            resp, _, _ = client.get(target.url)
            if resp and resp.status_code < 400:
                landing_url = str(resp.url) if hasattr(resp, "url") and resp.url else target.url
                page_title = ""
                if hasattr(resp, "text") and resp.text:
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                    page_title = title_match.group(1).strip() if title_match else ""
                logger.info(
                    "[AUTH] HTTP Basic authentication verified. Landing page: %s (HTTP %d, Title: '%s')",
                    landing_url,
                    resp.status_code,
                    page_title or "None",
                )
                return True, landing_url
            elif resp and resp.status_code == 401:
                logger.warning("[AUTH] Target returned HTTP 401 Unauthorized for user '%s'.", username)
                return False, target.url
        except Exception as exc:
            logger.debug("Post-auth HTTP verification notice: %s", exc)

    return True, target.url
