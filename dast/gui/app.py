"""Flask-based Web GUI Dashboard & API Server for DAST Security Scanner.

Provides real-time interactive assessment control, live milestone tracking (% progress),
event streaming (SSE), separated tabs (Progress, Vulnerabilities, Upload/Reports), and visual screenshot proof.
"""

from __future__ import annotations

from datetime import datetime
import json
import logging
from pathlib import Path
import queue
import threading
import time
from typing import Any
import webbrowser

from flask import Flask, Response, jsonify, render_template_string, request, send_file

from dast.detectors.registry import DetectorRegistry
from dast.models import EvidenceType, Finding, HttpMethod, ScanResult, Severity, Target
from dast.reporting.html_report import HTMLReporter
from dast.reporting.json_report import JSONReporter
from dast.reporting.markdown_report import MarkdownReporter
from dast.reporting.pdf_report import PDFReporter
from dast.scanner import Scanner

logger = logging.getLogger(__name__)


class ScanManager:
    """Manages background scan execution, state tracking, and SSE event broadcasting."""

    def __init__(self) -> None:
        self.status = "idle"  # idle, running, completed, error, stopped
        self.current_scan_id: str | None = None
        self.scanner: Scanner | None = None
        self.scan_thread: threading.Thread | None = None
        self.scan_result: ScanResult | None = None
        self.error_message: str | None = None
        self.start_time: float | None = None
        self.progress_percent: int = 0
        self.current_milestone: str = "idle"
        self.milestones_state: dict[str, str] = {
            "start": "pending",
            "reachability": "pending",
            "auth_start": "pending",
            "auth_completed": "pending",
            "crawling": "pending",
            "pentesting": "pending",
            "ai_verification": "pending",
            "completed": "pending",
        }
        self.activity_log: list[dict[str, Any]] = []
        self.events_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.subscribers: list[queue.Queue[dict[str, Any]]] = []
        self._lock = threading.Lock()
        self.current_endpoints: list[dict[str, Any]] = []
        self.current_findings: list[dict[str, Any]] = []
        self.stats = {
            "endpoints_crawled": 0,
            "total_findings": 0,
            "confirmed_findings": 0,
            "false_positives": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        payload = {"type": event_type, "timestamp": time.time(), "data": data}
        with self._lock:
            for q in self.subscribers:
                q.put(payload)

    def reset(self) -> None:
        with self._lock:
            self.status = "idle"
            self.scan_result = None
            self.error_message = None
            self.start_time = None
            self.progress_percent = 0
            self.current_milestone = "idle"
            self.milestones_state = {k: "pending" for k in self.milestones_state}
            self.activity_log.clear()
            self.current_endpoints.clear()
            self.current_findings.clear()
            self.stats = {k: 0 for k in self.stats}
            try:
                auth_dir = Path("evidence/screenshots/auth")
                if auth_dir.exists():
                    for f in auth_dir.glob("*.png"):
                        try:
                            f.unlink()
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                ev_dir = Path("evidence/screenshots")
                if ev_dir.exists():
                    for f in ev_dir.glob("*.png"):
                        try:
                            f.unlink()
                        except Exception:
                            pass
            except Exception:
                pass

    def start_scan(self, config: dict[str, Any]) -> tuple[bool, str]:
        if self.status == "running":
            if self.scanner and hasattr(self.scanner, "stop"):
                try:
                    self.scanner.stop()
                except Exception:
                    pass

        target_url = (config.get("target_url") or config.get("url") or "").strip()
        if not target_url:
            return False, "Target URL is required."

        self.reset()
        scan_id = str(time.time_ns())
        with self._lock:
            self.current_scan_id = scan_id
            self.status = "running"
            self.start_time = time.time()

        def _run() -> None:
            try:
                if self.current_scan_id != scan_id:
                    return

                allowed_hosts = [h.strip() for h in config.get("allowed_hosts", "").split(",") if h.strip()]
                custom_headers = config.get("custom_headers", {})
                auth_user = config.get("username", "").strip()
                auth_pass = config.get("password", "").strip()
                auth = (auth_user, auth_pass) if auth_user else None
                login_url = config.get("login_url", "").strip() or None
                after_auth_url = (config.get("after_auth_url") or config.get("authenticated_url") or "").strip() or None

                target = Target(
                    url=target_url,
                    allowed_hosts=allowed_hosts,
                    max_depth=int(config.get("max_depth", 2)),
                    max_pages=int(config.get("max_pages", 20)),
                    custom_headers=custom_headers,
                    auth=auth,
                    login_url=login_url,
                    after_auth_url=after_auth_url,
                )

                selected_detectors = config.get("detectors") or None
                max_workers = int(config.get("max_workers", 5))
                use_browser = bool(config.get("use_browser", True))
                enable_ai = bool(config.get("enable_ai", True))
                use_kafka = bool(config.get("use_kafka", True))
                kafka_broker = config.get("kafka_broker", "localhost:9092")

                self.broadcast("status", {"status": "running", "message": f"Starting scan on {target_url}..."})

                def handle_progress(milestone: str, title: str, message: str, percent: int, extra: dict[str, Any]) -> None:
                    if self.current_scan_id != scan_id:
                        return
                    ts_str = datetime.now().strftime("%H:%M:%S")
                    with self._lock:
                        if self.current_scan_id != scan_id:
                            return
                        self.progress_percent = percent
                        self.current_milestone = milestone
                        keys = list(self.milestones_state.keys())
                        if milestone in keys:
                            idx_curr = keys.index(milestone)
                            for i, k in enumerate(keys):
                                if i < idx_curr:
                                    self.milestones_state[k] = "completed"
                                elif i == idx_curr:
                                    self.milestones_state[k] = "in_progress" if (percent < 100 and milestone != "completed") else "completed"
                        if milestone == "completed":
                            for k in keys:
                                self.milestones_state[k] = "completed"
                        self.activity_log.append({
                            "timestamp": ts_str,
                            "milestone": milestone,
                            "title": title,
                            "message": message,
                            "percent": percent,
                        })
                    self.broadcast("progress_milestone", {
                        "milestone": milestone,
                        "title": title,
                        "message": message,
                        "percent": percent,
                        "extra": extra,
                        "milestones_state": dict(self.milestones_state),
                        "stats": dict(self.stats),
                        "timestamp": ts_str,
                    })

                def handle_endpoint(ep: Any, idx: int) -> None:
                    if self.current_scan_id != scan_id:
                        return
                    with self._lock:
                        if self.current_scan_id != scan_id:
                            return
                        self.stats["endpoints_crawled"] = idx
                        self.current_endpoints.append({
                            "url": ep.url,
                            "method": ep.method.value if hasattr(ep.method, "value") else str(ep.method),
                            "params": ep.get_all_param_names(),
                        })
                    self.broadcast("endpoint_discovered", {
                        "url": ep.url,
                        "method": ep.method.value if hasattr(ep.method, "value") else str(ep.method),
                        "stats": dict(self.stats),
                    })

                def handle_finding(f: Any) -> None:
                    if self.current_scan_id != scan_id:
                        return
                    f_json = f.model_dump(mode="json")
                    with self._lock:
                        if self.current_scan_id != scan_id:
                            return
                        self.current_findings.append(f_json)
                        self.stats["total_findings"] = len(self.current_findings)
                        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
                        if sev in self.stats:
                            self.stats[sev] += 1
                        if f.is_false_positive:
                            self.stats["false_positives"] += 1
                        else:
                            self.stats["confirmed_findings"] += 1
                    self.broadcast("finding_discovered", f_json)

                self.scanner = Scanner(
                    target=target,
                    selected_detectors=selected_detectors,
                    max_workers=max_workers,
                    enable_ai_validation=enable_ai,
                    use_kafka=use_kafka,
                    kafka_bootstrap_servers=kafka_broker,
                    enable_browser=use_browser,
                    on_endpoint_discovered=handle_endpoint,
                    on_finding_discovered=handle_finding,
                    on_progress=handle_progress,
                )

                result = self.scanner.run()
                if self.current_scan_id != scan_id:
                    return

                with self._lock:
                    if self.current_scan_id != scan_id or self.status == "stopped" or (self.scanner and self.scanner.stop_event.is_set()):
                        return
                    self.scan_result = result
                    self.status = "completed"
                    self.progress_percent = 100

                # Save artifacts
                JSONReporter.save(result, "dast-report.json")
                HTMLReporter.save(result, "dast-report.html")
                MarkdownReporter.save(result, "dast-report.md")
                try:
                    PDFReporter.save(result, "dast-report.pdf")
                except Exception as pdf_err:
                    logger.warning("Notice generating PDF report in GUI: %s", pdf_err)

                self.broadcast("completed", {
                    "status": "completed",
                    "total_findings": len(result.findings),
                    "confirmed": result.summary.get("confirmed_findings", len(result.findings)),
                    "duration": f"{result.duration_seconds:.2f}s",
                })
            except Exception as exc:
                if self.current_scan_id != scan_id:
                    return
                logger.exception("Error executing scan in GUI manager: %s", exc)
                with self._lock:
                    self.status = "error"
                    self.error_message = str(exc)
                self.broadcast("error", {"status": "error", "error": str(exc)})

        self.scan_thread = threading.Thread(target=_run, daemon=True)
        self.scan_thread.start()
        return True, "Scan started successfully."

    def stop_scan(self) -> tuple[bool, str]:
        with self._lock:
            self.current_scan_id = None
            if self.scanner and hasattr(self.scanner, "stop"):
                try:
                    self.scanner.stop()
                except Exception as e:
                    logger.debug("Notice stopping scanner: %s", e)
        self.reset()
        self.broadcast("status", {"status": "stopped", "message": "Scan stopped and cleared."})
        return True, "Scan stopped and cleared."


scan_manager = ScanManager()

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DAST Security Scanner - Live Interactive Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-dark: #090d16;
    --bg-card: #111827;
    --bg-card-hover: #1f293d;
    --border: #1e293b;
    --border-highlight: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --accent-glow: rgba(56, 189, 248, 0.15);
    --crit: #ef4444;
    --high: #f97316;
    --med: #f59e0b;
    --low: #3b82f6;
    --info: #64748b;
    --success: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text-main);
    line-height: 1.5;
    min-height: 100vh;
  }
  .navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 32px;
    background: rgba(17, 24, 39, 0.85);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo { display: flex; align-items: center; gap: 12px; }
  .logo-icon {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, #0284c7, #38bdf8);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 0 20px rgba(56, 189, 248, 0.35);
  }
  .logo-text h1 { font-size: 18px; font-weight: 800; letter-spacing: -0.02em; }
  .logo-text p { font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }

  /* Navigation Main Tabs in Header */
  .nav-tabs {
    display: flex;
    background: #0c1220;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 4px;
    gap: 4px;
  }
  .nav-tab-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 700;
    padding: 8px 18px;
    border-radius: 8px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: all 0.2s;
  }
  .nav-tab-btn:hover { color: #fff; background: rgba(255,255,255,0.04); }
  .nav-tab-btn.active {
    background: #1e293b;
    color: var(--accent);
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  }
  .nav-tab-badge {
    background: #334155;
    color: #fff;
    padding: 2px 7px;
    border-radius: 12px;
    font-size: 11px;
  }
  .nav-tab-badge.highlight { background: var(--crit); }
  
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: #1e293b;
    border: 1px solid var(--border);
  }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; }
  .status-running .status-dot { background: var(--accent); box-shadow: 0 0 10px var(--accent); animation: pulse 1.5s infinite; }
  .status-completed .status-dot { background: var(--success); box-shadow: 0 0 10px var(--success); }
  .status-error .status-dot { background: var(--crit); }
  @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

  .layout { display: grid; grid-template-columns: 360px 1fr; gap: 24px; padding: 24px 32px; max-width: 1750px; margin: 0 auto; }

  /* Config Sidebar */
  .panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
  }
  .panel-title {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 18px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
  }
  .form-group { margin-bottom: 15px; }
  .form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
  .form-control {
    width: 100%;
    background: #0b1120;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 9px 12px;
    color: #fff;
    font-size: 13px;
    font-family: inherit;
    transition: all 0.15s;
  }
  .form-control:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .input-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px 18px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    border: none;
    transition: all 0.15s;
    width: 100%;
  }
  .btn-primary { background: linear-gradient(135deg, #0284c7, #38bdf8); color: #090d16; }
  .btn-primary:hover { opacity: 0.95; transform: translateY(-1px); }
  .btn-danger { background: #ef4444; color: #fff; margin-top: 8px; }
  .btn-secondary { background: #1e293b; color: #fff; border: 1px solid var(--border); }
  .btn-secondary:hover { background: #334155; }
  .btn-success { background: #10b981; color: #090d16; }

  /* Tab View Areas */
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Real-Time Progress Tab Styles */
  .progress-hero {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 22px;
  }
  .progress-hero-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }
  .progress-track {
    width: 100%;
    height: 14px;
    background: #0b1120;
    border-radius: 10px;
    border: 1px solid var(--border);
    overflow: hidden;
    position: relative;
  }
  .progress-fill {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #0284c7, #38bdf8, #10b981);
    border-radius: 10px;
    transition: width 0.4s ease;
    box-shadow: 0 0 16px rgba(56, 189, 248, 0.4);
  }
  .progress-subtitle {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 8px;
    font-family: 'JetBrains Mono', monospace;
  }

  /* Milestones Stepper Grid */
  .milestone-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-bottom: 22px;
  }
  .milestone-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    transition: all 0.2s;
  }
  .milestone-card.in_progress {
    border-color: var(--accent);
    background: #0f1c30;
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.15);
  }
  .milestone-card.completed {
    border-color: rgba(16, 185, 129, 0.4);
    background: rgba(16, 185, 129, 0.05);
  }
  .milestone-icon {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    flex-shrink: 0;
    background: #1e293b;
  }
  .milestone-card.in_progress .milestone-icon { background: var(--accent); color: #090d16; }
  .milestone-card.completed .milestone-icon { background: #10b981; color: #090d16; }
  .milestone-info h4 { font-size: 13px; font-weight: 700; margin-bottom: 2px; }
  .milestone-info p { font-size: 11px; color: var(--text-muted); }
  .milestone-status-tag {
    font-size: 10px;
    font-weight: 800;
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    margin-top: 4px;
    display: inline-block;
  }
  .milestone-card.pending .milestone-status-tag { background: #1e293b; color: #64748b; }
  .milestone-card.in_progress .milestone-status-tag { background: rgba(56, 189, 248, 0.2); color: var(--accent); }
  .milestone-card.completed .milestone-status-tag { background: rgba(16, 185, 129, 0.2); color: var(--success); }

  /* Activity Feed & Endpoints Dual Box */
  .progress-split {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }
  .terminal-box {
    background: #070b14;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    height: 360px;
  }
  .terminal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 12px;
    font-size: 12px;
    font-weight: 700;
    color: var(--text-muted);
  }
  .terminal-logs {
    flex: 1;
    overflow-y: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    line-height: 1.6;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .log-line { display: flex; gap: 8px; align-items: baseline; }
  .log-ts { color: #64748b; }
  .log-title { color: var(--accent); font-weight: 600; }
  .log-msg { color: #cbd5e1; }

  .endpoints-table-container {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
    height: 360px;
    display: flex;
    flex-direction: column;
  }
  .endpoints-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .endpoints-table th {
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
    font-weight: 700;
  }
  .endpoints-table td {
    padding: 8px;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    font-family: 'JetBrains Mono', monospace;
  }

  /* Vulnerabilities Tab Styles */
  .metrics-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
    text-align: center;
  }
  .metric-num { font-size: 26px; font-weight: 800; line-height: 1.1; font-family: 'JetBrains Mono', monospace; }
  .metric-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-top: 4px; }

  .tab-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px 12px;
    margin-bottom: 20px;
  }
  .tab-group { display: flex; gap: 8px; }
  .tab-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
  }
  .tab-btn.active { background: #1e293b; color: var(--accent); }

  .finding-item {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 12px;
    overflow: hidden;
    transition: all 0.15s;
  }
  .finding-item:hover { border-color: var(--border-highlight); }
  .finding-header {
    padding: 14px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
  }
  .badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
  }
  .badge-crit { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
  .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
  .badge-med { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
  .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
  .badge-confirmed { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
  .badge-fp { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }

  .finding-body {
    padding: 18px;
    border-top: 1px solid var(--border);
    background: #0c1220;
    display: none;
  }
  .finding-body.open { display: block; }
  .evidence-box {
    background: #060911;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #cbd5e1;
    overflow-x: auto;
    white-space: pre-wrap;
    margin-top: 8px;
  }
  .screenshot-preview {
    margin-top: 12px;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
    max-width: 500px;
    cursor: pointer;
  }
  .screenshot-preview img { width: 100%; display: block; }

  /* Upload & Reports Tab Styles */
  .reports-hero {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px;
    margin-bottom: 24px;
    text-align: center;
  }
  .reports-cards-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  .report-action-card {
    background: #0b1120;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    text-align: center;
    transition: all 0.2s;
  }
  .report-action-card:hover { border-color: var(--accent); transform: translateY(-2px); }
  .report-action-card h3 { font-size: 15px; margin: 12px 0 6px 0; }
  .report-action-card p { font-size: 12px; color: var(--text-muted); margin-bottom: 16px; }

  /* Modal Lightbox */
  .modal-overlay {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(0,0,0,0.85);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }
  .modal-overlay.open { display: flex; }
  .modal-content { max-width: 90vw; max-height: 90vh; }
  .modal-content img { max-width: 100%; max-height: 90vh; border-radius: 8px; }

  .checkbox-group { display: flex; flex-direction: column; gap: 6px; max-height: 140px; overflow-y: auto; padding-right: 4px; }
  .checkbox-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
</style>
</head>
<body>

<nav class="navbar">
  <div class="logo">
    <div class="logo-icon">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#090d16" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
    </div>
    <div class="logo-text">
      <h1>DAST Security Auditor</h1>
      <p>Continuous AI-Powered Pentesting</p>
    </div>
  </div>

  <!-- Central Navigation Tabs -->
  <div class="nav-tabs">
    <button class="nav-tab-btn active" onclick="switchMainTab('tab-progress')">
      <span>⚡ Progress & Milestones</span>
      <span id="tabProgressPct" class="nav-tab-badge">0%</span>
    </button>
    <button class="nav-tab-btn" onclick="switchMainTab('tab-vulnerabilities')">
      <span>🛡️ Vulnerabilities</span>
      <span id="tabVulnCount" class="nav-tab-badge">0</span>
    </button>
    <button class="nav-tab-btn" onclick="switchMainTab('tab-reports')">
      <span>📤 Upload & Reports</span>
      <span id="tabReportReady" class="nav-tab-badge" style="display: none; background: var(--success); color: #090d16;">READY</span>
    </button>
  </div>

  <div style="display: flex; gap: 12px; align-items: center;">
    <div id="statusBadge" class="status-badge">
      <div class="status-dot"></div>
      <span id="statusText">IDLE</span>
    </div>
  </div>
</nav>

<div class="layout">
  <!-- Left: Scan Configuration -->
  <div class="panel">
    <div class="panel-title">
      <span>Scan Target & Options</span>
    </div>

    <form id="scanForm" onsubmit="event.preventDefault(); startScan();">
      <div class="form-group">
        <label>Target URL</label>
        <input type="url" id="targetUrl" class="form-control" value="http://localhost:80" required placeholder="http://target.local">
      </div>

      <div class="form-group">
        <label>Authentication Credentials</label>
        <div class="input-grid">
          <input type="text" id="username" class="form-control" placeholder="Username (e.g. admin)" value="admin">
          <input type="password" id="password" class="form-control" placeholder="Password (e.g. password)" value="password">
        </div>
      </div>

      <div class="form-group">
        <label>Login Page & After-Auth Landing Page</label>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <input type="url" id="loginUrl" class="form-control" value="http://localhost:80/login.php" placeholder="Login Page (e.g. http://localhost/login.php)">
          <input type="text" id="afterAuthUrl" class="form-control" value="http://localhost:80/portal.php" placeholder="After-Auth Page (e.g. http://localhost/portal.php or /index.php)">
        </div>
      </div>

      <div class="form-group">
        <label>Crawler Scope Limits</label>
        <div class="input-grid">
          <div>
            <span style="font-size: 10px; color: var(--text-muted);">Max Depth</span>
            <input type="number" id="maxDepth" class="form-control" value="2" min="1" max="10">
          </div>
          <div>
            <span style="font-size: 10px; color: var(--text-muted);">Max Pages</span>
            <input type="number" id="maxPages" class="form-control" value="20" min="1" max="500">
          </div>
        </div>
      </div>

      <div class="form-group">
        <label>Execution & Concurrency</label>
        <div class="input-grid">
          <div>
            <span style="font-size: 10px; color: var(--text-muted);">Workers</span>
            <input type="number" id="maxWorkers" class="form-control" value="5" min="1" max="20">
          </div>
          <div>
            <span style="font-size: 10px; color: var(--text-muted);">Browser Mode</span>
            <select id="useBrowser" class="form-control">
              <option value="true" selected>Enabled (Visual)</option>
              <option value="false">Disabled (HTTP)</option>
            </select>
          </div>
        </div>
      </div>

      <div class="form-group">
        <label>Active Detector Plugins</label>
        <div class="checkbox-group" id="detectorCheckboxes">
          <label class="checkbox-item"><input type="checkbox" name="det" value="all" checked onchange="toggleAllDetectors(this)"> <strong>Select All Plugins</strong></label>
        </div>
      </div>

      <button type="submit" id="startBtn" class="btn btn-primary">🚀 Launch Security Assessment</button>
      <button type="button" id="stopBtn" class="btn btn-danger" style="display: none;" onclick="stopScan()">🛑 Stop Assessment</button>
    </form>
  </div>

  <!-- Right: Tabbed Workspace Content -->
  <div>
    <!-- TAB 1: Real-Time Progress & Milestones -->
    <div id="tab-progress" class="tab-content active">
      <div class="progress-hero">
        <div class="progress-hero-header">
          <div>
            <h3 style="font-size: 16px; font-weight: 800;">Real-Time Assessment Progress</h3>
            <p id="progressCurrentStatus" style="font-size: 13px; color: var(--accent); margin-top: 2px;">Waiting for scan initiation...</p>
          </div>
          <div id="progressHeroPct" style="font-size: 28px; font-weight: 800; font-family: 'JetBrains Mono', monospace; color: var(--accent);">0%</div>
        </div>
        <div class="progress-track">
          <div id="progressBarFill" class="progress-fill"></div>
        </div>
        <div class="progress-subtitle">
          <span id="progressStepName">Stage: Idle</span>
          <span id="progressEndpointsBadge">Endpoints: 0</span>
        </div>
      </div>

      <!-- Milestone Stepper Cards -->
      <div class="milestone-grid">
        <div id="step-start" class="milestone-card pending">
          <div class="milestone-icon">🚀</div>
          <div class="milestone-info">
            <h4>1. Starting Scan</h4>
            <p>Target scope initialization</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-reachability" class="milestone-card pending">
          <div class="milestone-icon">🌐</div>
          <div class="milestone-info">
            <h4>2. Reachability</h4>
            <p>Curl pre-flight verification</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-auth_start" class="milestone-card pending">
          <div class="milestone-icon">🔐</div>
          <div class="milestone-info">
            <h4>3. Starting Auth</h4>
            <p>Browser form submission</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-auth_completed" class="milestone-card pending">
          <div class="milestone-icon">✅</div>
          <div class="milestone-info">
            <h4>4. Auth Success</h4>
            <p>Landing page & session sync</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-crawling" class="milestone-card pending">
          <div class="milestone-icon">🕸️</div>
          <div class="milestone-info">
            <h4>5. Crawling & Discovery</h4>
            <p>Endpoints & forms spidering</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-pentesting" class="milestone-card pending">
          <div class="milestone-icon">🎯</div>
          <div class="milestone-info">
            <h4>6. Pentesting</h4>
            <p>Parallel detector plugins</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-ai_verification" class="milestone-card pending">
          <div class="milestone-icon">🤖</div>
          <div class="milestone-info">
            <h4>7. AI Confirmation</h4>
            <p>Gemini FP validation</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>

        <div id="step-completed" class="milestone-card pending">
          <div class="milestone-icon">🏁</div>
          <div class="milestone-info">
            <h4>8. Completed</h4>
            <p>Report & artifact export</p>
            <span class="milestone-status-tag">Pending</span>
          </div>
        </div>
      </div>

      <!-- Authentication Visual Steps Proof -->
      <div id="authScreenshotsSection" style="display: none; margin-bottom: 20px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px;">
        <div style="font-size: 13px; font-weight: 700; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;">
          <span>🔐 Authentication & Session Verification Proof (Visual Steps)</span>
          <span id="authScreenshotCount" style="font-size: 11px; color: var(--text-muted);">0 screenshots</span>
        </div>
        <div id="authScreenshotsGrid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px;"></div>
      </div>

      <!-- Live Split: Activity Terminal + Discovered Endpoints -->
      <div class="progress-split">
        <div class="terminal-box">
          <div class="terminal-header">
            <span>💻 LIVE SCAN ACTIVITY LOG</span>
            <span id="logCount">0 events</span>
          </div>
          <div class="terminal-logs" id="terminalLogs">
            <div class="log-line"><span class="log-ts">[00:00:00]</span> <span class="log-msg">DAST Security Auditor console initialized. Ready to scan.</span></div>
          </div>
        </div>

        <div class="endpoints-table-container">
          <div class="terminal-header">
            <span>🔗 DISCOVERED TARGET ENDPOINTS</span>
            <span id="tableEndpointCount">0 discovered</span>
          </div>
          <div style="flex: 1; overflow-y: auto;">
            <table class="endpoints-table">
              <thead>
                <tr>
                  <th style="width: 80px;">Method</th>
                  <th>Endpoint URL</th>
                  <th style="width: 100px;">Parameters</th>
                </tr>
              </thead>
              <tbody id="endpointsTableBody">
                <tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 30px;">No endpoints discovered yet.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: Vulnerabilities Explorer -->
    <div id="tab-vulnerabilities" class="tab-content">
      <!-- Metrics Row -->
      <div class="metrics-row">
        <div class="metric-card" onclick="switchMainTab('tab-progress')" style="cursor: pointer;" title="View crawled endpoints">
          <div class="metric-num" id="statEndpoints" style="color: var(--accent);">0</div>
          <div class="metric-label">Endpoints</div>
        </div>
        <div class="metric-card" onclick="filterCategory('CONFIRMED')" style="cursor: pointer;" title="Filter by Confirmed True Positives">
          <div class="metric-num" id="statConfirmed" style="color: var(--success);">0</div>
          <div class="metric-label">Confirmed (AI)</div>
        </div>
        <div class="metric-card" onclick="filterCategory('FALSE_POSITIVE')" style="cursor: pointer;" title="Filter by False Positives">
          <div class="metric-num" id="statFP" style="color: var(--high);">0</div>
          <div class="metric-label">False Positives</div>
        </div>
        <div class="metric-card" onclick="filterCategory('ALL')" style="cursor: pointer;" title="View all findings">
          <div class="metric-num" id="statCrit" style="color: var(--crit);">0</div>
          <div class="metric-label">Critical</div>
        </div>
        <div class="metric-card" onclick="filterCategory('ALL')" style="cursor: pointer;" title="View all findings">
          <div class="metric-num" id="statHigh" style="color: var(--high);">0</div>
          <div class="metric-label">High</div>
        </div>
        <div class="metric-card" onclick="filterCategory('ALL')" style="cursor: pointer;" title="View all findings">
          <div class="metric-num" id="statMed" style="color: var(--med);">0</div>
          <div class="metric-label">Medium</div>
        </div>
      </div>

      <!-- Filter Tab Bar -->
      <div class="tab-bar">
        <div class="tab-group">
          <button class="tab-btn active" data-filter="CONFIRMED" onclick="filterCategory('CONFIRMED')">✓ Confirmed Only (<span id="btnFilterConfirmed">0</span>)</button>
          <button class="tab-btn" data-filter="ALL" onclick="filterCategory('ALL')">All Findings (<span id="btnFilterAll">0</span>)</button>
          <button class="tab-btn" data-filter="FALSE_POSITIVE" onclick="filterCategory('FALSE_POSITIVE')">⚠️ False Positives (<span id="btnFilterFP">0</span>)</button>
        </div>
        <input type="text" id="searchBox" class="form-control" style="width: 260px;" placeholder="Filter by title, URL, param..." onkeyup="filterFindingsUI()">
      </div>

      <!-- Findings List -->
      <div id="findingsList">
        <div style="text-align: center; padding: 60px; background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border);">
          <p style="color: var(--text-muted); font-size: 14px;">No assessment findings recorded. Start a scan to discover vulnerabilities.</p>
        </div>
      </div>
    </div>

    <!-- TAB 3: Upload & Reports -->
    <div id="tab-reports" class="tab-content">
      <div class="reports-hero">
        <h2 style="font-size: 22px; font-weight: 800; margin-bottom: 8px;">Security Audit Artifacts & Reports</h2>
        <p id="reportsHeroSubtitle" style="color: var(--text-muted); font-size: 14px; max-width: 600px; margin: 0 auto;">
          Download interactive executive HTML reports, Markdown audit documentation, or structured JSON data.
        </p>
      </div>

      <div class="reports-cards-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));">
        <div class="report-action-card" style="border: 1px solid #38bdf8; background: #0c182c;">
          <div style="font-size: 32px;">📑</div>
          <h3 style="color: #38bdf8;">Executive PDF Report</h3>
          <p>Complete audit documentation with confirmed True-Positive vulnerabilities, visual screenshots, curl reproduction guides, and remediation code.</p>
          <a href="/api/reports/pdf" target="_blank" class="btn btn-primary" download="dast-security-report.pdf">📥 Download PDF Report</a>
        </div>

        <div class="report-action-card">
          <div style="font-size: 32px;">📊</div>
          <h3>Interactive HTML Report</h3>
          <p>Full interactive HTML report with severity graphs, confirmed finding filters, and visual screenshot attachments.</p>
          <a href="/api/reports/html" target="_blank" class="btn btn-secondary">Download HTML Report</a>
        </div>

        <div class="report-action-card">
          <div style="font-size: 32px;">📋</div>
          <h3>Markdown Audit Report</h3>
          <p>GitHub-flavored Markdown report formatted with executive summaries, reproduction curl commands, and proofs.</p>
          <a href="/api/reports/markdown" target="_blank" class="btn btn-secondary">Download Markdown</a>
        </div>

        <div class="report-action-card">
          <div style="font-size: 32px;">⚙️</div>
          <h3>Structured JSON Export</h3>
          <p>Machine-readable JSON schema export containing all raw HTTP evidence, detector timings, and findings data.</p>
          <a href="/api/reports/json" target="_blank" class="btn btn-secondary">Download JSON</a>
        </div>
      </div>

      <div class="panel" style="margin-top: 20px;">
        <div class="panel-title">
          <span>📋 Export & Upload Actions</span>
        </div>
        <div style="display: flex; gap: 12px; flex-wrap: wrap;">
          <a href="/api/reports/pdf" target="_blank" class="btn btn-primary" style="width: auto; padding: 10px 24px;">📑 View / Download PDF Report</a>
          <button class="btn btn-secondary" style="width: auto; padding: 10px 24px;" onclick="copyReportJsonToClipboard()">📋 Copy JSON to Clipboard</button>
          <a href="/api/reports/html" target="_blank" class="btn btn-success" style="width: auto; padding: 10px 24px;">🌐 Open HTML Report</a>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Screenshot Lightbox Modal -->
<div id="lightboxModal" class="modal-overlay" onclick="closeModal()">
  <div class="modal-content">
    <img id="modalImg" src="" alt="Vulnerability Screenshot Evidence">
  </div>
</div>

<script>
  let allFindings = [];
  let currentFilter = 'CONFIRMED';
  let sseSource = null;

  function switchMainTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-tab-btn').forEach(el => el.classList.remove('active'));

    const targetTab = document.getElementById(tabId);
    if (targetTab) targetTab.classList.add('active');

    const btn = Array.from(document.querySelectorAll('.nav-tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
    if (btn) btn.classList.add('active');
  }

  async function loadDetectors() {
    try {
      const res = await fetch('/api/detectors');
      const data = await res.json();
      const container = document.getElementById('detectorCheckboxes');
      data.forEach(d => {
        const lbl = document.createElement('label');
        lbl.className = 'checkbox-item';
        lbl.innerHTML = `<input type="checkbox" name="detector" value="${d.name}" checked> <span>${d.name} (${d.category})</span>`;
        container.appendChild(lbl);
      });
    } catch(e) {
      console.error(e);
    }
  }

  function toggleAllDetectors(master) {
    document.querySelectorAll('input[name="detector"]').forEach(cb => cb.checked = master.checked);
  }

  function resetScanUI() {
    allFindings = [];
    const tbody = document.getElementById('endpointsTableBody');
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 32px;">No endpoints discovered yet.</td></tr>';
    }
    const findingsList = document.getElementById('findingsList');
    if (findingsList) {
      findingsList.innerHTML = '<div style="text-align: center; padding: 48px; background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border); color: var(--text-muted);">No matching findings for active filter.</div>';
    }
    const termLogs = document.getElementById('terminalLogs');
    if (termLogs) {
      termLogs.innerHTML = '';
    }
    const logCount = document.getElementById('logCount');
    if (logCount) logCount.innerText = '0 events';
    const authSec = document.getElementById('authScreenshotsSection');
    if (authSec) authSec.style.display = 'none';
    const authGrid = document.getElementById('authScreenshotsGrid');
    if (authGrid) authGrid.innerHTML = '';
    const authCount = document.getElementById('authScreenshotCount');
    if (authCount) authCount.innerText = '';
    const tableEpCount = document.getElementById('tableEndpointCount');
    if (tableEpCount) tableEpCount.innerText = '0 discovered';
    const progEpBadge = document.getElementById('progressEndpointsBadge');
    if (progEpBadge) progEpBadge.innerText = 'Endpoints: 0';
    const repBadge = document.getElementById('tabReportReady');
    if (repBadge) repBadge.style.display = 'none';

    document.getElementById('statConfirmed').innerText = '0';
    document.getElementById('statFP').innerText = '0';
    document.getElementById('statCrit').innerText = '0';
    document.getElementById('statHigh').innerText = '0';
    document.getElementById('statMed').innerText = '0';
    document.getElementById('statEndpoints').innerText = '0';
    document.getElementById('tabVulnCount').innerText = '0';

    resetMilestones();
    updateProgressUI(0, 'idle', 'Ready to Scan', 'Enter target URL and launch security assessment.');
  }

  async function startScan() {
    const targetUrl = document.getElementById('targetUrl').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const loginUrl = document.getElementById('loginUrl').value;
    const afterAuthUrl = (document.getElementById('afterAuthUrl') ? document.getElementById('afterAuthUrl').value : '').trim();
    const maxDepth = document.getElementById('maxDepth').value;
    const maxPages = document.getElementById('maxPages').value;
    const maxWorkers = document.getElementById('maxWorkers').value;
    const useBrowser = document.getElementById('useBrowser').value === 'true';

    const selectedDetectors = [];
    document.querySelectorAll('input[name="detector"]:checked').forEach(cb => selectedDetectors.push(cb.value));

    const payload = {
      url: targetUrl,
      username,
      password,
      login_url: loginUrl,
      after_auth_url: afterAuthUrl,
      max_depth: maxDepth,
      max_pages: maxPages,
      max_workers: maxWorkers,
      use_browser: useBrowser,
      detectors: selectedDetectors.length > 0 ? selectedDetectors : null,
      enable_ai: true,
      use_kafka: true
    };

    resetScanUI();
    setRunningUI(true);
    updateProgressUI(5, 'start', 'Starting Scan', 'Target scope initialized...');

    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        switchMainTab('tab-progress');
        startSSE();
      } else {
        alert(data.error || data.message || "Failed to start scan");
        setRunningUI(false);
      }
    } catch(err) {
      alert("Error initiating scan: " + err);
      setRunningUI(false);
    }
  }

  async function stopScan() {
    setRunningUI(false);
    resetScanUI();
    try {
      await fetch('/api/scan/stop', { method: 'POST' });
    } catch(e) {
      console.error(e);
    }
  }

  function setRunningUI(isRunning) {
    const badge = document.getElementById('statusBadge');
    const text = document.getElementById('statusText');
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');

    badge.className = 'status-badge ' + (isRunning ? 'status-running' : 'status-completed');
    text.innerText = isRunning ? 'SCANNING' : 'IDLE';
    startBtn.style.display = isRunning ? 'none' : 'block';
    stopBtn.style.display = isRunning ? 'block' : 'none';
  }

  function resetMilestones() {
    const keys = ['start', 'reachability', 'auth_start', 'auth_completed', 'crawling', 'pentesting', 'ai_verification', 'completed'];
    keys.forEach(k => {
      const el = document.getElementById('step-' + k);
      if (el) {
        el.className = 'milestone-card pending';
        const tag = el.querySelector('.milestone-status-tag');
        if (tag) tag.innerText = 'Pending';
      }
    });
  }

  function updateMilestonesUI(milestonesState) {
    if (!milestonesState) return;
    for (const [k, state] of Object.entries(milestonesState)) {
      const el = document.getElementById('step-' + k);
      if (el) {
        el.className = 'milestone-card ' + state;
        const tag = el.querySelector('.milestone-status-tag');
        if (tag) {
          tag.innerText = state === 'in_progress' ? 'Running' : (state === 'completed' ? 'Done' : 'Pending');
        }
      }
    }
  }

  function updateProgressUI(pct, milestone, title, message) {
    const pctInt = Math.min(100, Math.max(0, parseInt(pct) || 0));
    document.getElementById('progressBarFill').style.width = pctInt + '%';
    document.getElementById('progressHeroPct').innerText = pctInt + '%';
    document.getElementById('tabProgressPct').innerText = pctInt + '%';
    if (title || message) {
      document.getElementById('progressCurrentStatus').innerText = (title ? title + ': ' : '') + (message || '');
      document.getElementById('progressStepName').innerText = 'Stage: ' + (title || milestone);
    }
  }

  function addTerminalLog(ts, title, msg) {
    const logs = document.getElementById('terminalLogs');
    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `<span class="log-ts">[${ts}]</span> <span class="log-title">${title}:</span> <span class="log-msg">${msg}</span>`;
    logs.appendChild(line);
    logs.scrollTop = logs.scrollHeight;
    document.getElementById('logCount').innerText = logs.children.length + ' events';
  }

  function addEndpointToTable(ep) {
    const tbody = document.getElementById('endpointsTableBody');
    if (tbody.children.length === 1 && tbody.children[0].innerText.includes('No endpoints')) {
      tbody.innerHTML = '';
    }
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge" style="background:#1e293b; color:#38bdf8;">${ep.method || 'GET'}</span></td>
      <td><code style="color:#f8fafc; font-size:11px;">${ep.url}</code></td>
      <td style="color:#94a3b8;">${(ep.params || []).length} param(s)</td>
    `;
    tbody.appendChild(tr);
    document.getElementById('tableEndpointCount').innerText = tbody.children.length + ' discovered';
    document.getElementById('progressEndpointsBadge').innerText = 'Endpoints: ' + tbody.children.length;
  }

  function startSSE() {
    if (sseSource) sseSource.close();
    sseSource = new EventSource('/api/stream');

    sseSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'status') {
          if (payload.data.status === 'running') {
            setRunningUI(true);
          } else if (payload.data.status === 'stopped' || payload.data.status === 'idle') {
            setRunningUI(false);
            resetScanUI();
          } else if (payload.data.status === 'completed') {
            setRunningUI(false);
          }
        } else if (payload.type === 'progress_milestone') {
          const d = payload.data;
          updateProgressUI(d.percent, d.milestone, d.title, d.message);
          updateMilestonesUI(d.milestones_state);
          addTerminalLog(d.timestamp || new Date().toLocaleTimeString(), d.title, d.message);
        } else if (payload.type === 'endpoint_discovered') {
          addEndpointToTable(payload.data);
          if (payload.data.stats) {
            document.getElementById('statEndpoints').innerText = payload.data.stats.endpoints_crawled || 0;
          }
        } else if (payload.type === 'finding_discovered') {
          const item = payload.data;
          const exists = allFindings.some(f => f.title === item.title && f.url === item.url && f.parameter === item.parameter);
          if (!exists) {
            allFindings.unshift(item);
            updateMetrics();
            renderFindings();
            addTerminalLog(new Date().toLocaleTimeString(), '🚨 Vulnerability Discovered', `${item.title} [${item.severity}] on ${item.url}`);
          }
        } else if (payload.type === 'completed') {
          setRunningUI(false);
          updateProgressUI(100, 'completed', 'Scan Completed', 'Reports ready.');
          document.getElementById('tabReportReady').style.display = 'inline-block';
          pollStatus();
        }
      } catch(e) {
        console.error(e);
      }
    };
  }

  async function pollStatus() {
    try {
      const res = await fetch('/api/scan/status');
      const data = await res.json();
      if (data.status === 'running') {
        setRunningUI(true);
      } else if (data.status === 'completed') {
        setRunningUI(false);
        document.getElementById('tabReportReady').style.display = 'inline-block';
      } else if (data.status === 'stopped' || data.status === 'idle') {
        setRunningUI(false);
      }

      if (data.progress_percent !== undefined) {
        updateProgressUI(data.progress_percent, data.current_milestone, '', '');
      }
      if (data.milestones_state) {
        updateMilestonesUI(data.milestones_state);
      }
      if (data.findings) {
        allFindings = data.findings;
        document.getElementById('tabVulnCount').innerText = allFindings.length;
      }
      if (data.stats) {
        document.getElementById('statEndpoints').innerText = data.stats.endpoints_crawled || 0;
      }
      if (data.endpoints && data.endpoints.length > 0) {
        const tbody = document.getElementById('endpointsTableBody');
        tbody.innerHTML = '';
        data.endpoints.forEach(ep => addEndpointToTable(ep));
      } else if (data.status === 'idle' || data.status === 'stopped') {
        if (!data.endpoints || data.endpoints.length === 0) {
          const tbody = document.getElementById('endpointsTableBody');
          if (tbody && (!tbody.children.length || !tbody.children[0].innerText.includes('No endpoints'))) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 32px;">No endpoints discovered yet.</td></tr>';
          }
        }
      }
      if (data.auth_screenshots && data.auth_screenshots.length > 0) {
        renderAuthScreenshots(data.auth_screenshots);
      } else if (!data.auth_screenshots || data.auth_screenshots.length === 0) {
        const sec = document.getElementById('authScreenshotsSection');
        if (sec) sec.style.display = 'none';
      }
      updateMetrics();
      renderFindings();
    } catch(e) {}
  }

  function renderAuthScreenshots(shots) {
    const sec = document.getElementById('authScreenshotsSection');
    const grid = document.getElementById('authScreenshotsGrid');
    const count = document.getElementById('authScreenshotCount');
    if (!shots || shots.length === 0) {
      sec.style.display = 'none';
      return;
    }
    sec.style.display = 'block';
    count.innerText = shots.length + ' step(s) captured';
    grid.innerHTML = '';
    shots.forEach((shotUrl, idx) => {
      let label = `Step ${idx + 1}`;
      if (shotUrl.includes('step-1')) label = 'Step 1: Login Page Loaded';
      else if (shotUrl.includes('step-2')) label = 'Step 2: Credentials Filled';
      else if (shotUrl.includes('step-3')) label = 'Step 3: Authenticated Landing Page';

      const card = document.createElement('div');
      card.style.background = '#090d16';
      card.style.border = '1px solid #1e293b';
      card.style.borderRadius = '8px';
      card.style.overflow = 'hidden';
      card.style.cursor = 'pointer';
      card.onclick = () => openModal(shotUrl);

      card.innerHTML = `
        <div style="padding: 6px 10px; font-size: 11px; font-weight: 700; color: #38bdf8; background: #0e1726; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between;">
          <span>${label}</span>
          <span style="font-size: 10px; color: #94a3b8;">Click to expand</span>
        </div>
        <img src="${shotUrl}" alt="${label}" style="width: 100%; height: 160px; object-fit: cover; display: block; transition: transform 0.2s;" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'" />
      `;
      grid.appendChild(card);
    });
  }

  function isFPFinding(f) {
    return Boolean(f && (f.is_false_positive === true || f.is_false_positive === 'true' || f.ai_validation_status === 'FALSE_POSITIVE'));
  }

  function updateMetrics() {
    const confirmed = allFindings.filter(f => !isFPFinding(f)).length;
    const fp = allFindings.filter(f => isFPFinding(f)).length;
    const total = allFindings.length;
    const crit = allFindings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL' && !isFPFinding(f)).length;
    const high = allFindings.filter(f => (f.severity || '').toUpperCase() === 'HIGH' && !isFPFinding(f)).length;
    const med = allFindings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM' && !isFPFinding(f)).length;

    const elConf = document.getElementById('statConfirmed');
    if (elConf) elConf.innerText = confirmed;
    const elFp = document.getElementById('statFP');
    if (elFp) elFp.innerText = fp;
    const elCrit = document.getElementById('statCrit');
    if (elCrit) elCrit.innerText = crit;
    const elHigh = document.getElementById('statHigh');
    if (elHigh) elHigh.innerText = high;
    const elMed = document.getElementById('statMed');
    if (elMed) elMed.innerText = med;
    const elVuln = document.getElementById('tabVulnCount');
    if (elVuln) elVuln.innerText = confirmed;

    const btnConf = document.getElementById('btnFilterConfirmed');
    if (btnConf) btnConf.innerText = confirmed;
    const btnAll = document.getElementById('btnFilterAll');
    if (btnAll) btnAll.innerText = total;
    const btnFp = document.getElementById('btnFilterFP');
    if (btnFp) btnFp.innerText = fp;
  }

  function filterCategory(cat) {
    currentFilter = cat;
    document.querySelectorAll('.tab-btn[data-filter]').forEach(btn => {
      if (btn.getAttribute('data-filter') === cat) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
    renderFindings();
  }

  function filterFindingsUI() {
    renderFindings();
  }

  function renderFindings() {
    const container = document.getElementById('findingsList');
    if (!container) return;
    const search = (document.getElementById('searchBox') ? document.getElementById('searchBox').value || '' : '').toLowerCase().trim();

    let list = allFindings.filter(f => {
      const isFp = isFPFinding(f);
      if (currentFilter === 'CONFIRMED' && isFp) return false;
      if (currentFilter === 'FALSE_POSITIVE' && !isFp) return false;
      if (search) {
        const text = ((f.title || '') + ' ' + (f.url || '') + ' ' + (f.parameter || '') + ' ' + (f.detector_name || '')).toLowerCase();
        if (!text.includes(search)) return false;
      }
      return true;
    });

    if (list.length === 0) {
      let emptyMsg = 'No matching findings for active filter.';
      if (currentFilter === 'CONFIRMED' && allFindings.length === 0) {
        emptyMsg = 'No assessment findings recorded. Start a scan to discover vulnerabilities.';
      } else if (currentFilter === 'FALSE_POSITIVE' && allFindings.filter(f => isFPFinding(f)).length === 0) {
        emptyMsg = 'Zero false positives identified &mdash; all discovered vulnerabilities are confirmed true positives!';
      }
      container.innerHTML = `<div style="text-align: center; padding: 48px; background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border); color: var(--text-muted);">${emptyMsg}</div>`;
      return;
    }

    container.innerHTML = list.map((f, idx) => {
      const sevClass = 'badge-' + (f.severity || 'low').toLowerCase();
      const isFp = isFPFinding(f);
      const fpBadge = isFp 
        ? `<span class="badge badge-fp">⚠️ AI: False Positive</span>` 
        : `<span class="badge badge-confirmed">✓ AI: Confirmed</span>`;

      let screenshotHtml = '';
      if (f.screenshot_path) {
        screenshotHtml = `
          <div style="margin-top: 14px;">
            <span style="font-size: 11px; font-weight: 700; color: var(--accent);">📸 Visual Screenshot Proof:</span>
            <div class="screenshot-preview" onclick="openModal('${f.screenshot_path}')">
              <img src="${f.screenshot_path}" alt="Exploit Proof Screenshot">
            </div>
          </div>`;
      }

      return `
        <div class="finding-item" style="${f.is_false_positive ? 'border-left: 4px solid #f97316;' : ''}">
          <div class="finding-header" onclick="toggleDetails('finding-${idx}')">
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
              <span class="badge ${sevClass}">${f.severity}</span>
              <span class="badge" style="background:#1e293b; color:#94a3b8;">${f.detector_name}</span>
              ${fpBadge}
              <strong>${f.title}</strong>
            </div>
            <span style="font-size: 12px; color: var(--text-muted);">&#9662;</span>
          </div>
          <div id="finding-${idx}" class="finding-body">
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;"><strong>Affected Target:</strong> <code>${f.method} ${f.url}</code> ${f.parameter ? `(Param: <code>${f.parameter}</code>)` : ''}</p>
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">${f.description}</p>
            
            <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); margin-top: 12px;">Technical Evidence:</div>
            <div class="evidence-box">${f.evidence || 'N/A'}</div>

            ${f.ai_validation_reasoning ? `
              <div style="margin-top: 12px; background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 10px; font-size: 12px; color: #bae6fd;">
                <strong>🤖 AI Validator Rationale:</strong> ${f.ai_validation_reasoning}
              </div>
            ` : ''}

            ${screenshotHtml}
          </div>
        </div>
      `;
    }).join('');
  }

  function toggleDetails(id) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('open');
  }

  function openModal(imgSrc) {
    document.getElementById('modalImg').src = imgSrc;
    document.getElementById('lightboxModal').classList.add('open');
  }

  function closeModal() {
    document.getElementById('lightboxModal').classList.remove('open');
  }

  async function copyReportJsonToClipboard() {
    try {
      const res = await fetch('/api/reports/json');
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      alert('Report JSON copied to clipboard!');
    } catch(e) {
      alert('Failed to copy JSON: ' + e);
    }
  }

  window.onload = () => {
    loadDetectors();
    pollStatus();
    startSSE();
    setInterval(pollStatus, 2000);
  };
</script>
</body>
</html>
"""


def create_app() -> Flask:
    """Initialize and configure Flask GUI web application."""
    app = Flask(__name__)

    @app.route("/")
    def index() -> str:
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/detectors", methods=["GET"])
    def get_detectors() -> Response:
        from dast.detectors.registry import default_registry
        default_registry.discover_builtin()
        dets = []
        for name in default_registry.list_available():
            cls = default_registry.get_class(name)
            if cls:
                cat = cls.category.value if hasattr(cls.category, "value") else str(cls.category)
                dets.append({
                    "name": cls.name,
                    "category": cat,
                    "description": cls.description,
                })
        return jsonify(dets)

    @app.route("/api/scan/start", methods=["POST"])
    def start_scan_endpoint() -> Response:
        data = request.get_json() or {}
        ok, msg = scan_manager.start_scan(data)
        if not ok:
            return jsonify({"success": False, "error": msg}), 400
        return jsonify({"success": True, "message": msg})

    @app.route("/api/scan/stop", methods=["POST"])
    def stop_scan_endpoint() -> Response:
        ok, msg = scan_manager.stop_scan()
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/scan/status", methods=["GET"])
    def scan_status_endpoint() -> Response:
        findings_json = []
        auth_screenshots = []
        if scan_manager.scan_result:
            for f in scan_manager.scan_result.findings:
                findings_json.append(f.model_dump(mode="json"))
            auth_screenshots = list(scan_manager.scan_result.auth_screenshots or [])
        else:
            findings_json = scan_manager.current_findings
            if Path("evidence/screenshots/auth").exists():
                auth_screenshots = [f"/evidence/screenshots/auth/{p.name}" for p in sorted(Path("evidence/screenshots/auth").glob("*.png"))]

        return jsonify({
            "status": scan_manager.status,
            "error": scan_manager.error_message,
            "stats": scan_manager.stats,
            "findings": findings_json,
            "endpoints": scan_manager.current_endpoints,
            "auth_screenshots": auth_screenshots,
            "progress_percent": scan_manager.progress_percent,
            "current_milestone": scan_manager.current_milestone,
            "milestones_state": scan_manager.milestones_state,
            "activity_log": scan_manager.activity_log[-50:],
        })

    @app.route("/api/reports/html", methods=["GET"])
    def get_html_report() -> Response:
        p = Path("dast-report.html")
        if p.exists():
            return send_file(str(p.resolve()), mimetype="text/html")
        return jsonify({"error": "Report not generated yet"}), 404

    @app.route("/api/reports/json", methods=["GET"])
    def get_json_report() -> Response:
        p = Path("dast-report.json")
        if p.exists():
            return send_file(str(p.resolve()), mimetype="application/json")
        return jsonify({"error": "Report not generated yet"}), 404

    @app.route("/api/reports/markdown", methods=["GET"])
    def get_markdown_report() -> Response:
        p = Path("dast-report.md")
        if p.exists():
            return send_file(str(p.resolve()), mimetype="text/markdown")
        return jsonify({"error": "Report not generated yet"}), 404

    @app.route("/api/reports/pdf", methods=["GET"])
    def get_pdf_report() -> Response:
        p = Path("dast-report.pdf")
        if p.exists():
            return send_file(str(p.resolve()), mimetype="application/pdf")
        if scan_manager.scan_result:
            try:
                out_path = PDFReporter.save(scan_manager.scan_result, "dast-report.pdf")
                if out_path.exists():
                    return send_file(str(out_path.resolve()), mimetype="application/pdf")
            except Exception as e:
                logger.error("Error generating on-demand PDF report: %s", e)
        return jsonify({"error": "PDF report not generated yet"}), 404

    @app.route("/evidence/screenshots/<path:filename>")
    def serve_screenshot(filename: str) -> Response:
        p = Path("evidence/screenshots") / filename
        if p.exists() and p.is_file():
            return send_file(str(p.resolve()))
        return jsonify({"error": "Screenshot not found"}), 404

    @app.route("/api/stream")
    def sse_stream() -> Response:
        q = scan_manager.subscribe()

        def event_generator():
            try:
                # Send initial state
                init_event = json.dumps({"type": "status", "data": {"status": scan_manager.status}})
                yield f"data: {init_event}\n\n"

                while True:
                    try:
                        msg = q.get(timeout=20)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except queue.Empty:
                        # Keep-alive heartbeat ping
                        yield ": keepalive\n\n"
            finally:
                scan_manager.unsubscribe(q)

        return Response(event_generator(), mimetype="text/event-stream")

    return app


def launch_gui(host: str = "127.0.0.1", port: int = 5000, open_browser: bool = True) -> None:
    """Start local GUI dashboard web server."""
    app = create_app()
    url = f"http://{host}:{port}"
    logger.info("Starting DAST Security Auditor GUI at: %s", url)

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    launch_gui()
