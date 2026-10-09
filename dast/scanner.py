"""DAST Orchestration Engine.

Coordinates crawling, endpoint discovery, detector dispatch, and result aggregation
without embedding any vulnerability-specific logic into the orchestrator.
"""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
import threading
import time
from typing import Any, Sequence

import httpx

from dast.crawler import Crawler
from dast.detectors.registry import DetectorRegistry, default_registry
from dast.http_client import HTTPClient
from dast.models import Endpoint, Finding, ScanResult, Target

logger = logging.getLogger(__name__)


def _audit_detector_on_endpoint(
    detector: Any,
    endpoint: Endpoint,
    endpoint_idx: int,
    client: HTTPClient,
    browser_ctx: Any,
    form_handler: Any,
    get_pages_fn: Any,
    stop_event: threading.Event | None = None,
) -> tuple[str, float, list[Finding], Endpoint, int]:
    """Execute single detector scan on an endpoint with timing and error isolation."""
    if stop_event and stop_event.is_set():
        return (getattr(detector, "name", "unknown"), 0.0, [], endpoint, endpoint_idx)
    t_start = time.time()
    try:
        findings = detector.scan(
            endpoint,
            client,
            browser=browser_ctx,
            form_handler=form_handler,
            pages=get_pages_fn(),
        )
    except TypeError:
        try:
            findings = detector.scan(endpoint, client, browser=browser_ctx)
        except TypeError:
            findings = detector.scan(endpoint, client)
    except Exception as exc:
        logger.error(
            "Detector '%s' failed on endpoint %s: %s",
            detector.name,
            endpoint.url,
            exc,
            exc_info=True,
        )
        findings = []

    det_duration = time.time() - t_start
    return detector.name, det_duration, findings, endpoint, endpoint_idx


class Scanner:
    """Central orchestrator for end-to-end security audits."""

    def __init__(
        self,
        target: Target,
        registry: DetectorRegistry | None = None,
        selected_detectors: Sequence[str] | None = None,
        categories: Sequence[str] | None = None,
        timeout: float = 10.0,
        delay: float = 0.0,
        verify_ssl: bool = True,
        transport: httpx.BaseTransport | None = None,
        enable_browser: bool = False,
        browser_dir: str = "evidence/screenshots",
        requirements: Sequence[str] | None = None,
        enable_ai_validation: bool = True,
        gemini_api_key: str | None = None,
        gemini_model: str | None = None,
        use_kafka: bool = True,
        kafka_bootstrap_servers: str | None = None,
        kafka_topic: str | None = None,
        kafka_group_id: str | None = None,
        max_workers: int = 5,
        on_endpoint_discovered: Any | None = None,
        on_finding_discovered: Any | None = None,
        on_progress: Any | None = None,
    ) -> None:
        self.target = target
        self.registry = registry or default_registry
        self.selected_detectors = list(selected_detectors) if selected_detectors else None
        self.categories = list(categories) if categories else None
        self.requirements = list(requirements) if requirements else None
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.transport = transport
        self.enable_browser = enable_browser
        self.browser_dir = browser_dir
        self.enable_ai_validation = enable_ai_validation
        self.gemini_api_key = gemini_api_key
        self.gemini_model = gemini_model
        self.use_kafka = use_kafka
        self.kafka_bootstrap_servers = kafka_bootstrap_servers
        self.kafka_topic = kafka_topic
        self.kafka_group_id = kafka_group_id
        self.max_workers = max(1, max_workers)
        self.on_endpoint_discovered = on_endpoint_discovered
        self.on_finding_discovered = on_finding_discovered
        self.on_progress = on_progress
        self.stop_event = threading.Event()

        # Auto-discover built-in plugins if registry is unpopulated
        if not self.registry.list_available():
            self.registry.discover_builtin()

    def stop(self) -> None:
        """Signal scanner and crawler to stop immediately."""
        logger.info("Stop requested on Scanner.")
        self.stop_event.set()

    def emit_progress(self, milestone: str, title: str, message: str, percent: int, extra: dict[str, Any] | None = None) -> None:
        """Broadcast structured milestone progress update."""
        if self.on_progress:
            try:
                self.on_progress(milestone, title, message, percent, extra or {})
            except Exception:
                pass

    def run(self) -> ScanResult:
        """Execute scoped scan across all discovered endpoints."""
        logger.info("Initializing scan for target: %s", self.target.url)
        self.emit_progress(
            "start",
            "Starting Scan",
            f"Target scope initialized for {self.target.url}. Checking pre-flight reachability...",
            5,
            {"url": self.target.url},
        )

        # 1. Pre-flight reachability check with curl (-u credentials if provided)
        from dast.reachability import check_reachability_with_curl, configure_authentication

        is_reachable, status_code, reachability_msg = check_reachability_with_curl(
            url=self.target.url,
            auth=self.target.auth,
            custom_headers=self.target.custom_headers,
            timeout=self.timeout,
        )
        if not is_reachable:
            logger.warning("[REACHABILITY] Pre-flight reachability warning: %s", reachability_msg)
            self.emit_progress(
                "reachability",
                "Pre-Flight Reachability",
                f"Reachability warning: {reachability_msg}",
                10,
                {"reachable": False, "status_code": status_code},
            )
        else:
            self.emit_progress(
                "reachability",
                "Pre-Flight Reachability",
                f"Target is reachable (Status: {status_code or 200}).",
                12,
                {"reachable": True, "status_code": status_code},
            )

        from dast.models import DetectorRequirement, EvidenceType

        active_detectors = self.registry.get_instances(
            selected_names=self.selected_detectors,
            categories=self.categories,
            requirements=self.requirements,
        )
        active_names = [d.name for d in active_detectors]
        logger.info("Active detector plugins: %s", active_names)

        scan_result = ScanResult(
            target=self.target,
            active_detectors=active_names,
        )

        from dast.browser import BrowserManager

        should_enable_browser = self.enable_browser or any(
            getattr(d, "requirement", None) == DetectorRequirement.BROWSER
            for d in active_detectors
        )

        browser_http_creds = None
        if self.target.auth and len(self.target.auth) == 2 and self.target.auth[0]:
            browser_http_creds = {"username": self.target.auth[0], "password": self.target.auth[1]}

        browser_ctx = (
            BrowserManager(
                output_dir=self.browser_dir,
                timeout=self.timeout,
                custom_headers=self.target.custom_headers,
                base_url=self.target.url,
                http_credentials=browser_http_creds,
            )
            if should_enable_browser
            else None
        )

        with HTTPClient(
            timeout=self.timeout,
            delay=self.delay,
            verify_ssl=self.verify_ssl,
            default_headers=self.target.custom_headers,
            transport=self.transport,
            auth=self.target.auth,
        ) as client:
            # Clear stale auth screenshots before starting new authentication
            auth_dir = Path(self.browser_dir) / "auth"
            if auth_dir.exists():
                for old_f in auth_dir.glob("*.png"):
                    try:
                        old_f.unlink()
                    except Exception:
                        pass

            # Configure and verify authentication
            self.emit_progress(
                "auth_start",
                "Starting Authentication",
                "Initiating browser UI and session authentication...",
                15,
            )
            is_auth, landing_url = configure_authentication(self.target, client=client, browser=browser_ctx)
            if browser_ctx and auth_dir.exists():
                raw_imgs = sorted([str(p.resolve()) for p in auth_dir.glob("*.png")])
                step1 = next((p for p in raw_imgs if "step-1" in p), None)
                step2 = next((p for p in raw_imgs if "step-2" in p), None)
                step3 = next((p for p in raw_imgs if "step-3" in p), None)
                first_time_auth = [p for p in [step1, step2, step3] if p] or raw_imgs[:3]
                scan_result.auth_screenshots = first_time_auth

            if is_auth:
                self.emit_progress(
                    "auth_completed",
                    "Authentication Completed & Success",
                    f"Authentication successful! Landed on: {landing_url or self.target.url}",
                    25,
                    {"landing_url": landing_url, "authenticated": True, "auth_screenshots": scan_result.auth_screenshots},
                )
            else:
                self.emit_progress(
                    "auth_completed",
                    "Authentication Status",
                    "Proceeding with unauthenticated / public assessment scope.",
                    25,
                    {"landing_url": landing_url, "authenticated": False, "auth_screenshots": scan_result.auth_screenshots},
                )

            if browser_ctx:
                browser_ctx.start()

            from dast.kafka_stream import KafkaEndpointStream
            import threading

            stream = KafkaEndpointStream(
                bootstrap_servers=self.kafka_bootstrap_servers,
                topic=self.kafka_topic or "dast-discovered-urls",
                group_id=self.kafka_group_id or "dast-scanner-workers",
                use_kafka=self.use_kafka,
            )

            try:
                # 2. Scope crawl and endpoint discovery
                self.emit_progress(
                    "crawling",
                    "Crawling & Endpoint Discovery",
                    f"Starting web spider (depth: {self.target.max_depth}, max pages: {self.target.max_pages})...",
                    35,
                )
                logger.info("Starting crawler (max_depth=%d, max_pages=%d)...", self.target.max_depth, self.target.max_pages)
                seed_urls = [landing_url] if (is_auth and landing_url and landing_url != self.target.url) else None
                if seed_urls:
                    logger.info("[CRAWLER] Adding authenticated landing page to crawl seeds: %s", landing_url)
                crawler = Crawler(target=self.target, client=client, seed_urls=seed_urls, stream=stream)
                crawler.stop_event = self.stop_event

                # Execute crawler concurrently in background thread; endpoints stream to Kafka / queue
                crawler_thread = threading.Thread(target=crawler.crawl, daemon=True, name="CrawlerThread")
                crawler_thread.start()

                from dast.form_handler import FormHandler
                form_handler = FormHandler(client=client, browser=browser_ctx)

                # 3. Stream-driven parallel detector execution: audit endpoints in real-time as crawler finds them
                all_findings: list[Finding] = []
                detector_timings: dict[str, float] = {}
                processed_endpoints: list[Endpoint] = []
                idx = 0

                if self.max_workers > 1:
                    logger.info(
                        "Starting parallel detector execution pool (%d worker threads) on Kafka stream topic '%s'...",
                        self.max_workers,
                        stream.topic,
                    )
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
                    futures: list[concurrent.futures.Future[Any]] = []
                    try:
                        for endpoint in stream.consume_endpoints(stop_event=self.stop_event):
                            if self.stop_event.is_set():
                                logger.info("Scanner stop signal detected during endpoint dispatch.")
                                break
                            idx += 1
                            processed_endpoints.append(endpoint)
                            param_count = len(endpoint.get_all_param_names())
                            if self.on_endpoint_discovered:
                                try:
                                    self.on_endpoint_discovered(endpoint, idx)
                                except Exception:
                                    pass
                            self.emit_progress(
                                "pentesting",
                                "Vulnerability Pentesting",
                                f"Auditing endpoint [{idx}] {endpoint.url} with {len(active_detectors)} detector(s)...",
                                min(85, 40 + int(idx * 5)),
                                {"endpoint": endpoint.url, "index": idx, "detectors": len(active_detectors)},
                            )
                            logger.info(
                                "[%d] Dispatched %s (%d parameter(s)) across %d detector plugin(s) to parallel workers",
                                idx,
                                endpoint.url,
                                param_count,
                                len(active_detectors),
                            )
                            for detector in active_detectors:
                                if self.stop_event.is_set():
                                    break
                                fut = executor.submit(
                                    _audit_detector_on_endpoint,
                                    detector,
                                    endpoint,
                                    idx,
                                    client,
                                    browser_ctx,
                                    form_handler,
                                    crawler.get_pages,
                                    self.stop_event,
                                )
                                futures.append(fut)
                            if self.stop_event.is_set():
                                break

                        # Collect and process detector results as they complete concurrently
                        for fut in concurrent.futures.as_completed(futures):
                            if self.stop_event.is_set():
                                break
                            det_name, det_duration, findings, ep, ep_idx = fut.result()
                            detector_timings[det_name] = detector_timings.get(det_name, 0.0) + det_duration

                            if findings:
                                all_findings.extend(findings)
                                for f in findings:
                                    if self.on_finding_discovered:
                                        try:
                                            self.on_finding_discovered(f)
                                        except Exception:
                                            pass
                                    sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                                    logger.info(
                                        "    🚨 Vulnerability Found: %s [%s] in parameter '%s' on %s",
                                        f.title,
                                        sev_str,
                                        f.parameter or "N/A",
                                        ep.url,
                                    )

                            logger.info(
                                "  ✓ Finished %s on %s in %.2fs (%d finding(s))",
                                det_name,
                                ep.url,
                                det_duration,
                                len(findings),
                            )
                    finally:
                        if self.stop_event.is_set():
                            for fut in futures:
                                fut.cancel()
                            executor.shutdown(wait=False, cancel_futures=True)
                        else:
                            executor.shutdown(wait=True)
                else:
                    # Sequential execution mode (max_workers=1)
                    for endpoint in stream.consume_endpoints(stop_event=self.stop_event):
                        if self.stop_event.is_set():
                            break
                        idx += 1
                        processed_endpoints.append(endpoint)
                        param_count = len(endpoint.get_all_param_names())
                        if self.on_endpoint_discovered:
                            try:
                                self.on_endpoint_discovered(endpoint, idx)
                            except Exception:
                                pass
                        self.emit_progress(
                            "pentesting",
                            "Vulnerability Pentesting",
                            f"Auditing endpoint [{idx}] {endpoint.url} with {len(active_detectors)} detector(s)...",
                            min(85, 40 + int(idx * 5)),
                            {"endpoint": endpoint.url, "index": idx, "detectors": len(active_detectors)},
                        )
                        logger.info(
                            "[%d] Auditing %s (%d parameter(s))",
                            idx,
                            endpoint.url,
                            param_count,
                        )
                        for detector in active_detectors:
                            if self.stop_event.is_set():
                                break
                            logger.info("  ▶ Started detector: %s", detector.name)
                            det_name, det_duration, findings, ep, ep_idx = _audit_detector_on_endpoint(
                                detector,
                                endpoint,
                                idx,
                                client,
                                browser_ctx,
                                form_handler,
                                crawler.get_pages,
                                self.stop_event,
                            )
                            detector_timings[det_name] = detector_timings.get(det_name, 0.0) + det_duration

                            if findings:
                                all_findings.extend(findings)
                                for f in findings:
                                    if self.on_finding_discovered:
                                        try:
                                            self.on_finding_discovered(f)
                                        except Exception:
                                            pass
                                    sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                                    logger.info(
                                        "    🚨 Vulnerability Found: %s [%s] in parameter '%s'",
                                        f.title,
                                        sev_str,
                                        f.parameter or "N/A",
                                    )

                            logger.info(
                                "  ✓ Finished %s in %.2fs (%d finding(s) on endpoint)",
                                detector.name,
                                det_duration,
                                len(findings),
                            )

                crawler_thread.join(timeout=1.0 if self.stop_event.is_set() else 30)
                scan_result.scanned_endpoints = processed_endpoints or list(crawler._discovered_endpoints.values())
                scan_result.scanned_pages = crawler.get_pages()
                scan_result.findings = all_findings
                logger.info(
                    "Completed streaming audit of %d endpoints across %d pages",
                    len(scan_result.scanned_endpoints),
                    len(scan_result.scanned_pages),
                )
            finally:
                if browser_ctx:
                    browser_ctx.close()
                stream.close()

        if self.stop_event.is_set():
            logger.info("Scan stopped by user. Finalizing partial findings.")
            scan_result.finalize()
            return scan_result

        # 3. AI-assisted False-Positive Validation using Google Gemini
        if self.enable_ai_validation and scan_result.findings:
            self.emit_progress(
                "ai_verification",
                "AI Verification & Confirmation",
                f"Evaluating {len(scan_result.findings)} finding(s) with Google Gemini AI...",
                90,
            )
            from dast.validator import GeminiFindingValidator

            validator = GeminiFindingValidator(
                api_key=self.gemini_api_key,
                model=self.gemini_model,
                transport=self.transport,
            )
            validator.validate_findings(scan_result.findings)

        scan_result.finalize()
        scan_result.summary["detector_timings"] = {
            name: round(secs, 2) for name, secs in detector_timings.items()
        }
        confirmed_count = scan_result.summary.get("confirmed_findings", len(scan_result.findings))
        fp_count = scan_result.summary.get("false_positives", 0)
        self.emit_progress(
            "completed",
            "Scan Completed",
            f"Audit finished in {scan_result.duration_seconds:.2f}s. {len(scan_result.findings)} finding(s) found ({confirmed_count} confirmed, {fp_count} false positives).",
            100,
            {
                "duration": f"{scan_result.duration_seconds:.2f}s",
                "total_findings": len(scan_result.findings),
                "confirmed": confirmed_count,
                "false_positives": fp_count,
            },
        )
        logger.info(
            "Scan completed in %.2fs. Total findings: %d (Confirmed: %d, False Positives: %d)",
            scan_result.duration_seconds,
            len(scan_result.findings),
            confirmed_count,
            fp_count,
        )
        return scan_result
