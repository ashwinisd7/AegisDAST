"""Scoped crawler and endpoint discovery engine.

Traverses web resources within target boundary, extracting URLs, query parameters,
HTML forms into standardized Endpoint and PageModel objects.
"""

from __future__ import annotations

from collections import deque
import logging
from typing import TYPE_CHECKING, Any, Sequence
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from dast.http_client import HTTPClient
from dast.models import Endpoint, FormModel, HttpMethod, InputField, PageModel, Resource, ResourceType, Target

if TYPE_CHECKING:
    from dast.kafka_stream import KafkaEndpointStream

logger = logging.getLogger(__name__)


class Crawler:
    """Discovers web endpoints and builds rich PageModel representations."""

    def __init__(
        self,
        target: Target,
        client: HTTPClient,
        seed_urls: Sequence[str] | None = None,
        stream: KafkaEndpointStream | None = None,
    ) -> None:
        self.target = target
        self.client = client
        self.seed_urls = list(seed_urls) if seed_urls else []
        self.stream = stream
        self._visited_urls: set[str] = set()
        self._discovered_endpoints: dict[str, Endpoint] = {}
        self.discovered_pages: dict[str, PageModel] = {}
        self.stop_event: threading.Event | None = None

    @staticmethod
    def normalize_url(url: str) -> str:
        """Strip URL fragments and normalize trailing slashes."""
        parsed = urlparse(url)
        clean_path = parsed.path or "/"
        return urlunparse((parsed.scheme, parsed.netloc, clean_path, parsed.params, parsed.query, ""))

    def get_pages(self) -> list[PageModel]:
        """Return all discovered PageModel instances."""
        return list(self.discovered_pages.values())

    def crawl(self) -> list[Endpoint]:
        """Execute scoped breadth-first crawl and extract endpoints and PageModels."""
        try:
            start_url = self.normalize_url(self.target.url)
            seeds = [start_url]
            if self.seed_urls:
                for s in self.seed_urls:
                    norm_s = self.normalize_url(s)
                    if norm_s not in seeds and self.target.is_in_scope(norm_s):
                        seeds.append(norm_s)

            queue: deque[tuple[str, int]] = deque([(s, 0) for s in seeds])
            queued_urls: set[str] = set(seeds)

            while queue and len(self._visited_urls) < self.target.max_pages:
                if self.stop_event and self.stop_event.is_set():
                    logger.info("Crawler received cancellation signal; stopping crawl.")
                    break

                current_url, depth = queue.popleft()
                if current_url in self._visited_urls:
                    continue
                self._visited_urls.add(current_url)

                if depth > self.target.max_depth:
                    continue

                resp, _, _ = self.client.get(current_url)
                if not resp or resp.status_code >= 400:
                    continue

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    self._register_endpoint_from_url(current_url, content_type=content_type)
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract title
                title = ""
                title_tag = soup.find("title")
                if title_tag and title_tag.string:
                    title = title_tag.string.strip()

                page_links: list[str] = []
                page_resources: list[Resource] = []
                page_forms: list[FormModel] = []

                # 1. Extract HTML forms first so FormModels are fully parsed
                for form in soup.find_all("form"):
                    form_model = self._parse_form_model(form, current_url)
                    if form_model:
                        page_forms.append(form_model)
                    self._extract_form(form, current_url, form_model=form_model)

                # 2. Register/update endpoint for current_url itself with query params and discovered forms
                self._register_page_endpoint(current_url, forms=page_forms, content_type=content_type)

                # 3. Extract hyperlinks & stylesheet resources
                for tag in soup.find_all(["a", "link"], href=True):
                    raw_href = tag.get("href", "").strip()
                    if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue

                    full_url = self.normalize_url(urljoin(current_url, raw_href))
                    if tag.name == "a":
                        page_links.append(full_url)

                    if tag.name == "link":
                        rel = tag.get("rel", [])
                        rel_str = " ".join(rel) if isinstance(rel, list) else str(rel)
                        if "stylesheet" in rel_str.lower() or full_url.endswith(".css"):
                            page_resources.append(
                                Resource(url=full_url, resource_type=ResourceType.CSS, tag="link")
                            )

                    if not self.target.is_in_scope(full_url):
                        continue

                    if full_url not in self._visited_urls and full_url not in queued_urls:
                        queued_urls.add(full_url)
                        queue.append((full_url, depth + 1))

                # 4. Extract scripts (JavaScript)
                for s_tag in soup.find_all("script", src=True):
                    s_src = s_tag.get("src", "").strip()
                    if s_src:
                        full_src = urljoin(current_url, s_src)
                        page_resources.append(
                            Resource(url=full_src, resource_type=ResourceType.JAVASCRIPT, tag="script")
                        )

                # 5. Extract images
                for img_tag in soup.find_all("img", src=True):
                    img_src = img_tag.get("src", "").strip()
                    if img_src and not img_src.startswith("data:"):
                        full_img = urljoin(current_url, img_src)
                        page_resources.append(
                            Resource(url=full_img, resource_type=ResourceType.IMAGE, tag="img")
                        )

                # Construct and record PageModel
                unique_links = list(dict.fromkeys(page_links))
                page = PageModel(
                    url=current_url,
                    status_code=resp.status_code,
                    content_type=content_type,
                    title=title,
                    links=unique_links,
                    forms=page_forms,
                    resources=page_resources,
                )
                self.discovered_pages[current_url] = page

            return list(self._discovered_endpoints.values())
        finally:
            if self.stream:
                self.stream.send_eof()

    def _register_page_endpoint(
        self,
        url: str,
        forms: list[FormModel] | None = None,
        content_type: str | None = None,
    ) -> None:
        """Register or update endpoint for visited page URL with its query params and discovered forms."""
        parsed = urlparse(url)
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        query_dict = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        key = clean_url
        if key not in self._discovered_endpoints:
            ep = Endpoint(
                url=clean_url,
                method=HttpMethod.GET,
                params=query_dict,
                body_params={},
                content_type=content_type,
                forms=list(forms) if forms else [],
            )
            self._discovered_endpoints[key] = ep
            if self.stream:
                self.stream.publish_endpoint(ep)
        else:
            ep = self._discovered_endpoints[key]
            if query_dict:
                ep.params.update(query_dict)
            if content_type and not ep.content_type:
                ep.content_type = content_type
            if forms:
                for f in forms:
                    if f not in ep.forms:
                        ep.forms.append(f)
            if self.stream:
                self.stream.publish_endpoint(ep)

    def _register_endpoint_from_url(self, url: str, content_type: str | None = None) -> None:
        """Parse URL query parameters and record as endpoint."""
        parsed = urlparse(url)
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        query_dict = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        key = clean_url
        if key not in self._discovered_endpoints:
            ep = Endpoint(
                url=clean_url,
                method=HttpMethod.GET,
                params=query_dict,
                body_params={},
                content_type=content_type,
            )
            self._discovered_endpoints[key] = ep
            if self.stream:
                self.stream.publish_endpoint(ep)
        else:
            if query_dict:
                self._discovered_endpoints[key].params.update(query_dict)
            if content_type and not self._discovered_endpoints[key].content_type:
                self._discovered_endpoints[key].content_type = content_type
            if self.stream:
                self.stream.publish_endpoint(self._discovered_endpoints[key])

    def _parse_form_model(self, form: Any, current_url: str) -> FormModel:
        """Parse BeautifulSoup form element into standardized FormModel and InputFields."""
        raw_action = form.get("action", "").strip()
        action_url = self.normalize_url(urljoin(current_url, raw_action)) if raw_action else current_url
        method_str = form.get("method", "GET").strip().upper()

        inputs: list[InputField] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            tag_name = inp.name.lower()
            val = inp.get("value", "")
            placeholder = inp.get("placeholder", "")
            required = inp.has_attr("required")

            if tag_name == "textarea":
                input_type = "textarea"
                if not val and inp.string:
                    val = inp.string.strip()
                options = []
            elif tag_name == "select":
                input_type = "select"
                options = [opt.get("value", opt.text).strip() for opt in inp.find_all("option")]
                if not val and options:
                    val = options[0]
            else:
                input_type = inp.get("type", "text").lower()
                options = []

            inputs.append(
                InputField(
                    name=name,
                    input_type=input_type,
                    placeholder=placeholder,
                    required=required,
                    value=val,
                    options=options,
                )
            )

        return FormModel(
            action=action_url,
            method=method_str,
            inputs=inputs,
        )

    def _extract_form(self, form: Any, current_url: str, form_model: FormModel | None = None) -> None:
        """Parse form inputs and merge into endpoint model."""
        raw_action = form.get("action", "").strip()
        action_url = self.normalize_url(urljoin(current_url, raw_action)) if raw_action else current_url

        if not self.target.is_in_scope(action_url):
            return

        method_str = form.get("method", "GET").strip().upper()
        method = HttpMethod.POST if method_str == "POST" else HttpMethod.GET

        form_fields: dict[str, Any] = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            val = inp.get("value", "test")
            form_fields[name] = val

        parsed = urlparse(action_url)
        clean_action = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        action_query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        key = clean_action
        if key not in self._discovered_endpoints:
            if method == HttpMethod.POST:
                ep = Endpoint(
                    url=clean_action,
                    method=HttpMethod.POST,
                    params=action_query_params,
                    body_params=form_fields,
                    content_type="application/x-www-form-urlencoded",
                    forms=[form_model] if form_model else [],
                )
            else:
                combined_params = dict(action_query_params)
                combined_params.update(form_fields)
                ep = Endpoint(
                    url=clean_action,
                    method=HttpMethod.GET,
                    params=combined_params,
                    body_params={},
                    forms=[form_model] if form_model else [],
                )
            self._discovered_endpoints[key] = ep
            if self.stream:
                self.stream.publish_endpoint(ep)
        else:
            ep = self._discovered_endpoints[key]
            if action_query_params:
                ep.params.update(action_query_params)
            if method == HttpMethod.POST:
                ep.method = HttpMethod.POST
                ep.body_params.update(form_fields)
                ep.content_type = "application/x-www-form-urlencoded"
            else:
                ep.params.update(form_fields)
            if form_model and form_model not in ep.forms:
                ep.forms.append(form_model)
            if self.stream:
                self.stream.publish_endpoint(ep)
