#!/usr/bin/env python3
"""
Signal Forge OSINT - multi-provider research CLI

Confirmed starter integrations:
- Brave Search
- Shodan
- VirusTotal v3
- GreyNoise Community
- Censys Platform API v3
- BuiltWith Domain API
- WhoisXML WHOIS
- DNSDumpster
- SEC EDGAR (no key)

Secrets belong in signalforge.env or environment variables and must not be committed.

v0.3.3 additionally detects BuiltWith application-level errors that may arrive
inside HTTP 200 responses and captures only safe BuiltWith credit/rate-limit
response headers for provenance.

Report filenames use:
    yy-mm-dd_API_operation_target.json

Each JSON report begins with:
    title
    subject
    report_type
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

import requests

APP_NAME = "Signal Forge OSINT"
APP_VERSION = "0.3.3"
CONTACT_EMAIL = "research@signalforgeresearch.com"

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
DEFAULT_LOG_DIR = PROJECT_DIR / "logs"
DEFAULT_OUTPUT_DIR = PROJECT_DIR / "output"
DEFAULT_ENV_FILE = PROJECT_DIR / "signalforge.env"
DEFAULT_TIMEOUT = 30
MAX_RESPONSE_LOG_CHARS = 2500

SENSITIVE_QUERY_KEYS = {
    "key", "apikey", "api_key", "token", "access_token", "password",
    "secret", "authorization", "x-apikey"
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_dotenv_simple(path: Path) -> None:
    """Load simple KEY=VALUE pairs without overwriting existing environment values."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def sanitize_url(url: str) -> str:
    """Redact common credential-bearing query parameters before logging."""
    try:
        parts = urlsplit(url)
        clean = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS:
                value = "[REDACTED]"
            clean.append((key, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(clean), parts.fragment))
    except Exception:
        return "[URL_SANITIZATION_FAILED]"


def safe_filename(value: str, max_len: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value[:max_len] or "result"


def validate_ip(value: str) -> str:
    obj = ipaddress.ip_address(value.strip())
    if not obj.is_global:
        raise ValueError("Please provide a globally routable public IP address.")
    return str(obj)


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].strip(".")
    if not value or "." not in value or " " in value:
        raise ValueError("Please provide a domain such as example.com.")
    return value


def validate_file_hash(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError("File hash must contain hexadecimal characters only.")
    if len(value) not in (32, 40, 64):
        raise ValueError("Expected MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters.")
    return value


def validate_sha256(value: str) -> str:
    value = value.strip().lower().replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Expected a 64-character SHA-256 hexadecimal fingerprint.")
    return value


def normalize_cik(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if not digits:
        raise ValueError("CIK must contain digits.")
    return digits.zfill(10)


def show_examples(title: str, examples: list[str], note: str | None = None) -> None:
    print("\n" + "-" * 72)
    print(title)
    print("-" * 72)
    print("Examples:")
    for example in examples:
        print(f"  {example}")
    if note:
        print("\nNote:")
        print(f"  {note}")
    print("-" * 72)


def prompt_example(prompt_text: str, title: str, examples: list[str], note: str | None = None) -> str:
    show_examples(title, examples, note)
    return input(prompt_text).strip()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pretty(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)



def report_operation(result: "ProviderResult") -> str:
    """
    Return a compact provider-specific operation label.

    This keeps filenames short enough to read comfortably in iOS Files while
    still distinguishing operations such as BuiltWith Free API vs Domain API.
    """
    endpoint = (result.endpoint or "").lower()
    provider = result.provider.lower()
    query_type = (result.query_type or "").lower()

    if "builtwith" in provider:
        if "free1" in endpoint or "free" in provider:
            return "FreeAPI"
        if "/v26/" in endpoint:
            return "DomainAPI"
        if "/rv5/" in endpoint:
            return "Relationships"
        if "/change1/" in endpoint:
            return "Changes"
        if "/ctu4/" in endpoint:
            return "CompanyURL"
        return "Lookup"

    if "brave" in provider:
        if "/news/" in endpoint:
            return "News"
        return "WebSearch"

    if provider == "shodan":
        if "/host/search/filters" in endpoint:
            return "Filters"
        if "/host/search/facets" in endpoint:
            return "Facets"
        if "/host/search/tokens" in endpoint:
            return "QueryTokens"
        if "/host/count" in endpoint:
            return "Count"
        if "/host/search" in endpoint:
            return "Search"
        if "/dns/domain/" in endpoint:
            return "DNSDomain"
        if "/dns/resolve" in endpoint:
            return "DNSResolve"
        if "/dns/reverse" in endpoint:
            return "ReverseDNS"
        if "/shodan/host/" in endpoint:
            return "Host"
        return "Lookup"

    if "virustotal" in provider:
        if "/ip_addresses/" in endpoint:
            return "IP"
        if "/domains/" in endpoint:
            return "Domain"
        if "/urls/" in endpoint:
            return "URL"
        if "/files/" in endpoint:
            return "FileHash"
        return "Lookup"

    if "greynoise" in provider:
        return "CommunityIP"

    if "censys" in provider:
        if "/asset/webproperty/" in endpoint:
            return "WebProperty"
        if "/asset/certificate/" in endpoint:
            return "Certificate"
        if endpoint.rstrip("/").endswith("/asset/host") and query_type == "ip_list":
            return "MultiHost"
        if "/asset/host/" in endpoint:
            return "Host"
        return "Lookup"

    if "whoisxml" in provider:
        if "account-balance" in endpoint:
            return "Balance"
        if query_type == "domain" and result.notes and "availability" in result.notes.lower():
            return "Availability"
        return "WHOIS"

    if "dnsdumpster" in provider:
        if "/banners/" in endpoint:
            return "Banners"
        if result.notes and "map" in result.notes.lower():
            return "DomainMap"
        return "Domain"

    if "sec edgar" in provider:
        if "company_tickers" in endpoint:
            return "CompanySearch"
        if "/submissions/" in endpoint:
            return "Submissions"
        if "/companyfacts/" in endpoint:
            return "CompanyFacts"
        if "/companyconcept/" in endpoint:
            return "CompanyConcept"
        if "/frames/" in endpoint:
            return "Frame"
        return "EDGAR"

    return safe_filename(result.query_type or "Lookup", max_len=20)


def report_provider_label(provider: str) -> str:
    """Compact API/provider label for filenames."""
    mapping = {
        "Brave Search": "Brave",
        "VirusTotal": "VirusTotal",
        "GreyNoise Community": "GreyNoise",
        "BuiltWith Free": "BuiltWith",
        "WhoisXML WHOIS": "WhoisXML",
        "SEC EDGAR": "SEC",
    }
    return mapping.get(provider, provider)


def report_identifier(value: str) -> str:
    """
    Produce the short identifying tail of a JSON filename.

    Domains and IPs remain immediately recognizable. Longer search strings,
    URLs, hashes, and lists are shortened so iOS Files does not hide the useful
    part of the filename.
    """
    value = str(value or "result").strip()

    # Make full URLs easier to read by dropping the scheme.
    value = re.sub(r"^https?://", "", value, flags=re.I)
    value = value.rstrip("/")

    # Keep filenames useful on a narrow phone display.
    return safe_filename(value, max_len=36)


def unique_json_path(directory: Path, stem: str) -> Path:
    """
    Avoid overwriting a report when the same API/query is run more than once
    on the same day. The second copy becomes _02, then _03, etc.
    """
    candidate = directory / f"{stem}.json"
    counter = 2

    while candidate.exists():
        candidate = directory / f"{stem}_{counter:02d}.json"
        counter += 1

    return candidate


def report_title(result: "ProviderResult") -> str:
    provider = report_provider_label(result.provider)
    operation = report_operation(result)
    return f"Signal Forge Research — {provider} {operation} Report"




class SecretRedactionFilter(logging.Filter):
    """
    Redact configured API credentials from every log record, including records
    emitted by third-party HTTP libraries.
    """

    SECRET_ENV_NAMES = (
        "BRAVE_API_KEY",
        "SHODAN_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "GREYNOISE_API_KEY",
        "CENSYS_PAT",
        "CENSYS_ORG_ID",
        "BUILTWITH_API_KEY",
        "WHOISXML_API_KEY",
        "DNSDUMPSTER_API_KEY",
        "OPENCORPORATES_API_KEY",
    )

    def __init__(self) -> None:
        super().__init__()
        self.secrets = [
            os.getenv(name)
            for name in self.SECRET_ENV_NAMES
            if os.getenv(name)
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()

            for secret in self.secrets:
                if secret:
                    message = message.replace(secret, "[REDACTED]")

            message = re.sub(
                r'(?i)([?&](?:key|api_key|apikey|token|access_token|secret)=)[^&\\s\\"]+',
                r'\\1[REDACTED]',
                message,
            )
            message = re.sub(
                r'(?i)(authorization[:=]\\s*(?:bearer|api)?\\s*)[^,\\s\\"]+',
                r'\\1[REDACTED]',
                message,
            )

            record.msg = message
            record.args = ()
        except Exception:
            pass

        return True



def configure_logging(log_dir: Path, verbose: bool = True) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"signal_forge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    redactor = SecretRedactionFilter()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    root.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redactor)
    root.addHandler(console_handler)

    # requests/urllib3 can emit the final request URL at DEBUG level.
    # Some provider URLs contain credentials, so suppress those traces.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    return log_path


@dataclass
class ProviderResult:
    provider: str
    query_type: str
    query_value: str
    endpoint: str
    retrieved_at: str
    http_status: Optional[int]
    success: bool
    response_sha256: Optional[str]
    data: Any
    error: Optional[str] = None
    notes: Optional[str] = None
    provider_metadata: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "query": {"type": self.query_type, "value": self.query_value},
            "source": {
                "endpoint": sanitize_url(self.endpoint),
                "retrieved_at": self.retrieved_at,
                "http_status": self.http_status,
                "response_sha256": self.response_sha256,
            },
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "notes": self.notes,
            "provider_metadata": self.provider_metadata,
        }


def missing_key(provider: str, env_name: str, query_type: str, query_value: str) -> ProviderResult:
    msg = f"{provider} is not configured. Set {env_name} in signalforge.env or the environment."
    logging.warning(msg)
    return ProviderResult(
        provider, query_type, query_value, "not_requested", utc_now(),
        None, False, None, None, msg
    )


class SignalForgeClient:
    def __init__(self, output_dir: Path, subject: str = ""):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Optional human-readable research subject/case label.
        # Examples:
        #   OpenAI public-domain technology profile
        #   Google Public DNS infrastructure test
        #   Signal Forge proof-of-concept — example.com
        #
        # If left blank, each JSON report automatically uses the query target
        # (domain, IP, search text, CIK, etc.) as its subject.
        self.subject = subject.strip()
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": f"{APP_NAME}/{APP_VERSION} ({CONTACT_EMAIL})",
        })

    def _request_json(
        self,
        *,
        provider: str,
        method: str,
        url: str,
        query_type: str,
        query_value: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        notes: Optional[str] = None,
    ) -> ProviderResult:
        retrieved_at = utc_now()

        logging.info("=" * 76)
        logging.info("PROVIDER: %s", provider)
        logging.info("QUERY TYPE: %s", query_type)
        logging.info("QUERY VALUE: %s", query_value)
        logging.info("METHOD: %s", method)
        logging.info("ENDPOINT: %s", sanitize_url(url))

        safe_params = {}
        for k, v in (params or {}).items():
            safe_params[k] = "[REDACTED]" if k.lower() in SENSITIVE_QUERY_KEYS else v
        if safe_params:
            logging.debug("PARAMETERS: %s", safe_params)

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=DEFAULT_TIMEOUT,
            )
            digest = sha256_bytes(response.content)
            logging.info("HTTP STATUS: %s", response.status_code)
            logging.info("RESPONSE BYTES: %s", len(response.content))
            logging.info("RESPONSE SHA-256: %s", digest)

            try:
                data = response.json()
            except ValueError:
                data = {"raw_text": response.text[:10000]}
                logging.warning("Response was not JSON; saved a limited text preview.")

            preview = pretty(data)
            if len(preview) > MAX_RESPONSE_LOG_CHARS:
                preview = preview[:MAX_RESPONSE_LOG_CHARS] + "\n...[preview truncated]..."
            logging.debug("RESPONSE PREVIEW:\n%s", preview)

            if response.status_code == 429:
                logging.warning("Provider rate limit reached.")
            elif response.status_code in (401, 403):
                logging.warning("Authentication/authorization failure; check key and account plan.")
            elif response.status_code >= 500:
                logging.warning("Provider returned a server-side error.")

            # Some APIs return HTTP 200 even when the JSON body reports an
            # application-level failure. BuiltWith does this for conditions
            # such as exhausted/unallocated API credits and invalid lookups.
            application_error = None
            if provider.startswith("BuiltWith") and isinstance(data, dict):
                errors = data.get("Errors")
                if isinstance(errors, list) and errors:
                    parts = []
                    for item in errors:
                        if isinstance(item, dict):
                            code = item.get("Code")
                            message = item.get("Message")
                            if code is not None and message:
                                parts.append(f"BuiltWith {code}: {message}")
                            elif message:
                                parts.append(str(message))
                            else:
                                parts.append(str(item))
                        else:
                            parts.append(str(item))
                    application_error = "; ".join(parts)
                    logging.warning(
                        "BuiltWith application-level error despite HTTP %s: %s",
                        response.status_code,
                        application_error,
                    )

            # Capture only non-secret BuiltWith quota/rate-limit headers.
            # These headers let the report distinguish "no credits allocated"
            # from "credits were consumed" without exposing credentials.
            provider_metadata = None
            if provider.startswith("BuiltWith"):
                safe_header_names = (
                    "X-API-CREDITS-AVAILABLE",
                    "X-API-CREDITS-USED",
                    "X-API-CREDITS-REMAINING",
                    "X-RATELIMIT-CURRENT-CONCURRENT",
                    "X-RATELIMIT-CURRENT-PERSECOND",
                    "X-RATELIMIT-LIMIT-CONCURRENT",
                    "X-RATELIMIT-LIMIT-PERSECOND",
                )
                captured = {
                    name: response.headers.get(name)
                    for name in safe_header_names
                    if response.headers.get(name) is not None
                }
                if captured:
                    provider_metadata = {"response_headers": captured}
                    logging.info("BUILTWITH SAFE ACCOUNT HEADERS: %s", captured)

            effective_success = response.ok and application_error is None
            effective_error = (
                application_error
                if application_error
                else (None if response.ok else f"HTTP {response.status_code}")
            )

            return ProviderResult(
                provider=provider,
                query_type=query_type,
                query_value=query_value,
                endpoint=response.url,
                retrieved_at=retrieved_at,
                http_status=response.status_code,
                success=effective_success,
                response_sha256=digest,
                data=data,
                error=effective_error,
                notes=notes,
                provider_metadata=provider_metadata,
            )

        except requests.Timeout as exc:
            logging.exception("Request timed out.")
            return ProviderResult(provider, query_type, query_value, sanitize_url(url),
                                  retrieved_at, None, False, None, None,
                                  f"Timeout: {exc}", notes)
        except requests.RequestException as exc:
            logging.exception("Network/request error.")
            return ProviderResult(provider, query_type, query_value, sanitize_url(url),
                                  retrieved_at, None, False, None, None,
                                  f"Request error: {exc}", notes)
        except Exception as exc:
            logging.exception("Unexpected provider error.")
            return ProviderResult(provider, query_type, query_value, sanitize_url(url),
                                  retrieved_at, None, False, None, None,
                                  f"Unexpected error: {exc}", notes)

    def save_result(self, result: ProviderResult) -> Path:
        """
        Save one provider result.

        Filename convention:
            yy-mm-dd_API_operation_target.json

        Examples:
            26-09-26_BuiltWith_FreeAPI_example.com.json
            26-09-26_BuiltWith_DomainAPI_example.com.json
            26-09-26_Shodan_Host_8.8.8.8.json

        If the same report is generated again on the same day, Signal Forge
        appends _02, _03, etc. instead of overwriting the earlier report.
        """
        date_stamp = datetime.now().strftime("%y-%m-%d")
        provider_label = safe_filename(
            report_provider_label(result.provider),
            max_len=18,
        )
        operation = safe_filename(report_operation(result), max_len=20)
        identifier = report_identifier(result.query_value)

        stem = f"{date_stamp}_{provider_label}_{operation}_{identifier}"
        path = unique_json_path(self.output_dir, stem)

        # Keep these first fields in this exact order. Python dictionaries
        # preserve insertion order and pretty() deliberately does not sort keys.
        # This makes the first lines useful when previewing JSON on an iPhone.
        payload = {
            "title": report_title(result),
            "subject": self.subject or result.query_value,
            "report_type": (
                f"{report_provider_label(result.provider)} / "
                f"{report_operation(result)}"
            ),
            "generated_at": utc_now(),
            "project": "Signal Forge Research",
            "project_status": "proof-of-concept",
            **result.as_dict(),
        }

        encoded = (pretty(payload) + "\n").encode("utf-8")
        path.write_bytes(encoded)

        logging.info("SAVED RESULT: %s", path)
        logging.info("REPORT TITLE: %s", payload["title"])
        logging.info("SUBJECT: %s", payload["subject"])
        logging.info("REPORT TYPE: %s", payload["report_type"])
        logging.info("FILE SHA-256: %s", sha256_bytes(encoded))

        return path

    def save_bundle(self, name: str, query_type: str, query_value: str,
                    results: list[ProviderResult]) -> Path:
        """
        Save a cross-provider bundle using the same short naming convention.
        """
        date_stamp = datetime.now().strftime("%y-%m-%d")

        bundle_label = {
            "ip_bundle": "IPBundle",
            "domain_bundle": "DomainBundle",
            "public_ip_bundle": "IPBundle",
        }.get(name, safe_filename(name, max_len=22))

        identifier = report_identifier(query_value)
        stem = f"{date_stamp}_SignalForge_{bundle_label}_{identifier}"
        path = unique_json_path(self.output_dir, stem)

        payload = {
            "title": f"Signal Forge Research — {bundle_label} Report",
            "subject": self.subject or query_value,
            "report_type": f"Signal Forge / {bundle_label}",
            "generated_at": utc_now(),
            "project": "Signal Forge Research",
            "project_status": "proof-of-concept",
            "bundle": name,
            "query": {
                "type": query_type,
                "value": query_value,
            },
            "results": [r.as_dict() for r in results],
        }

        encoded = (pretty(payload) + "\n").encode("utf-8")
        path.write_bytes(encoded)

        logging.info("SAVED BUNDLE: %s", path)
        logging.info("REPORT TITLE: %s", payload["title"])
        logging.info("SUBJECT: %s", payload["subject"])
        logging.info("FILE SHA-256: %s", sha256_bytes(encoded))

        return path

    def brave_search(self, query: str, count: int = 10) -> ProviderResult:
        key = os.getenv("BRAVE_API_KEY")
        if not key:
            return missing_key("Brave Search", "BRAVE_API_KEY", "web_search", query)
        return self._request_json(
            provider="Brave Search",
            method="GET",
            url="https://api.search.brave.com/res/v1/web/search",
            query_type="web_search",
            query_value=query,
            headers={"X-Subscription-Token": key},
            params={"q": query, "count": max(1, min(count, 20))},
            notes="Brave Search Web Search API.",
        )

    def shodan_ip(self, ip: str) -> ProviderResult:
        ip = validate_ip(ip)
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "ip", ip)
        return self._request_json(
            provider="Shodan",
            method="GET",
            url=f"https://api.shodan.io/shodan/host/{ip}",
            query_type="ip",
            query_value=ip,
            params={"key": key, "minify": "true"},
            notes="Shodan host-information lookup; minified response requested.",
        )

    def virustotal_ip(self, ip: str) -> ProviderResult:
        ip = validate_ip(ip)
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return missing_key("VirusTotal", "VIRUSTOTAL_API_KEY", "ip", ip)
        return self._request_json(
            provider="VirusTotal",
            method="GET",
            url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            query_type="ip",
            query_value=ip,
            headers={"x-apikey": key},
            notes="VirusTotal API v3 IP-address report.",
        )

    def greynoise_ip(self, ip: str) -> ProviderResult:
        """
        GreyNoise Community IP lookup.

        A Community lookup may return HTTP 404 together with a structured JSON
        message such as "IP not observed scanning the internet." Signal Forge
        preserves both the HTTP status and provider body so this negative
        lookup can be distinguished from authentication/transport failures.
        """
        ip = validate_ip(ip)
        key = os.getenv("GREYNOISE_API_KEY")
        headers = {"key": key} if key else None
        return self._request_json(
            provider="GreyNoise Community",
            method="GET",
            url=f"https://api.greynoise.io/v3/community/{ip}",
            query_type="ip",
            query_value=ip,
            headers=headers,
            notes="GreyNoise Community API; configured key used when present.",
        )

    def censys_host(self, ip: str) -> ProviderResult:
        """
        Censys Platform API v3 host lookup.

        Authentication uses a Personal Access Token (PAT) as a Bearer token.
        Free accounts can use host-lookup endpoints. Broader search endpoints
        depend on the user's current Censys plan and permissions.
        """
        ip = validate_ip(ip)
        token = os.getenv("CENSYS_PAT")
        if not token:
            return missing_key("Censys", "CENSYS_PAT", "ip", ip)

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }

        org_id = os.getenv("CENSYS_ORG_ID")
        if org_id:
            headers["X-Organization-ID"] = org_id

        return self._request_json(
            provider="Censys",
            method="GET",
            url=f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
            query_type="ip",
            query_value=ip,
            headers=headers,
            notes=(
                "Censys Platform API v3 host lookup. Free accounts can use "
                "host lookup; other endpoints depend on plan/role."
            ),
        )

    def builtwith_domain(self, domain: str) -> ProviderResult:
        """
        BuiltWith Domain API v26 technology lookup.

        The API key is sent in the Authorization header instead of the URL.
        Access and credits depend on the BuiltWith account.
        """
        domain = normalize_domain(domain)
        key = os.getenv("BUILTWITH_API_KEY")
        if not key:
            return missing_key("BuiltWith", "BUILTWITH_API_KEY", "domain", domain)

        return self._request_json(
            provider="BuiltWith",
            method="GET",
            url="https://api.builtwith.com/v26/api.json",
            query_type="domain",
            query_value=domain,
            headers={"Authorization": f"API {key}"},
            params={"LOOKUP": domain},
            notes="BuiltWith Domain API v26 technology lookup.",
        )

    def builtwith_free_domain(self, domain: str) -> ProviderResult:
        """
        BuiltWith Free API lookup.

        This returns last-updated information and technology group/category
        counts rather than the complete Domain API detail.
        """
        domain = normalize_domain(domain)
        key = os.getenv("BUILTWITH_API_KEY")
        if not key:
            return missing_key("BuiltWith Free", "BUILTWITH_API_KEY", "domain", domain)

        return self._request_json(
            provider="BuiltWith Free",
            method="GET",
            url="https://api.builtwith.com/free1/api.json",
            query_type="domain",
            query_value=domain,
            params={"KEY": key, "LOOKUP": domain},
            notes="BuiltWith Free API lookup.",
        )

    def whoisxml_domain(self, domain: str) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("WHOISXML_API_KEY")
        if not key:
            return missing_key("WhoisXML WHOIS", "WHOISXML_API_KEY", "domain", domain)
        return self._request_json(
            provider="WhoisXML WHOIS",
            method="POST",
            url="https://www.whoisxmlapi.com/whoisserver/WhoisService",
            query_type="domain",
            query_value=domain,
            headers={"Content-Type": "application/json"},
            json_body={"apiKey": key, "domainName": domain, "outputFormat": "JSON"},
            notes="HTTPS POST keeps the API key out of the URL.",
        )

    def dnsdumpster_domain(self, domain: str) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("DNSDUMPSTER_API_KEY")
        if not key:
            return missing_key("DNSDumpster", "DNSDUMPSTER_API_KEY", "domain", domain)
        logging.info("DNSDumpster pacing: waiting 2.1 seconds before request.")
        time.sleep(2.1)
        return self._request_json(
            provider="DNSDumpster",
            method="GET",
            url=f"https://api.dnsdumpster.com/domain/{domain}",
            query_type="domain",
            query_value=domain,
            headers={"X-API-Key": key},
            notes="DNSDumpster domain-record lookup.",
        )

    def sec_company_tickers(self) -> ProviderResult:
        headers = {
            "User-Agent": f"{APP_NAME}/{APP_VERSION} {CONTACT_EMAIL}",
            "Accept-Encoding": "gzip, deflate",
        }
        return self._request_json(
            provider="SEC EDGAR",
            method="GET",
            url="https://www.sec.gov/files/company_tickers.json",
            query_type="dataset",
            query_value="company_tickers",
            headers=headers,
            notes="SEC public ticker/CIK mapping; no API key required.",
        )

    def sec_find_company(self, name: str) -> ProviderResult:
        base = self.sec_company_tickers()
        if not base.success or not isinstance(base.data, dict):
            return base
        needle = name.strip().lower()
        matches = []
        for item in base.data.values():
            title = str(item.get("title", ""))
            ticker = str(item.get("ticker", ""))
            if needle in title.lower() or needle == ticker.lower():
                matches.append(item)
        return ProviderResult(
            "SEC EDGAR", "company_search", name,
            "https://www.sec.gov/files/company_tickers.json",
            utc_now(), 200, True, base.response_sha256,
            {"matches": matches},
            notes="Local filter of SEC company_tickers.json.",
        )

    def sec_submissions(self, cik: str) -> ProviderResult:
        digits = re.sub(r"\D", "", str(cik))
        if not digits:
            raise ValueError("CIK must contain digits.")
        cik10 = digits.zfill(10)
        headers = {
            "User-Agent": f"{APP_NAME}/{APP_VERSION} {CONTACT_EMAIL}",
            "Accept-Encoding": "gzip, deflate",
        }
        return self._request_json(
            provider="SEC EDGAR",
            method="GET",
            url=f"https://data.sec.gov/submissions/CIK{cik10}.json",
            query_type="cik",
            query_value=cik10,
            headers=headers,
            notes="SEC EDGAR submissions history; no API key required.",
        )


    # ------------------------------------------------------------------
    # Additional Brave operations
    # ------------------------------------------------------------------

    def brave_web_search(self, query: str, freshness: str = "") -> ProviderResult:
        key = os.getenv("BRAVE_API_KEY")
        if not key:
            return missing_key("Brave Search", "BRAVE_API_KEY", "web_search", query)
        params = {"q": query, "count": 10, "country": "US", "search_lang": "en"}
        if freshness:
            params["freshness"] = freshness
        return self._request_json(
            provider="Brave Search",
            method="GET",
            url="https://api.search.brave.com/res/v1/web/search",
            query_type="web_search",
            query_value=query,
            headers={"X-Subscription-Token": key},
            params=params,
            notes="Brave Web Search API."
        )

    def brave_news_search(self, query: str, freshness: str = "") -> ProviderResult:
        key = os.getenv("BRAVE_API_KEY")
        if not key:
            return missing_key("Brave Search", "BRAVE_API_KEY", "news_search", query)
        params = {"q": query, "count": 10, "country": "US", "search_lang": "en"}
        if freshness:
            params["freshness"] = freshness
        return self._request_json(
            provider="Brave Search",
            method="GET",
            url="https://api.search.brave.com/res/v1/news/search",
            query_type="news_search",
            query_value=query,
            headers={"X-Subscription-Token": key},
            params=params,
            notes="Brave News Search API."
        )

    # ------------------------------------------------------------------
    # Additional Shodan operations
    # ------------------------------------------------------------------

    def shodan_search(self, query: str) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "search", query)
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/shodan/host/search",
            query_type="search_query", query_value=query,
            params={"key": key, "query": query, "page": 1, "minify": "true"},
            notes="Shodan host search. Filtered searches may consume query credits."
        )

    def shodan_count(self, query: str) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "count", query)
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/shodan/host/count",
            query_type="search_query", query_value=query,
            params={"key": key, "query": query},
            notes="Shodan count-only search; returns totals instead of host records."
        )

    def shodan_domain(self, domain: str) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "domain", domain)
        return self._request_json(
            provider="Shodan", method="GET",
            url=f"https://api.shodan.io/dns/domain/{domain}",
            query_type="domain", query_value=domain,
            params={"key": key},
            notes="Shodan DNS domain information; may consume a query credit."
        )

    def shodan_dns_resolve(self, hostnames: str) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "dns_resolve", hostnames)
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/dns/resolve",
            query_type="hostnames", query_value=hostnames,
            params={"key": key, "hostnames": hostnames},
            notes="Shodan forward DNS lookup."
        )

    def shodan_dns_reverse(self, ips: str) -> ProviderResult:
        normalized = ",".join(validate_ip(x.strip()) for x in ips.split(",") if x.strip())
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "dns_reverse", normalized)
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/dns/reverse",
            query_type="ips", query_value=normalized,
            params={"key": key, "ips": normalized},
            notes="Shodan reverse DNS lookup."
        )

    def shodan_filters(self) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "filters", "all")
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/shodan/host/search/filters",
            query_type="filters", query_value="all",
            params={"key": key}, notes="List Shodan search filters."
        )

    def shodan_facets(self) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "facets", "all")
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/shodan/host/search/facets",
            query_type="facets", query_value="all",
            params={"key": key}, notes="List Shodan search facets."
        )

    def shodan_tokens(self, query: str) -> ProviderResult:
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            return missing_key("Shodan", "SHODAN_API_KEY", "tokens", query)
        return self._request_json(
            provider="Shodan", method="GET",
            url="https://api.shodan.io/shodan/host/search/tokens",
            query_type="search_query", query_value=query,
            params={"key": key, "query": query},
            notes="Ask Shodan how it parses a query."
        )

    # ------------------------------------------------------------------
    # Additional VirusTotal operations
    # ------------------------------------------------------------------

    def virustotal_domain(self, domain: str) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return missing_key("VirusTotal", "VIRUSTOTAL_API_KEY", "domain", domain)
        return self._request_json(
            provider="VirusTotal", method="GET",
            url=f"https://www.virustotal.com/api/v3/domains/{domain}",
            query_type="domain", query_value=domain,
            headers={"x-apikey": key}, notes="VirusTotal API v3 domain-object lookup."
        )

    def virustotal_url(self, target_url: str) -> ProviderResult:
        if not re.match(r"^https?://", target_url, re.I):
            raise ValueError("URL must begin with http:// or https://")
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return missing_key("VirusTotal", "VIRUSTOTAL_API_KEY", "url", target_url)
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
        return self._request_json(
            provider="VirusTotal", method="GET",
            url=f"https://www.virustotal.com/api/v3/urls/{url_id}",
            query_type="url", query_value=target_url,
            headers={"x-apikey": key}, notes="VirusTotal existing URL-object lookup."
        )

    def virustotal_file_hash(self, file_hash: str) -> ProviderResult:
        file_hash = validate_file_hash(file_hash)
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return missing_key("VirusTotal", "VIRUSTOTAL_API_KEY", "file_hash", file_hash)
        return self._request_json(
            provider="VirusTotal", method="GET",
            url=f"https://www.virustotal.com/api/v3/files/{file_hash}",
            query_type="file_hash", query_value=file_hash,
            headers={"x-apikey": key}, notes="VirusTotal file-object lookup by hash."
        )

    # ------------------------------------------------------------------
    # Additional Censys Free-compatible lookup operations
    # ------------------------------------------------------------------

    def _censys_headers(self, media: str) -> Dict[str, str] | None:
        token = os.getenv("CENSYS_PAT")
        if not token:
            return None
        types = {
            "host": "application/vnd.censys.api.v3.host.v1+json",
            "webproperty": "application/vnd.censys.api.v3.webproperty.v1+json",
            "certificate": "application/vnd.censys.api.v3.certificate.v1+json",
        }
        headers = {"Authorization": f"Bearer {token}", "Accept": types.get(media, "application/json")}
        org_id = os.getenv("CENSYS_ORG_ID")
        if org_id:
            headers["X-Organization-ID"] = org_id
        return headers

    def censys_webproperty(self, hostname: str, port: int) -> ProviderResult:
        value = f"{hostname.strip().lower()}:{int(port)}"
        headers = self._censys_headers("webproperty")
        if not headers:
            return missing_key("Censys", "CENSYS_PAT", "webproperty", value)
        return self._request_json(
            provider="Censys", method="GET",
            url="https://api.platform.censys.io/v3/global/asset/webproperty/" + quote(value, safe=""),
            query_type="hostname_port", query_value=value,
            headers=headers, notes="Censys Platform API v3 web property lookup."
        )

    def censys_certificate(self, fingerprint: str) -> ProviderResult:
        fingerprint = validate_sha256(fingerprint)
        headers = self._censys_headers("certificate")
        if not headers:
            return missing_key("Censys", "CENSYS_PAT", "certificate", fingerprint)
        return self._request_json(
            provider="Censys", method="GET",
            url=f"https://api.platform.censys.io/v3/global/asset/certificate/{fingerprint}",
            query_type="sha256", query_value=fingerprint,
            headers=headers, notes="Censys certificate lookup by SHA-256 fingerprint."
        )

    def censys_multiple_hosts(self, ips: str) -> ProviderResult:
        values = [validate_ip(x.strip()) for x in ips.split(",") if x.strip()]
        if not values or len(values) > 100:
            raise ValueError("Enter 1 to 100 comma-separated public IP addresses.")
        headers = self._censys_headers("host")
        if not headers:
            return missing_key("Censys", "CENSYS_PAT", "multiple_hosts", ",".join(values))
        return self._request_json(
            provider="Censys", method="POST",
            url="https://api.platform.censys.io/v3/global/asset/host",
            query_type="ip_list", query_value=",".join(values),
            headers=headers, json_body={"host_ids": values},
            notes="Censys Platform API v3 multi-host retrieval (up to 100)."
        )

    # ------------------------------------------------------------------
    # Additional BuiltWith operations
    # ------------------------------------------------------------------

    def builtwith_relationships(self, domain: str, page: int = 1) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("BUILTWITH_API_KEY")
        if not key:
            return missing_key("BuiltWith", "BUILTWITH_API_KEY", "relationships", domain)
        return self._request_json(
            provider="BuiltWith", method="GET",
            url="https://api.builtwith.com/rv5/api.json",
            query_type="domain", query_value=domain,
            headers={"Authorization": f"API {key}"}, params={"LOOKUP": domain, "PAGE": max(1, int(page))},
            notes="BuiltWith Relationships API; availability/credits depend on plan."
        )

    def builtwith_changes(self, domain: str, since: str = "") -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("BUILTWITH_API_KEY")
        if not key:
            return missing_key("BuiltWith", "BUILTWITH_API_KEY", "changes", domain)
        params = {"LOOKUP": domain}
        if since:
            params["SINCE"] = since
        return self._request_json(
            provider="BuiltWith", method="GET",
            url="https://api.builtwith.com/change1/api.json",
            query_type="domain", query_value=domain,
            headers={"Authorization": f"API {key}"}, params=params,
            notes="BuiltWith Change API; availability/credits depend on plan."
        )

    def builtwith_company_to_url(self, company: str) -> ProviderResult:
        key = os.getenv("BUILTWITH_API_KEY")
        if not key:
            return missing_key("BuiltWith", "BUILTWITH_API_KEY", "company_to_url", company)
        return self._request_json(
            provider="BuiltWith", method="GET",
            url="https://api.builtwith.com/ctu4/api.json",
            query_type="company", query_value=company,
            headers={"Authorization": f"API {key}"}, params={"COMPANY": company},
            notes="BuiltWith Company-to-URL API; availability/credits depend on plan."
        )

    # ------------------------------------------------------------------
    # Additional WhoisXML operations
    # ------------------------------------------------------------------

    def whoisxml_lookup(self, value: str) -> ProviderResult:
        key = os.getenv("WHOISXML_API_KEY")
        if not key:
            return missing_key("WhoisXML WHOIS", "WHOISXML_API_KEY", "lookup", value)
        return self._request_json(
            provider="WhoisXML WHOIS", method="POST",
            url="https://www.whoisxmlapi.com/whoisserver/WhoisService",
            query_type="domain_ip_or_email", query_value=value,
            headers={"Content-Type": "application/json"},
            json_body={"apiKey": key, "domainName": value, "outputFormat": "JSON"},
            notes="WhoisXML WHOIS lookup for a domain, IP address, or email address."
        )

    def whoisxml_availability(self, domain: str) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("WHOISXML_API_KEY")
        if not key:
            return missing_key("WhoisXML WHOIS", "WHOISXML_API_KEY", "availability", domain)
        return self._request_json(
            provider="WhoisXML WHOIS", method="POST",
            url="https://www.whoisxmlapi.com/whoisserver/WhoisService",
            query_type="domain", query_value=domain,
            headers={"Content-Type": "application/json"},
            json_body={"apiKey": key, "domainName": domain, "cmd": "GET_DN_AVAILABILITY", "outputFormat": "JSON"},
            notes="WhoisXML domain-availability lookup."
        )

    def whoisxml_balance(self) -> ProviderResult:
        key = os.getenv("WHOISXML_API_KEY")
        if not key:
            return missing_key("WhoisXML WHOIS", "WHOISXML_API_KEY", "balance", "account")
        return self._request_json(
            provider="WhoisXML WHOIS", method="POST",
            url="https://user.whoisxmlapi.com/user-service/account-balance",
            query_type="account", query_value="current",
            headers={"Content-Type": "application/json"},
            json_body={"apiKey": key, "outputFormat": "JSON"},
            notes="WhoisXML account balance information."
        )

    # ------------------------------------------------------------------
    # Additional DNSDumpster operations
    # ------------------------------------------------------------------

    def dnsdumpster_domain_plus(self, domain: str, page: int = 1, include_map: bool = False) -> ProviderResult:
        domain = normalize_domain(domain)
        key = os.getenv("DNSDUMPSTER_API_KEY")
        if not key:
            return missing_key("DNSDumpster", "DNSDUMPSTER_API_KEY", "domain_plus", domain)
        params = {"page": max(1, int(page))}
        if include_map:
            params["map"] = 1
        logging.info("DNSDumpster pacing: waiting 2.1 seconds before request.")
        time.sleep(2.1)
        return self._request_json(
            provider="DNSDumpster", method="GET",
            url=f"https://api.dnsdumpster.com/domain/{domain}",
            query_type="domain", query_value=domain,
            headers={"X-API-Key": key}, params=params,
            notes="DNSDumpster Plus pagination/map options."
        )

    def dnsdumpster_banners(self, cidr: str) -> ProviderResult:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        if network.version != 4 or network.num_addresses > 256:
            raise ValueError("Use an IPv4 /24 or smaller network, e.g. 203.0.113.0/24")
        key = os.getenv("DNSDUMPSTER_API_KEY")
        if not key:
            return missing_key("DNSDumpster", "DNSDUMPSTER_API_KEY", "banners", str(network))
        logging.info("DNSDumpster pacing: waiting 2.1 seconds before request.")
        time.sleep(2.1)
        return self._request_json(
            provider="DNSDumpster", method="GET",
            url=f"https://api.dnsdumpster.com/banners/{quote(str(network), safe='/')}",
            query_type="cidr", query_value=str(network),
            headers={"X-API-Key": key}, notes="DNSDumpster Plus network-banners lookup."
        )

    # ------------------------------------------------------------------
    # Additional SEC EDGAR operations
    # ------------------------------------------------------------------

    def sec_companyfacts(self, cik: str) -> ProviderResult:
        cik10 = normalize_cik(cik)
        headers = {"User-Agent": f"{APP_NAME}/{APP_VERSION} {CONTACT_EMAIL}", "Accept-Encoding": "gzip, deflate"}
        return self._request_json(
            provider="SEC EDGAR", method="GET",
            url=f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik10}.json",
            query_type="cik", query_value=cik10, headers=headers,
            notes="SEC XBRL company facts; no API key required."
        )

    def sec_companyconcept(self, cik: str, taxonomy: str, tag: str) -> ProviderResult:
        cik10 = normalize_cik(cik)
        headers = {"User-Agent": f"{APP_NAME}/{APP_VERSION} {CONTACT_EMAIL}", "Accept-Encoding": "gzip, deflate"}
        value = f"{cik10}/{taxonomy}/{tag}"
        return self._request_json(
            provider="SEC EDGAR", method="GET",
            url=f"https://data.sec.gov/api/xbrl/companyconcept/CIK{cik10}/{quote(taxonomy, safe='')}/{quote(tag, safe='')}.json",
            query_type="cik_taxonomy_tag", query_value=value, headers=headers,
            notes="SEC XBRL company-concept API; no API key required."
        )

    def sec_frame(self, taxonomy: str, tag: str, unit: str, period: str) -> ProviderResult:
        headers = {"User-Agent": f"{APP_NAME}/{APP_VERSION} {CONTACT_EMAIL}", "Accept-Encoding": "gzip, deflate"}
        value = f"{taxonomy}/{tag}/{unit}/{period}"
        return self._request_json(
            provider="SEC EDGAR", method="GET",
            url=f"https://data.sec.gov/api/xbrl/frames/{quote(taxonomy, safe='')}/{quote(tag, safe='')}/{quote(unit, safe='-')}/{quote(period, safe='')}.json",
            query_type="taxonomy_tag_unit_period", query_value=value, headers=headers,
            notes="SEC XBRL frames API; no API key required."
        )


KEYS = [
    ("Brave Search", "BRAVE_API_KEY"),
    ("Shodan", "SHODAN_API_KEY"),
    ("VirusTotal", "VIRUSTOTAL_API_KEY"),
    ("GreyNoise", "GREYNOISE_API_KEY"),
    ("Censys", "CENSYS_PAT"),
    ("BuiltWith", "BUILTWITH_API_KEY"),
    ("WhoisXML", "WHOISXML_API_KEY"),
    ("DNSDumpster", "DNSDUMPSTER_API_KEY"),
]


def print_configuration_status() -> None:
    print("\nAPI CONFIGURATION STATUS")
    print("-" * 62)
    for provider, env_name in KEYS:
        status = "CONFIGURED" if os.getenv(env_name) else "NOT CONFIGURED"
        print(f"{provider:24} : {status}")
    print(f"{'SEC EDGAR':24} : NO KEY REQUIRED")
    print(f"{'OpenCorporates':24} : PENDING API ACCESS")
    print("-" * 62)
    print("Credential values are intentionally never printed.\n")


def run_and_save(client: SignalForgeClient, result: ProviderResult) -> None:
    path = client.save_result(result)
    print("\nRESULT SUMMARY")
    print("-" * 62)
    print(f"Provider : {result.provider}")
    print(f"Success  : {result.success}")
    print(f"HTTP     : {result.http_status}")
    print(f"Retrieved: {result.retrieved_at}")
    print(f"SHA-256  : {result.response_sha256}")
    print(f"Saved    : {path}")
    if result.error:
        print(f"Error    : {result.error}")
    print("-" * 62)


def brave_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nBRAVE SEARCH\n1. Web search\n2. News search\n0. Back\n""")
        c = input("Select Brave operation: ").strip()
        if c == "0": return
        if c not in {"1", "2"}: print("Unknown option."); continue
        q = prompt_example("Query: ", "BRAVE QUERY FORMAT", [
            "open source intelligence",
            '\"Signal Forge Research\"',
            "site:sec.gov EDGAR APIs",
            'cybersecurity \"certificate transparency\"'])
        show_examples("OPTIONAL FRESHNESS", ["pd = past 24 hours", "pw = past 7 days", "pm = past 31 days", "py = past year", "2026-09-01to2026-09-26"])
        f = input("Freshness [Enter for none]: ").strip()
        run_and_save(client, client.brave_web_search(q, f) if c == "1" else client.brave_news_search(q, f))


def shodan_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nSHODAN\n1. Host information by IP\n2. Search Shodan\n3. Count query results\n4. DNS domain information\n5. DNS resolve hostnames\n6. Reverse DNS IPs\n7. List search filters\n8. List search facets\n9. Parse/test query tokens\n0. Back\n""")
        c = input("Select Shodan operation: ").strip()
        if c == "0": return
        if c == "1":
            v = prompt_example("Public IP: ", "SHODAN HOST LOOKUP", ["8.8.8.8", "1.1.1.1"])
            run_and_save(client, client.shodan_ip(v))
        elif c in {"2", "3", "9"}:
            q = prompt_example("Shodan query: ", "SHODAN QUERY FORMAT", ["nginx", "port:443", "product:nginx", "apache country:DE", 'org:\"Google LLC\" port:443', "Raspbian port:22"], "Filters use filter:value syntax. Filtered searches may consume query credits.")
            run_and_save(client, client.shodan_search(q) if c == "2" else client.shodan_count(q) if c == "3" else client.shodan_tokens(q))
        elif c == "4":
            d = prompt_example("Domain: ", "SHODAN DNS DOMAIN", ["example.com", "google.com"])
            run_and_save(client, client.shodan_domain(d))
        elif c == "5":
            h = prompt_example("Comma-separated hostnames: ", "SHODAN DNS RESOLVE", ["example.com", "google.com,cloudflare.com"])
            run_and_save(client, client.shodan_dns_resolve(h))
        elif c == "6":
            ips = prompt_example("Comma-separated IPs: ", "SHODAN REVERSE DNS", ["8.8.8.8", "8.8.8.8,1.1.1.1"])
            run_and_save(client, client.shodan_dns_reverse(ips))
        elif c == "7": run_and_save(client, client.shodan_filters())
        elif c == "8": run_and_save(client, client.shodan_facets())
        else: print("Unknown option.")


def virustotal_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nVIRUSTOTAL\n1. IP report\n2. Domain report\n3. URL report\n4. File report by hash\n0. Back\n""")
        c = input("Select VirusTotal operation: ").strip()
        if c == "0": return
        if c == "1":
            v = prompt_example("Public IP: ", "VIRUSTOTAL IP", ["8.8.8.8", "1.1.1.1"]); run_and_save(client, client.virustotal_ip(v))
        elif c == "2":
            v = prompt_example("Domain: ", "VIRUSTOTAL DOMAIN", ["example.com", "github.com"]); run_and_save(client, client.virustotal_domain(v))
        elif c == "3":
            v = prompt_example("Full URL: ", "VIRUSTOTAL URL", ["https://example.com/", "https://example.com/path/page.html"], "Include http:// or https://."); run_and_save(client, client.virustotal_url(v))
        elif c == "4":
            v = prompt_example("MD5 / SHA-1 / SHA-256: ", "VIRUSTOTAL FILE HASH", ["d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]); run_and_save(client, client.virustotal_file_hash(v))
        else: print("Unknown option.")


def greynoise_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nGREYNOISE COMMUNITY\n1. Community IP lookup\n0. Back\n""")
        c = input("Select GreyNoise operation: ").strip()
        if c == "0": return
        if c == "1":
            v = prompt_example("Public IP: ", "GREYNOISE COMMUNITY LOOKUP", ["8.8.8.8", "1.1.1.1"], "Community/free access is focused on IP lookups."); run_and_save(client, client.greynoise_ip(v))
        else: print("Unknown option.")


def censys_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nCENSYS PLATFORM API v3\n1. Host lookup by IP\n2. Web property lookup by hostname + port\n3. Certificate lookup by SHA-256\n4. Retrieve multiple hosts (up to 100)\n0. Back\n\nThese lookup endpoints are available to Censys Free users.\n""")
        c = input("Select Censys operation: ").strip()
        if c == "0": return
        if c == "1":
            v = prompt_example("Public IP: ", "CENSYS HOST", ["8.8.8.8", "1.1.1.1"]); run_and_save(client, client.censys_host(v))
        elif c == "2":
            h = prompt_example("Hostname: ", "CENSYS WEB PROPERTY HOSTNAME", ["platform.censys.io", "example.com"])
            p = prompt_example("Port: ", "CENSYS WEB PROPERTY PORT", ["80", "443", "8443"])
            run_and_save(client, client.censys_webproperty(h, int(p)))
        elif c == "3":
            f = prompt_example("Certificate SHA-256: ", "CENSYS CERTIFICATE", ["3daf2843a77b6f4e6af43cd9b6f6746053b8c928e056e8a724808db8905a94cf"]); run_and_save(client, client.censys_certificate(f))
        elif c == "4":
            ips = prompt_example("Comma-separated IPs: ", "CENSYS MULTI-HOST", ["8.8.8.8,1.1.1.1", "8.8.8.8,8.8.4.4,1.1.1.1"], "Maximum 100 hosts per call."); run_and_save(client, client.censys_multiple_hosts(ips))
        else: print("Unknown option.")


def builtwith_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nBUILTWITH\n1. Domain API v26 - detailed technologies\n2. Free API - technology counts\n3. Relationships API [PLAN-DEPENDENT]\n4. Change API [PLAN-DEPENDENT]\n5. Company -> URL API [PLAN-DEPENDENT]\n0. Back\n""")
        c = input("Select BuiltWith operation: ").strip()
        if c == "0": return
        if c in {"1", "2", "3", "4"}:
            d = prompt_example("Root domain: ", "BUILTWITH DOMAIN INPUT", ["example.com", "github.com", "openai.com"], "Use the root domain; do not include https:// or a page path.")
            if c == "1": run_and_save(client, client.builtwith_domain(d))
            elif c == "2": run_and_save(client, client.builtwith_free_domain(d))
            elif c == "3": run_and_save(client, client.builtwith_relationships(d, int(input("Page [1]: ").strip() or "1")))
            else: run_and_save(client, client.builtwith_changes(d, input("SINCE [Enter for none; example: last month]: ").strip()))
        elif c == "5":
            name = prompt_example("Company name: ", "BUILTWITH COMPANY -> URL", ["OpenAI", "Microsoft", "HotelsCombined"]); run_and_save(client, client.builtwith_company_to_url(name))
        else: print("Unknown option.")


def whoisxml_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nWHOISXML\n1. WHOIS lookup - domain, IP, or email\n2. Domain availability\n3. Account balance / remaining credits\n0. Back\n""")
        c = input("Select WhoisXML operation: ").strip()
        if c == "0": return
        if c == "1":
            v = prompt_example("Domain / IP / email: ", "WHOISXML LOOKUP", ["example.com", "8.8.8.8", "admin@example.com"]); run_and_save(client, client.whoisxml_lookup(v))
        elif c == "2":
            d = prompt_example("Domain: ", "WHOISXML DOMAIN AVAILABILITY", ["example.com", "example.org"]); run_and_save(client, client.whoisxml_availability(d))
        elif c == "3": run_and_save(client, client.whoisxml_balance())
        else: print("Unknown option.")


def dnsdumpster_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nDNSDUMPSTER\n1. Domain / DNS / attack-surface lookup\n2. Domain lookup with page number [PLUS]\n3. Domain lookup with map [PLUS]\n4. Network banners by IPv4 CIDR [PLUS]\n0. Back\n""")
        c = input("Select DNSDumpster operation: ").strip()
        if c == "0": return
        if c in {"1", "2", "3"}:
            d = prompt_example("Domain: ", "DNSDUMPSTER DOMAIN", ["example.com", "openai.com"])
            if c == "1": run_and_save(client, client.dnsdumpster_domain(d))
            elif c == "2": run_and_save(client, client.dnsdumpster_domain_plus(d, int(input("Page [2]: ").strip() or "2"), False))
            else: run_and_save(client, client.dnsdumpster_domain_plus(d, 1, True))
        elif c == "4":
            cidr = prompt_example("IPv4 CIDR: ", "DNSDUMPSTER NETWORK BANNERS", ["203.0.113.0/24", "198.51.100.0/25"], "Plus feature; query only networks you are authorized to research."); run_and_save(client, client.dnsdumpster_banners(cidr))
        else: print("Unknown option.")


def sec_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nSEC EDGAR\n1. Search company / ticker -> CIK\n2. Company submissions by CIK\n3. XBRL company facts by CIK\n4. XBRL company concept by CIK + taxonomy + tag\n5. XBRL frame by taxonomy + tag + unit + period\n0. Back\n""")
        c = input("Select SEC operation: ").strip()
        if c == "0": return
        if c == "1":
            q = prompt_example("Company or ticker: ", "SEC COMPANY SEARCH", ["Apple", "AAPL", "Microsoft", "MSFT"]); run_and_save(client, client.sec_find_company(q))
        elif c in {"2", "3", "4"}:
            cik = prompt_example("CIK: ", "SEC CIK INPUT", ["320193", "0000320193"], "Leading zeroes are optional; Signal Forge pads to 10 digits.")
            if c == "2": run_and_save(client, client.sec_submissions(cik))
            elif c == "3": run_and_save(client, client.sec_companyfacts(cik))
            else:
                tax = prompt_example("Taxonomy: ", "SEC XBRL TAXONOMY", ["us-gaap", "ifrs-full", "dei"])
                tag = prompt_example("Tag: ", "SEC XBRL CONCEPT", ["AccountsPayableCurrent", "Assets", "Revenues"])
                run_and_save(client, client.sec_companyconcept(cik, tax, tag))
        elif c == "5":
            tax = prompt_example("Taxonomy: ", "SEC FRAME TAXONOMY", ["us-gaap"])
            tag = prompt_example("Tag: ", "SEC FRAME TAG", ["AccountsPayableCurrent", "Assets"])
            unit = prompt_example("Unit: ", "SEC FRAME UNIT", ["USD", "shares", "USD-per-shares"])
            period = prompt_example("Period: ", "SEC FRAME PERIOD", ["CY2025", "CY2025Q1", "CY2025Q1I"], "Annual CY####; quarterly CY####Q#; instantaneous CY####Q#I.")
            run_and_save(client, client.sec_frame(tax, tag, unit, period))
        else: print("Unknown option.")


def bundles_menu(client: SignalForgeClient) -> None:
    while True:
        print("""\nCROSS-PROVIDER BUNDLES\n1. Public IP bundle - Shodan + VirusTotal + GreyNoise + Censys\n2. Domain bundle - VirusTotal + WhoisXML + DNSDumpster + BuiltWith + Shodan DNS\n0. Back\n""")
        c = input("Select bundle: ").strip()
        if c == "0": return
        if c == "1":
            ip = validate_ip(prompt_example("Public IP: ", "PUBLIC IP BUNDLE", ["8.8.8.8", "1.1.1.1"]))
            results = [client.shodan_ip(ip), client.virustotal_ip(ip), client.greynoise_ip(ip), client.censys_host(ip)]
            for r in results: client.save_result(r)
            print("Bundle saved:", client.save_bundle("ip_bundle", "ip", ip, results))
        elif c == "2":
            d = normalize_domain(prompt_example("Domain: ", "DOMAIN BUNDLE", ["example.com", "openai.com"]))
            results = [client.virustotal_domain(d), client.whoisxml_lookup(d), client.dnsdumpster_domain(d), client.builtwith_domain(d), client.shodan_domain(d)]
            for r in results: client.save_result(r)
            print("Bundle saved:", client.save_bundle("domain_bundle", "domain", d, results))
        else: print("Unknown option.")


def interactive_menu(client: SignalForgeClient) -> None:
    while True:
        print(f"""\n{APP_NAME} v{APP_VERSION}\n================================================================\n1.  Brave Search\n2.  Shodan\n3.  VirusTotal\n4.  GreyNoise Community\n5.  Censys Platform API v3\n6.  BuiltWith\n7.  WhoisXML\n8.  DNSDumpster\n9.  SEC EDGAR\n10. Cross-provider bundles\n11. Configuration diagnostic\n12. Set / change research subject\n0.  Exit\n================================================================\nChoose a provider first. Each provider then shows its own query choices\nand examples of correctly formatted input.\n""")
        c = input("Select provider: ").strip()
        try:
            if c == "0": logging.info("User exited normally."); return
            elif c == "1": brave_menu(client)
            elif c == "2": shodan_menu(client)
            elif c == "3": virustotal_menu(client)
            elif c == "4": greynoise_menu(client)
            elif c == "5": censys_menu(client)
            elif c == "6": builtwith_menu(client)
            elif c == "7": whoisxml_menu(client)
            elif c == "8": dnsdumpster_menu(client)
            elif c == "9": sec_menu(client)
            elif c == "10": bundles_menu(client)
            elif c == "11":
                print_configuration_status()
            elif c == "12":
                print("\nRESEARCH SUBJECT / CASE LABEL")
                print("-" * 72)
                print("This value appears near the top of every JSON report.")
                print("Examples:")
                print("  OpenAI public-domain technology profile")
                print("  Google Public DNS infrastructure test")
                print("  Signal Forge proof-of-concept — example.com")
                print()
                print("Press Enter to clear it and use each query target automatically.")
                print("-" * 72)
                client.subject = input("Subject: ").strip()
                if client.subject:
                    print(f"Subject set to: {client.subject}")
                    logging.info("RESEARCH SUBJECT SET: %s", client.subject)
                else:
                    print("Subject cleared; reports will use the query target.")
                    logging.info("RESEARCH SUBJECT CLEARED.")
            else:
                print("Unknown menu option.")
        except KeyboardInterrupt:
            print("\\nOperation cancelled.")
            logging.warning("Operation cancelled by user.")
        except Exception as exc:
            logging.exception("Operation failed: %s", exc)
            print(f"ERROR: {exc}")

def main() -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} multi-provider research CLI")
    parser.add_argument("--env", default=str(DEFAULT_ENV_FILE), help="Path to signalforge.env credential file")
    parser.add_argument("--quiet", action="store_true", help="Reduce console logging")
    parser.add_argument("--diagnostic", action="store_true", help="Show provider config and exit")
    args = parser.parse_args()

    load_dotenv_simple(Path(args.env))
    log_path = configure_logging(DEFAULT_LOG_DIR, verbose=not args.quiet)

    logging.info("%s v%s STARTING", APP_NAME, APP_VERSION)
    logging.info("UTC START: %s", utc_now())
    logging.info("PROJECT DIR: %s", PROJECT_DIR)
    logging.info("LOG FILE: %s", log_path)
    logging.info("OUTPUT DIR: %s", DEFAULT_OUTPUT_DIR)
    logging.info("API KEYS WILL NEVER BE PRINTED.")
    logging.info("SECRET-REDACTION FILTER: ENABLED")
    logging.info("LOW-LEVEL HTTP DEBUG URL LOGGING: SUPPRESSED")

    print_configuration_status()
    if args.diagnostic:
        return 0

    print("OPTIONAL RESEARCH SUBJECT / CASE LABEL")
    print("-" * 66)
    print("This becomes the 'subject' field near the top of every JSON report.")
    print("Examples:")
    print("  OpenAI public-domain technology profile")
    print("  Google Public DNS infrastructure test")
    print("  Signal Forge proof-of-concept — example.com")
    print()
    print("Press Enter to leave it blank; the query target will be used instead.")
    print("-" * 66)
    subject = input("Research subject [optional]: ").strip()

    client = SignalForgeClient(DEFAULT_OUTPUT_DIR, subject=subject)
    interactive_menu(client)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
