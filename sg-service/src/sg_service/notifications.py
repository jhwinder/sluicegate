from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

ADAPTER_TYPES = ("mock", "webhook", "resend", "smtp")
EMAIL_ADAPTER_TYPES = ("resend", "smtp")
RESEND_API_URL = "https://api.resend.com/emails"
SEND_TIMEOUT_SECONDS = 10.0
MAX_EMAIL_RECIPIENTS = 20
SMTP_DEFAULT_PORTS = {"none": 25, "starttls": 587, "tls": 465}

_ADDRESS_PATTERN = re.compile(r"^[^@\s,;<>\"()\\]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_HOST_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


class ConfigurationError(ValueError):
    pass


class NotificationError(Exception):
    def __init__(self, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


def is_valid_address(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 254 and _ADDRESS_PATTERN.fullmatch(value) is not None


def resolve_secret(name: str) -> str | None:
    """Read a secret from NAME_FILE (preferred) or NAME in the service environment."""
    file_path = os.environ.get(f"{name}_FILE", "").strip()
    if file_path:
        try:
            value = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return value or None
    return os.environ.get(name, "").strip() or None


def required_secret_names(adapter_type: str, config: dict[str, Any]) -> list[str]:
    if adapter_type == "resend":
        return ["RESEND_API_KEY"]
    if adapter_type == "smtp" and config.get("auth_mode") == "login":
        return ["SG_SMTP_USERNAME", "SG_SMTP_PASSWORD"]
    return []


def secrets_status(adapter_type: str, config: dict[str, Any]) -> dict[str, bool]:
    return {name: resolve_secret(name) is not None for name in required_secret_names(adapter_type, config)}


def _reject_unknown_keys(adapter_type: str, config: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(config) - allowed)
    if unknown:
        raise ConfigurationError(f"Unsupported {adapter_type} configuration field(s): {', '.join(unknown)}")


def validate_adapter_config(adapter_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if adapter_type == "email":
        raise ConfigurationError("Choose an explicit email provider: 'resend' or 'smtp'")
    if adapter_type not in ADAPTER_TYPES:
        raise ConfigurationError(f"Unsupported adapter type '{adapter_type}'")

    if adapter_type == "mock":
        return dict(config)

    if adapter_type == "webhook":
        _reject_unknown_keys(adapter_type, config, {"url"})
        url = config.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")) or len(url) > 2048:
            raise ConfigurationError("Webhook configuration requires an http(s) 'url'")
        return {"url": url}

    sender = config.get("sender")
    if not is_valid_address(sender):
        raise ConfigurationError("A valid 'sender' email address is required")

    if adapter_type == "resend":
        _reject_unknown_keys(adapter_type, config, {"sender"})
        return {"sender": sender}

    _reject_unknown_keys(adapter_type, config, {"sender", "host", "port", "tls_mode", "auth_mode", "ca_bundle_path"})
    host = config.get("host")
    if not isinstance(host, str) or len(host) > 253 or _HOST_PATTERN.fullmatch(host) is None:
        raise ConfigurationError("SMTP configuration requires a valid 'host'")
    tls_mode = config.get("tls_mode", "starttls")
    if tls_mode not in SMTP_DEFAULT_PORTS:
        raise ConfigurationError("SMTP 'tls_mode' must be one of: none, starttls, tls")
    auth_mode = config.get("auth_mode", "none")
    if auth_mode not in ("none", "login"):
        raise ConfigurationError("SMTP 'auth_mode' must be one of: none, login")
    if auth_mode == "login" and tls_mode == "none":
        raise ConfigurationError("SMTP login requires 'starttls' or 'tls' so credentials are not sent in clear text")
    port = config.get("port", SMTP_DEFAULT_PORTS[tls_mode])
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigurationError("SMTP 'port' must be an integer between 1 and 65535")
    normalized: dict[str, Any] = {"sender": sender, "host": host, "port": port, "tls_mode": tls_mode, "auth_mode": auth_mode}
    ca_bundle_path = config.get("ca_bundle_path")
    if ca_bundle_path:
        if not isinstance(ca_bundle_path, str) or not os.path.isabs(ca_bundle_path):
            raise ConfigurationError("SMTP 'ca_bundle_path' must be an absolute path")
        normalized["ca_bundle_path"] = ca_bundle_path
    return normalized


def adapter_fingerprint(adapter_type: str, config: dict[str, Any], key: bytes) -> str:
    """Keyed digest of the provider, its settings, and its current secret values; never reversible to the secrets."""
    material = {
        "type": adapter_type,
        "config": config,
        "secrets": {
            name: (hashlib.sha256(value.encode("utf-8")).hexdigest() if (value := resolve_secret(name)) else None)
            for name in required_secret_names(adapter_type, config)
        },
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def _single_line(value: str, limit: int) -> str:
    return " ".join(value.split())[:limit]


def build_message(
    event_type: str,
    request_id: str,
    summary: str,
    details: dict[str, Any],
    template: str,
    console_url: str,
) -> tuple[str, str]:
    subject = f"[SluiceGate] {_single_line(summary, 200)}"
    details_text = json.dumps(details, default=str, sort_keys=True)[:2000]
    if template:
        body = (
            template.replace("{event_type}", event_type)
            .replace("{request_id}", request_id)
            .replace("{summary}", summary)
            .replace("{details}", details_text)
            .replace("{console_url}", console_url)
        )
        return subject, body
    lines = [summary, "", f"Event: {event_type}", f"Reference: {request_id}", f"Details: {details_text}"]
    if console_url:
        lines.extend(["", f"Review in the SluiceGate Admin Console (sign-in required): {console_url}"])
    return subject, "\n".join(lines)


def _send_resend(config: dict[str, Any], recipients: list[str], subject: str, body: str, idempotency_key: str) -> None:
    api_key = resolve_secret("RESEND_API_KEY")
    if not api_key:
        raise NotificationError("RESEND_API_KEY is not configured on the service", retryable=False)
    try:
        response = httpx.post(
            RESEND_API_URL,
            json={"from": config["sender"], "to": recipients, "subject": subject, "text": body},
            headers={"Authorization": f"Bearer {api_key}", "Idempotency-Key": idempotency_key},
            timeout=SEND_TIMEOUT_SECONDS,
        )
    except httpx.TimeoutException:
        raise NotificationError("Resend request timed out", retryable=True) from None
    except httpx.HTTPError as exc:
        raise NotificationError(f"Resend request failed ({type(exc).__name__})", retryable=True) from None
    if response.status_code == 429 or response.status_code >= 500:
        raise NotificationError(f"Resend returned HTTP {response.status_code}", retryable=True)
    if not 200 <= response.status_code < 300:
        raise NotificationError(f"Resend rejected the message (HTTP {response.status_code})", retryable=False)


def _send_smtp(config: dict[str, Any], recipients: list[str], subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = config["sender"]
    message["To"] = ", ".join(recipients)
    message["Subject"] = _single_line(subject, 200)
    message.set_content(body)

    tls_mode = config.get("tls_mode", "starttls")
    username = password = None
    if config.get("auth_mode") == "login":
        username, password = resolve_secret("SG_SMTP_USERNAME"), resolve_secret("SG_SMTP_PASSWORD")
        if not username or not password:
            raise NotificationError("SMTP credentials are not configured on the service", retryable=False)
    try:
        context = ssl.create_default_context(cafile=config.get("ca_bundle_path") or None)
        if tls_mode == "tls":
            client: smtplib.SMTP = smtplib.SMTP_SSL(config["host"], config["port"], timeout=SEND_TIMEOUT_SECONDS, context=context)
        else:
            client = smtplib.SMTP(config["host"], config["port"], timeout=SEND_TIMEOUT_SECONDS)
        with client:
            client.ehlo()
            if tls_mode == "starttls":
                client.starttls(context=context)
                client.ehlo()
            if username and password:
                client.login(username, password)
            client.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise NotificationError("SMTP authentication failed", retryable=False) from None
    except ssl.SSLError:
        raise NotificationError("SMTP TLS negotiation or certificate validation failed", retryable=False) from None
    except smtplib.SMTPResponseException as exc:
        raise NotificationError(f"SMTP server returned code {exc.smtp_code}", retryable=400 <= exc.smtp_code < 500) from None
    except smtplib.SMTPRecipientsRefused as exc:
        retryable = all(400 <= code < 500 for code, _ in exc.recipients.values())
        raise NotificationError("SMTP server refused the recipients", retryable=retryable) from None
    except smtplib.SMTPNotSupportedError:
        raise NotificationError("SMTP server does not support the configured TLS/authentication mode", retryable=False) from None
    except smtplib.SMTPException as exc:
        raise NotificationError(f"SMTP delivery failed ({type(exc).__name__})", retryable=True) from None
    except OSError as exc:
        raise NotificationError(f"SMTP connection failed ({type(exc).__name__})", retryable=True) from None


def send_email(
    adapter_type: str,
    config: dict[str, Any],
    recipients: list[str],
    subject: str,
    body: str,
    idempotency_key: str,
) -> None:
    if adapter_type == "resend":
        _send_resend(config, recipients, subject, body, idempotency_key)
    elif adapter_type == "smtp":
        _send_smtp(config, recipients, subject, body)
    else:
        raise NotificationError(f"'{adapter_type}' is not an email provider", retryable=False)


def send_webhook(config: dict[str, Any], payload: dict[str, Any]) -> None:
    url = config.get("url")
    if not url:
        raise NotificationError("Webhook adapter has no URL", retryable=False)
    try:
        response = httpx.post(url, json=payload, timeout=SEND_TIMEOUT_SECONDS)
    except httpx.TimeoutException:
        raise NotificationError("Webhook request timed out", retryable=True) from None
    except httpx.HTTPError as exc:
        raise NotificationError(f"Webhook request failed ({type(exc).__name__})", retryable=True) from None
    if response.status_code == 429 or response.status_code >= 500:
        raise NotificationError(f"Webhook returned HTTP {response.status_code}", retryable=True)
    if not 200 <= response.status_code < 300:
        raise NotificationError(f"Webhook rejected the notification (HTTP {response.status_code})", retryable=False)
