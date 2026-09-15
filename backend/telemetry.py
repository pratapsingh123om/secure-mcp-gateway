from __future__ import annotations

import threading

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from backend.config import Settings


_lock = threading.Lock()
_configured = False


def configure_telemetry(settings: Settings) -> None:
    """Install the OpenTelemetry SDK once; optionally export redacted spans to stdout."""
    global _configured
    with _lock:
        if _configured:
            return
        provider = TracerProvider(resource=Resource.create({
            "service.name": "zero-trust-mcp-gateway",
            "service.version": "1.0.0",
            "deployment.environment": settings.environment,
        }))
        if settings.otel_console_exporter:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        _configured = True
