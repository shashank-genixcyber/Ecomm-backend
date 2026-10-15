from time import perf_counter
from uuid import uuid4

from django.conf import settings
from django.http import JsonResponse

from . import audit


class DemoAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, "DEMO_ENABLED", False):
            return self.get_response(request)
        request_id = str(uuid4())
        request.demo_request_id = request_id
        marker = audit.context.set({"request_id": request_id, "caller": str(request.user.pk) if request.user.is_authenticated else "anonymous"})
        started = perf_counter()
        try:
            # Local demo identity and synthetic credentials must never become a
            # remotely reachable authentication mode through an accidental bind.
            if request.META.get("REMOTE_ADDR") not in {"127.0.0.1", "::1"}:
                return JsonResponse({"detail": "The demo is available on loopback only."}, status=403)
            try:
                audit.emit("http.request.started", http_method=request.method, http_path=request.path)
            except audit.AuditUnavailable:
                return JsonResponse({"detail": "Demo audit unavailable.", "request_id": request_id}, status=503)
            response = self.get_response(request)
            try:
                audit.emit("http.request.completed", http_method=request.method, http_path=request.path,
                           http_status=response.status_code, duration_ms=round((perf_counter() - started) * 1000, 3))
            except audit.AuditUnavailable:
                response = JsonResponse({"detail": "Demo audit unavailable.", "request_id": request_id}, status=503)
            response["X-Request-ID"] = request_id
            response["Cache-Control"] = "no-store"
            return response
        finally:
            audit.context.reset(marker)
