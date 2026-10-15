from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from .runtime import trace_headers


class DemoSocialAccountAdapter(DefaultSocialAccountAdapter):
    def get_requests_session(self):
        session = super().get_requests_session()
        session.verify = str(settings.DEMO_ASSET_DIR / "ca.pem")
        session.headers.update(trace_headers())
        return session
