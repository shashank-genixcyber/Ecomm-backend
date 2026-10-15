from django.contrib import admin
from django.urls import include, path
from shop.oauth import callback
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/oidc/<str:provider_id>/login/callback/", callback),
    path("accounts/", include("allauth.urls")),
    path("api/", include("shop.urls")),
]

if settings.DEMO_ENABLED:
    urlpatterns.insert(0, path("api/demo/", include("demo.urls")))
