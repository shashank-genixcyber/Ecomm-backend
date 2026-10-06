from django.contrib import admin
from django.urls import include, path
from shop.oauth import callback

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/oidc/<str:provider_id>/login/callback/", callback),
    path("accounts/", include("allauth.urls")),
    path("api/", include("shop.urls")),
]
