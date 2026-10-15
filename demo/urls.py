from django.urls import path
from . import views

urlpatterns = [
    path("services/", views.services),
    path("services/<slug:consumer_id>/run/", views.individual),
    path("run/", views.batch),
    path("exposure/secret/run/", views.exposure, {"credential_type": "secret"}),
    path("exposure/key/run/", views.exposure, {"credential_type": "key"}),
    path("cart/", views.cart),
]
