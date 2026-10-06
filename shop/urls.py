from django.urls import path
from . import views

urlpatterns = [
    path("session/", views.session),
    path("products/", views.products),
    path("orders/", views.orders),
    path("logout/", views.sign_out),
]

