from decimal import Decimal

from django.conf import settings
from django.contrib.auth import logout
from django.db import transaction
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Order, Product
from demo.runtime import DemoFailure, shopping


def demo_failure(error):
    return Response({"detail": "A demo credential dependency failed. Check the demo panel and shared log.",
                     **error.result}, status=503)


@never_cache
@api_view(["GET"])
@permission_classes([AllowAny])
def session(request):
    user = request.user
    return Response({
        "user": {"id": user.pk, "name": user.first_name or user.email.split("@")[0], "email": user.email} if user.is_authenticated else None,
        "csrf_token": get_token(request),
        "login_url": "/accounts/oidc/shop/login/",
        "provider": settings.OIDC_PROVIDER_NAME,
        "oauth_configured": bool(settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET),
        "demo_enabled": settings.DEMO_ENABLED,
    })


@api_view(["GET"])
@permission_classes([AllowAny])
def products(request):
    catalog = Product.objects.order_by("id").values("id", "name", "description", "category", "artwork", "price")
    result = [{**product, "price": str(product["price"])} for product in catalog]
    try:
        shopping("products", result)
    except DemoFailure as error:
        return demo_failure(error)
    return Response(result)


class CartItem(serializers.Serializer):
    product_id = serializers.IntegerField(min_value=1)
    quantity = serializers.IntegerField(min_value=1, max_value=20)


class Checkout(serializers.Serializer):
    items = CartItem(many=True, allow_empty=False, max_length=50)


@api_view(["GET", "POST"])
def orders(request):
    if request.method == "GET":
        history = Order.objects.filter(user=request.user).values("id", "items", "total", "created_at")
        result = [{**order, "total": str(order["total"])} for order in history]
        try:
            shopping("orders", [{"id": order["id"], "total": order["total"]} for order in result])
        except DemoFailure as error:
            return demo_failure(error)
        return Response(result)
    checkout = Checkout(data=request.data)
    checkout.is_valid(raise_exception=True)
    cart = checkout.validated_data["items"]
    ids = [item["product_id"] for item in cart]
    if len(ids) != len(set(ids)):
        return Response({"detail": "Each product must appear once."}, status=400)
    with transaction.atomic():
        catalog = Product.objects.in_bulk(ids)
        if len(catalog) != len(ids):
            return Response({"detail": "One or more products are unavailable."}, status=400)
        items = [{
            "product_id": product.pk, "name": product.name, "price": str(product.price), "quantity": item["quantity"],
        } for item in cart for product in [catalog[item["product_id"]]]]
        total = sum((Decimal(item["price"]) * item["quantity"] for item in items), Decimal("0"))
        try:
            shopping("checkout", {"items": items, "total": str(total)})
        except DemoFailure as error:
            return demo_failure(error)
        order = Order.objects.create(user=request.user, items=items, total=total)
    return Response({"id": order.pk, "items": items, "total": str(total), "created_at": order.created_at}, status=201)


@csrf_protect
@api_view(["POST"])
def sign_out(request):
    logout(request)
    return Response({"detail": "Signed out."})
