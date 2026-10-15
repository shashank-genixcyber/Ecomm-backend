from django.http import Http404
from django.conf import settings
from django.views.decorators.csrf import csrf_protect
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from shop.models import Product
from shop.views import CartItem
from .exposure import EXPOSURE_CONSUMERS, execute_exposure
from .registry import BY_ID, CONSUMERS, CREDENTIAL_TYPES
from .runtime import run


def enabled():
    if not getattr(settings, "DEMO_ENABLED", False):
        raise Http404


def failure_response(result):
    return Response({"detail": "A demo credential operation failed. Check the demo panel and shared log.",
                     **result}, status=503)


@api_view(["GET"])
@permission_classes([AllowAny])
def services(request):
    enabled()
    return Response({"services": [consumer.public() for consumer in CONSUMERS]})


class Selection(serializers.Serializer):
    credential_type = serializers.ChoiceField(choices=CREDENTIAL_TYPES, required=False)


@api_view(["POST"])
def batch(request):
    enabled()
    selection = Selection(data=request.data)
    selection.is_valid(raise_exception=True)
    category = selection.validated_data.get("credential_type")
    return Response(run([consumer for consumer in CONSUMERS if category is None or consumer.credential_type == category], trigger="manual_batch"))


@api_view(["POST"])
def individual(request, consumer_id):
    enabled()
    if consumer_id not in BY_ID:
        raise Http404
    result = run([BY_ID[consumer_id]], trigger="manual")
    return failure_response(result) if result["summary"]["failed"] else Response(result)


@api_view(["POST"])
def exposure(request, credential_type):
    enabled()
    result = run([EXPOSURE_CONSUMERS[credential_type]], trigger="manual_log_exposure", executor=execute_exposure)
    return failure_response(result) if result["summary"]["failed"] else Response(result)


class CartPreview(serializers.Serializer):
    items = CartItem(many=True, allow_empty=True, max_length=50)


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_protect
def cart(request):
    enabled()
    serializer = CartPreview(data=request.data)
    serializer.is_valid(raise_exception=True)
    items = serializer.validated_data["items"]
    ids = [item["product_id"] for item in items]
    if len(ids) != len(set(ids)) or Product.objects.filter(pk__in=ids).count() != len(ids):
        return Response({"detail": "The cart contains duplicate or unavailable products."}, status=400)
    result = run([consumer for consumer in CONSUMERS if consumer.trigger == "cart"], trigger="cart", payload={"items": items})
    return failure_response(result) if result["summary"]["failed"] else Response(result)
