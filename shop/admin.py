from django.contrib import admin
from .models import Order, Product

admin.site.register(Product)

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "total", "created_at"]
    readonly_fields = ["user", "items", "total", "created_at"]

