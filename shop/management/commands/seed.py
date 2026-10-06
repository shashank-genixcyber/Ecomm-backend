from django.core.management.base import BaseCommand
from shop.models import Product

PRODUCTS = [
    ("The morning mug", "A warm stoneware companion for your daily ritual.", "Home", "mug", "690.00"),
    ("Everywhere tote", "Heavyweight cotton. Room for your whole day.", "Carry", "tote", "1190.00"),
    ("Little desk lamp", "A softer glow for focused evenings.", "Desk", "lamp", "2490.00"),
    ("Notes to self", "Lay-flat pages for ideas worth keeping.", "Desk", "notebook", "390.00"),
    ("Sunday throw", "Soft woven cotton, made for slowing down.", "Home", "throw", "1890.00"),
    ("Daylong bottle", "A reusable steel bottle for wherever you go.", "Carry", "bottle", "890.00"),
]

class Command(BaseCommand):
    help = "Add six sample products (safe to run again)."

    def handle(self, *args, **options):
        for name, description, category, artwork, price in PRODUCTS:
            Product.objects.update_or_create(name=name, defaults={
                "description": description, "category": category, "artwork": artwork, "price": price,
            })
        self.stdout.write(self.style.SUCCESS("Sample products ready."))

