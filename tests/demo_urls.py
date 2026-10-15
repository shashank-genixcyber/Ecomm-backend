from django.urls import include, path
from config.urls import urlpatterns as application_urls

urlpatterns = [path("api/demo/", include("demo.urls")), *application_urls]
