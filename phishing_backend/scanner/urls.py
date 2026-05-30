from django.urls import path
from .views import check_url_api

urlpatterns = [
    path("api/check-url/", check_url_api, name="check_url_api"),
]