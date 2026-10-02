from django.urls import path

from .views import siem_config_api, siem_test_api

urlpatterns = [
    path("api/siem/config/", siem_config_api, name="siem_config_api"),
    path("api/siem/test/", siem_test_api, name="siem_test_api"),
]
