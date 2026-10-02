from django.urls import path

from .views import erasure_request_api, retention_policy_api, trigger_purge_api

urlpatterns = [
    path("api/compliance/retention/", retention_policy_api, name="retention_policy_api"),
    path("api/compliance/erasure-request/", erasure_request_api, name="erasure_request_api"),
    path("api/compliance/purge/", trigger_purge_api, name="trigger_purge_api"),
]
