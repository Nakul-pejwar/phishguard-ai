from django.urls import path

from .views import sso_acs_api, sso_config_api, sso_initiate_api, sso_metadata_api

urlpatterns = [
    path("api/auth/sso/metadata/<slug:org_slug>/", sso_metadata_api, name="sso_metadata_api"),
    path("api/auth/sso/initiate/", sso_initiate_api, name="sso_initiate_api"),
    path("api/auth/sso/acs/<slug:org_slug>/", sso_acs_api, name="sso_acs_api"),
    path("api/auth/sso/config/", sso_config_api, name="sso_config_api"),
]
