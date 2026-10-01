from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self):
        # Attempt eager model loading on application startup
        try:
            from .ml.predictor import ModelManager
            ModelManager.get_instance().load_model()
        except Exception:
            # Safe startup: failure to load ML model should not prevent Django from running
            pass
