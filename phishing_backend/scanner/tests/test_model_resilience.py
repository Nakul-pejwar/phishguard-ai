from scanner.ml.predictor import ModelManager, predict_phishing_url


def test_model_manager_missing_file_fallback():
    manager = ModelManager.get_instance()
    original_loaded = manager.is_loaded
    original_model = manager.model
    original_path = manager.model_path
    original_error = manager.load_error
    original_attempted = manager._load_attempted

    try:
        manager.model_path = "/non/existent/path/model.joblib"
        loaded = manager.load_model("/non/existent/path/model.joblib")
        assert loaded is False
        assert manager.is_loaded is False
        assert manager.model is None
        assert manager.load_error is not None

        # Predict should not crash, but use fallback
        result = predict_phishing_url("https://unknown-domain.com/login")
        assert result["domain"] == "unknown-domain.com"
        assert any("fallback" in r.lower() or "unavailable" in r.lower() for r in result["reasons"])

    finally:
        # Restore state
        manager.model_path = original_path
        manager.is_loaded = original_loaded
        manager.model = original_model
        manager.load_error = original_error
        manager._load_attempted = original_attempted
        manager.load_model()
