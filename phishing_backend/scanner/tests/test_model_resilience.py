from scanner.ml.predictor import ModelManager, predict_phishing_url


def test_model_manager_missing_file_fallback():
    manager = ModelManager.get_instance()
    original_loaded = manager.is_loaded
    original_model = manager.model

    try:
        # Simulate missing model file
        loaded = manager.load_model(custom_path="/non/existent/path/model.joblib")
        assert loaded is False
        assert manager.is_loaded is False
        assert manager.model is None
        assert manager.load_error is not None

        # Predict should not crash, but use fallback
        result = predict_phishing_url("https://google.com")
        assert result["domain"] == "google.com"
        assert result["verdict"] == "safe"
        assert any("fallback" in r.lower() for r in result["reasons"])

    finally:
        # Restore state
        manager.is_loaded = original_loaded
        manager.model = original_model
        manager.load_model()
