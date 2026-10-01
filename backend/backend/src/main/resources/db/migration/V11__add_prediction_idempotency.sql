ALTER TABLE predictions
    ADD CONSTRAINT uk_predictions_event_model_version
        UNIQUE (event_id, model_name, model_version);