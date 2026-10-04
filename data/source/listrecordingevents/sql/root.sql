SELECT r.* FROM recorded_events r WHERE r.namespace = :Namespace AND r.recording_id = :RecordingID ORDER BY r.sequence ASC LIMIT 10001
