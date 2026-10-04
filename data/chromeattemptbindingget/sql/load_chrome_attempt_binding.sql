SELECT * FROM  (SELECT b.* FROM chrome_attempt_bindings b WHERE b.namespace=:Namespace AND b.client_id=:ClientID AND b.browser_attempt_id=:BrowserAttemptID
)  bindings