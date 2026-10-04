-- Infrastructure migration: user-owned typed variables, independent of ledger/history.
CREATE TABLE IF NOT EXISTS run_variables(namespace TEXT NOT NULL,run_id TEXT NOT NULL,name TEXT NOT NULL,value_json TEXT NOT NULL,PRIMARY KEY(namespace,run_id,name),FOREIGN KEY(namespace,run_id) REFERENCES runs(namespace,id));
PRAGMA user_version=2;
