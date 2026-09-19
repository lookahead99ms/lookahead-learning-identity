ALTER TABLE accounts ADD COLUMN credential_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN password_failure_count integer NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN password_failure_window timestamptz;
CREATE INDEX oauth2_authorization_principal_idx ON oauth2_authorization(principal_name);
