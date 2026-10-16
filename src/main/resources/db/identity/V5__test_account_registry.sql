-- DLV-961: only explicitly admitted synthetic accounts enter this registry.
-- The legacy author is excluded; no account profile or password is changed here.
CREATE TABLE test_accounts (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    username varchar(254) NOT NULL UNIQUE,
    is_test_account boolean NOT NULL DEFAULT true CHECK (is_test_account),
    last_changed_by varchar(254) NOT NULL,
    last_changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
GRANT SELECT, INSERT, UPDATE ON test_accounts TO lookahead_identity_app;
