CREATE TABLE logical_sign_ins (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_epoch bigint NOT NULL,
    binding_digest varchar(64) NOT NULL,
    created_at timestamptz NOT NULL,
    last_active_at timestamptz NOT NULL,
    recent_auth_at timestamptz NOT NULL,
    revoked_at timestamptz,
    label varchar(80) NOT NULL DEFAULT '',
    client_description varchar(80) NOT NULL DEFAULT 'Browser'
);
CREATE INDEX logical_sign_ins_account_idx ON logical_sign_ins(account_id);
CREATE TABLE sign_in_challenges (
    token_digest varchar(64) PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_epoch bigint NOT NULL,
    binding_digest varchar(64) NOT NULL,
    client_description varchar(80) NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    cancelled boolean NOT NULL DEFAULT false,
    selected_id uuid,
    admitted_id uuid REFERENCES logical_sign_ins(id)
);
CREATE INDEX sign_in_challenges_account_idx ON sign_in_challenges(account_id);
ALTER TABLE oauth2_authorization ADD COLUMN logical_sign_in_id uuid REFERENCES logical_sign_ins(id);
CREATE INDEX oauth2_authorization_sign_in_idx ON oauth2_authorization(logical_sign_in_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON logical_sign_ins, sign_in_challenges TO lookahead_identity_app;
