CREATE TABLE account_preferences (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    theme varchar(6) NOT NULL CHECK (theme IN ('light','dark','system')),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE account_profile_links (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind varchar(16) NOT NULL CHECK (kind IN ('github','linkedin','x','website')),
    url varchar(300) NOT NULL,
    PRIMARY KEY (account_id, kind)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON account_preferences, account_profile_links TO lookahead_identity_app;
