CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    username varchar(254) NOT NULL UNIQUE,
    display_name varchar(160) NOT NULL,
    password_hash varchar(255) NOT NULL,
    enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE account_profiles (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    first_name varchar(80) NOT NULL,
    last_name varchar(80) NOT NULL,
    email varchar(254) NOT NULL UNIQUE,
    country_code char(2) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_normalized CHECK (email = lower(email)),
    CONSTRAINT country_code_format CHECK (country_code ~ '^[A-Z]{2}$')
);
-- Spring Security 7.1.1 JDBC schemas, adapted to PostgreSQL per the bundled schema instructions.
/*
IMPORTANT:
    If using PostgreSQL:
        - update ALL columns defined with 'timestamp' to 'timestamptz', to ensure that time instants are stored accurately.
    If using MySQL:
        - add 'preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true' to JDBC connection URL
          to ensure that time instants are stored accurately. See https://dev.mysql.com/doc/connector-j/en/connector-j-time-instants.html
*/
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamptz DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

/*
IMPORTANT:
    If using PostgreSQL:
        - update ALL columns defined with 'blob' to 'text', as PostgreSQL does not support the 'blob' data type.
        - update ALL columns defined with 'timestamp' to 'timestamptz', to ensure that time instants are stored accurately.
    If using MySQL:
        - add 'preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true' to JDBC connection URL
          to ensure that time instants are stored accurately. See https://dev.mysql.com/doc/connector-j/en/connector-j-time-instants.html
*/
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamptz DEFAULT NULL,
    authorization_code_expires_at timestamptz DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamptz DEFAULT NULL,
    access_token_expires_at timestamptz DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamptz DEFAULT NULL,
    oidc_id_token_expires_at timestamptz DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamptz DEFAULT NULL,
    refresh_token_expires_at timestamptz DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    user_code_value text DEFAULT NULL,
    user_code_issued_at timestamptz DEFAULT NULL,
    user_code_expires_at timestamptz DEFAULT NULL,
    user_code_metadata text DEFAULT NULL,
    device_code_value text DEFAULT NULL,
    device_code_issued_at timestamptz DEFAULT NULL,
    device_code_expires_at timestamptz DEFAULT NULL,
    device_code_metadata text DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);


REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lookahead_identity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON accounts, account_profiles,
    oauth2_registered_client, oauth2_authorization, oauth2_authorization_consent TO lookahead_identity_app;
GRANT SELECT ON flyway_schema_history TO lookahead_identity_app;
