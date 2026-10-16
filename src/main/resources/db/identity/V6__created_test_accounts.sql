-- Dynamic Local learner fixtures begin disabled until Domain records ownership.
ALTER TABLE test_accounts ADD COLUMN creation_state varchar(12) NOT NULL DEFAULT 'active'
    CHECK (creation_state IN ('pending','active','deleted'));
CREATE INDEX test_accounts_creation_state ON test_accounts(creation_state);
