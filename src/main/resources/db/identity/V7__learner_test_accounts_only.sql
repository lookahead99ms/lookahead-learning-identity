-- DLV-971: the managed Local test roster holds learner test accounts only (learner01-learner27).
-- The staff test accounts coauthor01, coauthor02 and admin01-admin06 left the roster the
-- applications serve, and the separate staff password with them. A Local database that still
-- holds those identities must not keep them signable, so this migration retires them the way
-- TestAccountService.disable() does: block login, advance the credential epoch, scrub the password
-- hash, erase authorizations, sign-ins, profile, preferences and links, and keep the registry
-- tombstone. Only identities registered in test_accounts are touched; a real account that merely
-- shares a username is never changed, and the existing author is outside the roster. Rerunning the
-- same statements is harmless: the credential epoch advances once, the rest is already gone.
UPDATE accounts SET enabled=false, credential_epoch=credential_epoch+1, password_hash='deleted',
    display_name='Deleted test account'
WHERE id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
             WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'))
  AND password_hash<>'deleted';
DELETE FROM oauth2_authorization WHERE principal_name IN (SELECT t.account_id::text FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM oauth2_authorization_consent WHERE principal_name IN (SELECT t.account_id::text FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM sign_in_challenges WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM logical_sign_ins WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM account_profile_links WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM account_preferences WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
DELETE FROM account_profiles WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
UPDATE test_accounts SET creation_state='deleted', last_changed_by='V7', last_changed_at=clock_timestamp()
WHERE account_id IN (SELECT t.account_id FROM test_accounts t JOIN accounts a ON a.id=t.account_id AND a.username=t.username
    WHERE t.username IN ('coauthor01','coauthor02','admin01','admin02','admin03','admin04','admin05','admin06'));
