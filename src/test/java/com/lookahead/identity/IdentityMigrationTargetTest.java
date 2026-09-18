package com.lookahead.identity;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class IdentityMigrationTargetTest {
    @Test void acceptsOnlyTheDedicatedMigratorAtAnExplicitDatabase() {
        assertThatCode(() -> IdentityMigration.validateMigrationTarget("lookahead_identity_migrator", "jdbc:postgresql://database:5432/owned"))
                .doesNotThrowAnyException();
        assertThatIllegalStateException().isThrownBy(() -> IdentityMigration.validateMigrationTarget("postgres", "jdbc:postgresql://database:5432/owned"));
        assertThatIllegalStateException().isThrownBy(() -> IdentityMigration.validateMigrationTarget("lookahead_identity_app", "jdbc:postgresql://database:5432/owned"));
    }
    @Test void urlCannotReplaceValidatedRoleOrSessionConfiguration() {
        for (String query : new String[]{"user=postgres", "password=private-value", "options=-c%20role%3Dpostgres", "currentSchema=another", "socketTimeout=0"})
            assertThatIllegalStateException().isThrownBy(() -> IdentityMigration.validateMigrationTarget("lookahead_identity_migrator", "jdbc:postgresql://database:5432/owned?" + query))
                    .withMessageNotContaining("private-value");
    }
}
