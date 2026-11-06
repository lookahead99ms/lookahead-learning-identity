package com.lookahead.identity.seed;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

class TestAccountRosterTest {
    @Test void rosterPreservesLearnerIdsAndExcludesTheExistingOwner() {
        var entries = TestAccountRoster.entries();
        assertThat(entries).hasSize(27);
        assertThat(entries.stream().map(TestAccountRoster.Entry::username)).doesNotHaveDuplicates()
                .doesNotContain("author01", "author@lookahead.test", "coauthor01", "coauthor02", "admin01", "admin06")
                .contains("learner01", "learner10", "learner27")
                .allMatch(name -> name.matches("learner(0[1-9]|1[0-9]|2[0-7])"));
        var first = entries.getFirst();
        assertThat(first.accountId()).isEqualTo(UUID.nameUUIDFromBytes(
                "lookahead-local-test:learner01".getBytes(StandardCharsets.UTF_8)));
        assertThat(first.email()).isEqualTo("learner01@lookahead.test");
        assertThat(first.firstName()).isEqualTo("Learner01");
        assertThatThrownBy(() -> entries.clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
