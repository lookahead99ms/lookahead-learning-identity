package com.lookahead.identity.oauth;

import org.junit.jupiter.api.Test;
import org.mockito.MockMakers;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.oauth2.server.authorization.*;
import javax.sql.DataSource;
import java.sql.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TransactionalAuthorizationServiceTest {
    @Test void nestedClientLookupUsesOneConnectionEvenWhenOnlyOneIsAvailable() throws Exception {
        var source = mock(DataSource.class, withSettings().mockMaker(MockMakers.PROXY));
        var connection = mock(Connection.class, withSettings().mockMaker(MockMakers.PROXY));
        var statement = mock(Statement.class, withSettings().mockMaker(MockMakers.PROXY));
        var outerRows = mock(ResultSet.class, withSettings().mockMaker(MockMakers.PROXY));
        var innerRows = mock(ResultSet.class, withSettings().mockMaker(MockMakers.PROXY));
        var checkedOut = new AtomicBoolean();
        when(source.getConnection()).thenAnswer(call -> {
            if (checkedOut.getAndSet(true)) throw new SQLException("The only pool connection is already held");
            return connection;
        });
        doAnswer(call -> { checkedOut.set(false); return null; }).when(connection).close();
        when(connection.getAutoCommit()).thenReturn(true);
        when(connection.createStatement()).thenReturn(statement);
        when(statement.executeQuery("authorization")).thenReturn(outerRows);
        when(statement.executeQuery("registered-client")).thenReturn(innerRows);
        when(outerRows.next()).thenReturn(true, false);
        when(innerRows.next()).thenReturn(true, false);
        when(innerRows.getInt(1)).thenReturn(1);
        var jdbc = new JdbcTemplate(source);
        var delegate = mock(OAuth2AuthorizationService.class, withSettings().mockMaker(MockMakers.PROXY));
        when(delegate.findByToken("synthetic", OAuth2TokenType.ACCESS_TOKEN)).thenAnswer(call ->
                jdbc.queryForObject("authorization", (row, index) -> {
                    Integer clientId = jdbc.queryForObject("registered-client", (client, clientIndex) -> client.getInt(1));
                    assertEquals(Integer.valueOf(1), clientId);
                    return null;
                }));
        var service = new TransactionalAuthorizationService(delegate, new JdbcTransactionManager(source));
        assertNull(service.findByToken("synthetic", OAuth2TokenType.ACCESS_TOKEN));
        verify(source, times(1)).getConnection();
        verify(connection).commit();
        assertFalse(checkedOut.get());
    }

    @Test void failedAuthorizationWriteRollsBackAndPropagates() throws Exception {
        var source = mock(DataSource.class, withSettings().mockMaker(MockMakers.PROXY));
        var connection = mock(Connection.class, withSettings().mockMaker(MockMakers.PROXY));
        when(source.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        var delegate = mock(OAuth2AuthorizationService.class, withSettings().mockMaker(MockMakers.PROXY));
        var authorization = mock(OAuth2Authorization.class);
        doThrow(new IllegalStateException("synthetic failure")).when(delegate).save(authorization);
        var service = new TransactionalAuthorizationService(delegate, new JdbcTransactionManager(source));
        assertThrows(IllegalStateException.class, () -> service.save(authorization));
        verify(connection).rollback();
        verify(connection, never()).commit();
    }
}
