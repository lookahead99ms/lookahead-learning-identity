package com.lookahead.identity.filter;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.*;

class AccountRequestLimitsFilterTest {
    private final AccountRequestLimitsFilter filter = new AccountRequestLimitsFilter();

    @Test void boundedJsonIsReplayedExactlyForTheController() throws Exception {
        byte[] body = "{\"displayName\":\"A learner\",\"settings\":[true,1,null]}".getBytes(StandardCharsets.UTF_8);
        var request = request("POST", "/api/v1/account/profile", body);
        var response = new MockHttpServletResponse();
        var called = new AtomicBoolean();
        filter.doFilter(request, response, (wrapped, reply) -> {
            called.set(true);
            var input = wrapped.getInputStream();
            assertThat(input.isReady()).isTrue();
            assertThat(input.isFinished()).isFalse();
            assertThat(input.read()).isEqualTo(body[0]);
            assertThat(input.readAllBytes()).containsExactly(java.util.Arrays.copyOfRange(body, 1, body.length));
            assertThat(input.isFinished()).isTrue();
            assertThat(input.read()).isEqualTo(-1);
            assertThatThrownBy(() -> input.setReadListener(null)).isInstanceOf(UnsupportedOperationException.class);
            assertThat(wrapped.getInputStream().readAllBytes()).containsExactly(body);
        });
        assertThat(called).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test void malformedAndExcessivelyNestedJsonFailBeforeControllerAndNeverEchoPayload() throws Exception {
        for (String body : new String[]{"{secret-value", "[".repeat(34) + "0" + "]".repeat(34)}) {
            assertRejected(request("POST", "/api/v1/auth/register", body.getBytes(StandardCharsets.UTF_8)),
                    400, "MALFORMED_JSON");
        }
    }

    @Test void bothDeclaredAndStreamingOversizeBodiesFailClosed() throws Exception {
        byte[] oversized = ("\"" + "x".repeat(8191) + "\"").getBytes(StandardCharsets.UTF_8);
        assertRejected(request("POST", "/api/v1/account/password", oversized), 413, "PAYLOAD_TOO_LARGE");
        var streaming = new MockHttpServletRequest("POST", "/api/v1/account/password") {
            @Override public long getContentLengthLong() { return -1; }
        };
        streaming.setContent(oversized);
        assertRejected(streaming, 413, "PAYLOAD_TOO_LARGE");
    }

    @Test void everyAccountMutationUsesTheSameLimitsAndOtherRequestsAreUntouched() throws Exception {
        for (String path : new String[]{"/api/v1/auth/register", "/api/v1/account/profile",
                "/api/v1/account/password", "/api/v1/account/sign-ins/revoke",
                "/api/v1/account/sign-ins/revoke-others", "/api/v1/account/sign-ins/label",
                "/api/v1/auth/sign-in-challenge/replace", "/api/v1/auth/sign-in-challenge/cancel"}) {
            assertRejected(request("POST", path, new byte[]{'{'}), 400, "MALFORMED_JSON");
        }
        for (var request : new MockHttpServletRequest[]{request("GET", "/api/v1/account/profile", new byte[]{'{'}),
                request("POST", "/oauth2/token", new byte[]{'{'} )}) {
            var called = new AtomicBoolean();
            filter.doFilter(request, new MockHttpServletResponse(), (incoming, response) -> {
                assertThat(incoming).isSameAs(request);
                called.set(true);
            });
            assertThat(called).isTrue();
        }
    }

    private void assertRejected(HttpServletRequest request, int status, String code) throws Exception {
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (incoming, reply) -> { throw new AssertionError("Controller must not run"); });
        assertThat(response.getStatus()).isEqualTo(status);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString()).contains(code).doesNotContain("secret-value");
    }

    private MockHttpServletRequest request(String method, String path, byte[] body) {
        var request = new MockHttpServletRequest(method, path);
        request.setContent(body);
        request.setContentType("application/json");
        return request;
    }
}
