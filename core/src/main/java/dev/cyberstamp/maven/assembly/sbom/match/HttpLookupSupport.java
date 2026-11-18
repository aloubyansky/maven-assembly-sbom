package dev.cyberstamp.maven.assembly.sbom.match;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared HTTP GET helper for the checksum-search lookup implementations.
 * Centralizes timeout handling, optional Basic authentication, and the
 * "never throw, just log and report empty" contract required by
 * {@link CoordinatesLookup}.
 */
final class HttpLookupSupport {

    private static final Logger log = LoggerFactory.getLogger(HttpLookupSupport.class);

    private HttpLookupSupport() {
    }

    /**
     * Performs a GET request and returns the response body, or empty if the
     * request failed, timed out, or did not return HTTP 200. Failures are
     * reported through {@code failures}.
     *
     * @param client the shared HTTP client
     * @param uri the request URI
     * @param timeout the per-request timeout
     * @param basicAuthHeader a pre-built {@code Authorization: Basic ...}
     *        header value, or {@code null} for an unauthenticated request
     * @param failures where failed requests are reported
     * @return the response body, or empty
     */
    static Optional<String> get(HttpClient client, URI uri, Duration timeout, String basicAuthHeader,
            FailureLog failures) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .GET();
            if (basicAuthHeader != null) {
                builder.header("Authorization", basicAuthHeader);
            }
            HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                failures.httpStatus(uri, response.statusCode());
                return Optional.empty();
            }
            return Optional.of(response.body());
        } catch (IOException | RuntimeException e) {
            failures.exception(uri, e);
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    /**
     * Builds an {@code Authorization: Basic ...} header value.
     *
     * @param username the username
     * @param password the password
     * @return the header value
     */
    static String basicAuthHeader(String username, String password) {
        String token = username + ":" + password;
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Reports failed lookups of one backend as warnings, so users notice a
     * misconfigured or unreachable repository. Each kind of failure (an HTTP
     * status, or an exception type) is warned about once; repeats are logged
     * at debug level to avoid one warning per looked-up file.
     *
     * <p>
     * A missing match is not a failure: the search APIs answer it with
     * HTTP 200 and an empty result.
     * </p>
     */
    static final class FailureLog {

        private final String backendName;
        private final Set<String> reported = new HashSet<>();

        FailureLog(String backendName) {
            this.backendName = backendName;
        }

        void httpStatus(URI uri, int status) {
            String key = "HTTP " + status;
            if (!firstOccurrence(key)) {
                log.debug("{} lookup against {} returned HTTP {}", backendName, uri, status);
            } else if (status == 401 || status == 403) {
                log.warn("{} lookup against {} was rejected with HTTP {}; check the credentials of the "
                        + "configured serverId and its permissions. Further occurrences are logged at debug level",
                        backendName, uri, status);
            } else {
                log.warn("{} lookup against {} returned HTTP {}; check the configured search URL. "
                        + "Further occurrences are logged at debug level", backendName, uri, status);
            }
        }

        void exception(URI uri, Exception e) {
            if (firstOccurrence(e.getClass().getName())) {
                log.warn("{} lookup against {} failed: {}. Further occurrences are logged at debug level",
                        backendName, uri, e.toString());
            }
            log.debug("{} lookup against {} failed", backendName, uri, e);
        }

        /**
         * Returns {@code true} the first time a failure kind is seen.
         */
        boolean firstOccurrence(String key) {
            return reported.add(key);
        }
    }
}
