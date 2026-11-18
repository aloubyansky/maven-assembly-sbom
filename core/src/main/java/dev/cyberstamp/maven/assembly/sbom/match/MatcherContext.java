package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.http.HttpClient;
import java.util.function.Function;

/**
 * What a {@code MavenArtifactMatcherFactory} needs to build its matcher, shared
 * by all matchers of one run.
 *
 * @param httpClient the shared HTTP client
 * @param hasher the shared SHA-1 hasher, so each file is hashed once
 * @param credentials resolves a {@code settings.xml} server id to its
 *        decrypted credentials, or {@code null} if there is no such server
 */
public record MatcherContext(HttpClient httpClient, Sha1Hasher hasher, Function<String, ServerCredentials> credentials) {

    /**
     * Returns the Basic authentication header for the given server id, or
     * {@code null} for anonymous access.
     */
    public String basicAuthHeader(String serverId) {
        if (serverId == null || serverId.isBlank()) {
            return null;
        }
        ServerCredentials resolved = credentials.apply(serverId);
        return resolved == null ? null : resolved.basicAuthHeader();
    }
}
