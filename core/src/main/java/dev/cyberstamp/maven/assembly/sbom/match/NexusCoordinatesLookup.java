package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.Identification;

/**
 * Looks up Maven coordinates by SHA-1 against an internal Nexus Repository
 * Manager 3 instance, using its REST search API.
 *
 * <p>
 * Targets Nexus 3 only; Nexus 2 (whose search API differs) has reached
 * end-of-life and is out of scope. The response is expected in Nexus 3's
 * search-result shape: a top-level {@code items} array of components, each
 * with {@code group}/{@code name}/{@code version} fields and an
 * {@code assets} array.
 * </p>
 *
 * <p>
 * The coordinates are taken from the {@code maven2} attributes of the asset
 * whose {@code checksum.sha1} matches, which include the asset's classifier
 * and extension. If no asset carries a matching checksum, the first returned
 * component's {@code group}/{@code name}/{@code version} are used, without a
 * classifier (see {@link Identification#remoteComponentMatch(int)}).
 * </p>
 *
 * <p>
 * The configured URL must be a complete search request containing a literal
 * {@code {sha1}} placeholder for the content hash (see {@link #PLACEHOLDER}),
 * e.g. {@code https://nexus.example.com/service/rest/v1/search?sha1={sha1}}.
 * This is deliberately not derived from a bare base URL: the REST path and
 * any extra filters (e.g. Nexus's {@code repository} parameter) are under
 * Sonatype's control, and hardcoding them here could go stale. Requiring the
 * full URL means a Nexus-side API change only needs a config update, not a
 * new plugin release.
 * </p>
 */
public final class NexusCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Nexus");
    private final String basicAuthHeader;

    public NexusCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate, String basicAuthHeader) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
        this.basicAuthHeader = basicAuthHeader;
    }

    @Override
    public Optional<MavenMatch> lookup(String sha1Hex, String fileName) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, basicAuthHeader, failures)
                .flatMap(body -> JsonLookupSupport.parse(body, uri, failures))
                .flatMap(root -> toMatch(root.path("items"), sha1Hex));
    }

    private static Optional<MavenMatch> toMatch(JsonNode items, String sha1Hex) {
        for (JsonNode item : items) {
            for (JsonNode asset : item.path("assets")) {
                if (sha1Hex.equalsIgnoreCase(asset.path("checksum").path("sha1").asText())) {
                    Optional<ArtifactCoords> coords = fromMaven2Attributes(asset.path("maven2"));
                    if (coords.isPresent()) {
                        return coords.map(c -> new MavenMatch(c, Identification.remoteAssetMatch()));
                    }
                }
            }
        }
        return fromComponent(items.path(0)).map(c -> new MavenMatch(c, items.size() == 1
                ? Identification.remoteCoordinatesLookup()
                : Identification.remoteComponentMatch(items.size())));
    }

    private static Optional<ArtifactCoords> fromMaven2Attributes(JsonNode maven2) {
        String groupId = text(maven2, "groupId");
        String artifactId = text(maven2, "artifactId");
        String version = text(maven2, "version");
        if (groupId == null || artifactId == null || version == null) {
            return Optional.empty();
        }
        return Optional.of(new ArtifactCoords(groupId, artifactId, version,
                text(maven2, "extension"), text(maven2, "classifier")));
    }

    private static Optional<ArtifactCoords> fromComponent(JsonNode item) {
        String groupId = text(item, "group");
        String artifactId = text(item, "name");
        String version = text(item, "version");
        if (groupId == null || artifactId == null || version == null) {
            return Optional.empty();
        }
        return Optional.of(ArtifactCoords.of(groupId, artifactId, version));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }
}
