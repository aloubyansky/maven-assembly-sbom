package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.Identification;

/**
 * Looks up Maven coordinates by SHA-1 against an internal JFrog Artifactory
 * instance, using its checksum search API.
 *
 * <p>
 * Unlike Maven Central and Nexus, Artifactory's checksum search does not
 * return structured group/artifact/version fields; it returns the storage
 * {@code uri} of the matching item instead. Coordinates are recovered from
 * that path by assuming the standard Maven2 repository layout:
 * {@code .../api/storage/<repoKey>/<groupPath>/<artifactId>/<version>/<file>}.
 * </p>
 *
 * <p>
 * The classifier and extension are read from the storage file name on a
 * best-effort basis via {@link Maven2FileName}.
 * </p>
 *
 * <p>
 * The configured URL must be a complete search request containing a literal
 * {@code {sha1}} placeholder for the content hash (see {@link #PLACEHOLDER}),
 * e.g.
 * {@code https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}}.
 * This is deliberately not derived from a bare base URL: the REST path and
 * any extra filters (e.g. Artifactory's {@code repos} parameter) are under
 * JFrog's control, and hardcoding them here could go stale. Requiring the
 * full URL means an Artifactory-side API change only needs a config update,
 * not a new plugin release.
 * </p>
 */
public final class ArtifactoryCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Artifactory");
    private final String basicAuthHeader;

    public ArtifactoryCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate, String basicAuthHeader) {
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
                .flatMap(ArtifactoryCoordinatesLookup::firstMatchingResult)
                .map(coords -> new MavenMatch(coords, Identification.remoteCoordinatesLookup()));
    }

    /**
     * Returns coordinates from the first {@code results[]} entry that
     * follows the Maven2 layout, skipping non-matching entries (e.g. a
     * {@code generic} repo result) in favor of the next one.
     */
    private static Optional<ArtifactCoords> firstMatchingResult(JsonNode root) {
        JsonNode results = root.findPath("results");
        if (!results.isArray()) {
            return Optional.empty();
        }
        for (JsonNode result : results) {
            JsonNode uri = result.path("uri");
            if (!uri.isTextual() || uri.asText().isBlank()) {
                continue;
            }
            Optional<ArtifactCoords> coords = toCoords(uri.asText());
            if (coords.isPresent()) {
                return coords;
            }
        }
        return Optional.empty();
    }

    /**
     * Recovers {@code groupId:artifactId:version} from a storage {@code uri}
     * following the standard Maven2 layout, anchored at the fixed
     * {@code api/storage} path segment pair that precedes the repository key.
     *
     * @return the coordinates, or empty if the path does not follow the
     *         expected shape (e.g. a non-Maven-layout repository)
     */
    private static Optional<ArtifactCoords> toCoords(String uri) {
        String path;
        try {
            path = URI.create(uri).getPath();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (path == null) {
            return Optional.empty();
        }
        List<String> segments = new ArrayList<>();
        for (String segment : path.split("/")) {
            if (!segment.isEmpty()) {
                segments.add(segment);
            }
        }
        int storageIdx = apiStorageIdx(segments);
        if (storageIdx < 0) {
            return Optional.empty();
        }
        // segments after "storage": [repoKey, g1, g2, ..., artifactId, version, file]
        List<String> repoRelative = segments.subList(storageIdx + 1, segments.size());
        if (repoRelative.size() < 4) {
            return Optional.empty();
        }
        int size = repoRelative.size();
        String version = repoRelative.get(size - 2);
        String artifactId = repoRelative.get(size - 3);
        List<String> groupPath = repoRelative.subList(1, size - 3);
        if (groupPath.isEmpty()) {
            return Optional.empty();
        }
        String groupId = String.join(".", groupPath);
        String fileName = repoRelative.get(size - 1);
        if (!fileName.startsWith(artifactId + "-" + version)) {
            return Optional.empty(); // not a Maven2-layout artifact
        }
        return Optional.of(Maven2FileName.classifierAndExtension(groupId, artifactId, version, fileName));
    }

    /**
     * Returns the index of the {@code storage} segment in the fixed
     * {@code api/storage} pair, or {@code -1} if absent. Anchored on the
     * adjacent pair, not a bare {@code lastIndexOf("storage")}, since the
     * repo key, group path, artifact id or version could themselves be
     * named "storage".
     */
    private static int apiStorageIdx(List<String> segments) {
        for (int i = 0; i < segments.size() - 1; i++) {
            if ("api".equals(segments.get(i)) && "storage".equals(segments.get(i + 1))) {
                return i + 1;
            }
        }
        return -1;
    }

}
