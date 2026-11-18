package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.Identification;

/**
 * Looks up Maven coordinates by SHA-1 against the public Maven Central
 * search API ({@code search.maven.org}) by default. Requires no
 * configuration or credentials, but the search URL can be overridden (see
 * {@link Central#setUrl(String)}) — e.g. to point at an
 * internal mirror of the Central search API, or to adapt if Sonatype ever
 * changes its public API shape, without needing a new plugin release.
 *
 * <p>
 * Central's response has no per-asset classifier of its own, only an
 * {@code ec} ("extra content") array listing every file suffix published for
 * that version (e.g. {@code ["-sources.jar", ".jar", "-linux-x86_64.jar"]}).
 * A classifier is derived from the archive entry's own file name via
 * {@link Maven2FileName}, but only trusted if the resulting suffix is
 * actually listed in {@code ec} — otherwise the entry could be a locally
 * renamed file wrongly implying a classifier Central never published, so
 * the coordinates fall back to the bare GAV instead.
 * </p>
 */
public final class MavenCentralCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    public static final String DEFAULT_SEARCH_URL = "https://search.maven.org/solrsearch/select?q=1:"
            + PLACEHOLDER + "&rows=1&wt=json";

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Maven Central");

    MavenCentralCoordinatesLookup(HttpClient client, Duration timeout) {
        this(client, timeout, DEFAULT_SEARCH_URL);
    }

    /**
     * @param searchUrlTemplate a complete search URL containing a literal
     *        {@code {sha1}} placeholder for the content hash; overridable so
     *        tests can point at a stub server instead of the real API
     */
    public MavenCentralCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
    }

    @Override
    public Optional<MavenMatch> lookup(String sha1Hex, String fileName) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, null, failures)
                .flatMap(body -> JsonLookupSupport.parse(body, uri, failures))
                .flatMap(root -> toCoords(root.findPath("docs"), fileName))
                .map(coords -> new MavenMatch(coords, Identification.remoteCoordinatesLookup()));
    }

    private static Optional<ArtifactCoords> toCoords(JsonNode docs, String fileName) {
        if (!docs.isArray() || docs.isEmpty()) {
            return Optional.empty();
        }
        JsonNode doc = docs.get(0);
        String groupId = text(doc, "g");
        String artifactId = text(doc, "a");
        String version = text(doc, "v");
        if (groupId == null || artifactId == null || version == null) {
            return Optional.empty();
        }
        ArtifactCoords plain = ArtifactCoords.of(groupId, artifactId, version);
        if (fileName == null) {
            return Optional.of(plain);
        }
        ArtifactCoords withClassifier = Maven2FileName.classifierAndExtension(groupId, artifactId, version, fileName);
        return Optional.of(confirmedByExtraContent(withClassifier, doc.path("ec")) ? withClassifier : plain);
    }

    /**
     * Returns whether the classifier+type combination (e.g. the
     * {@code -linux-x86_64.jar} suffix, or plain {@code .jar} when there is
     * no classifier) implied by {@code withClassifier} is listed in
     * Central's {@code ec} ("extra content") array for this version.
     */
    private static boolean confirmedByExtraContent(ArtifactCoords withClassifier, JsonNode ec) {
        if (!ec.isArray()) {
            return false;
        }
        String suffix = withClassifier.classifier() == null
                ? "." + withClassifier.type()
                : "-" + withClassifier.classifier() + "." + withClassifier.type();
        for (JsonNode entry : ec) {
            if (entry.isTextual() && suffix.equals(entry.asText())) {
                return true;
            }
        }
        return false;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }
}
