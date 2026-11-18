package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.URI;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Parses the JSON responses of the checksum-search backends
 * ({@link MavenCentralCoordinatesLookup}, {@link NexusCoordinatesLookup},
 * {@link ArtifactoryCoordinatesLookup}) once into a navigable tree, so each
 * backend can read every field it needs from that same tree instead of
 * re-parsing the response per field.
 */
final class JsonLookupSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonLookupSupport() {
    }

    /**
     * Parses a JSON document, reporting a malformed document through
     * {@code failures} exactly like an HTTP-level failure.
     *
     * @param json the JSON document, or {@code null}
     * @param uri the request URI the document came from, for the failure report
     * @param failures where an unparseable document is reported
     * @return the root node, or empty if the input is {@code null} or malformed
     */
    static Optional<JsonNode> parse(String json, URI uri, HttpLookupSupport.FailureLog failures) {
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(MAPPER.readTree(json));
        } catch (JsonProcessingException e) {
            failures.exception(uri, e);
            return Optional.empty();
        }
    }
}
