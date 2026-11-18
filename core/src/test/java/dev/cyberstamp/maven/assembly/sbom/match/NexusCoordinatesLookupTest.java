package dev.cyberstamp.maven.assembly.sbom.match;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.Identification;

class NexusCoordinatesLookupTest {

    private HttpServer server;
    private final AtomicReference<String> lastQuery = new AtomicReference<>();
    private final AtomicReference<String> lastAuthHeader = new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private void respondWith(int status, String body) {
        server.createContext("/service/rest/v1/search", exchange -> {
            lastQuery.set(exchange.getRequestURI().getQuery());
            lastAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    @Test
    void returnsCoordsOnMatch() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\"}],"
                + "\"continuationToken\":null}");

        Optional<MavenMatch> result = lookup(null).lookup("abc123", null);

        assertEquals(Optional.of(new MavenMatch(ArtifactCoords.of("com.example", "lib", "2.0"),
                Identification.remoteCoordinatesLookup())), result);
        assertEquals("sha1=abc123", lastQuery.get());
    }

    @Test
    void takesClassifierAndExtensionFromTheAssetWithMatchingChecksum() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\","
                + "\"assets\":["
                + asset("0000", "com.example", "lib", "2.0", "jar", null)
                + "," + asset("abc123", "com.example", "lib", "2.0", "jar", "jdk8")
                + "]}]}");

        Optional<MavenMatch> result = lookup(null).lookup("abc123", null);

        assertEquals(Optional.of(new MavenMatch(new ArtifactCoords("com.example", "lib", "2.0", "jar", "jdk8"),
                Identification.remoteAssetMatch())), result);
    }

    @Test
    void matchingAssetWithoutClassifierIsTheMainArtifact() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"app\",\"version\":\"2.0\","
                + "\"assets\":[" + asset("ABC123", "com.example", "app", "2.0", "war", null) + "]}]}");

        Optional<MavenMatch> result = lookup(null).lookup("abc123", null);

        assertEquals(Optional.of(new MavenMatch(new ArtifactCoords("com.example", "app", "2.0", "war", null),
                Identification.remoteAssetMatch())), result,
                "checksums are compared case-insensitively and the extension becomes the type");
    }

    @Test
    void fallsBackToComponentCoordinatesWithoutMatchingAsset() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\","
                + "\"assets\":[{\"checksum\":{\"sha1\":\"abc123\"}}]}]}");

        assertEquals(Optional.of(new MavenMatch(ArtifactCoords.of("com.example", "lib", "2.0"),
                Identification.remoteCoordinatesLookup())), lookup(null).lookup("abc123", null),
                "an asset without maven2 attributes must not hide the component's coordinates");
    }

    @Test
    void confidenceFallsAsMoreComponentsShareTheSameContentHash() {
        respondWith(200, "{\"items\":["
                + "{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\"},"
                + "{\"group\":\"com.example.relocated\",\"name\":\"lib\",\"version\":\"2.0\"}"
                + "]}");

        assertEquals(Optional.of(new MavenMatch(ArtifactCoords.of("com.example", "lib", "2.0"),
                Identification.remoteComponentMatch(2))), lookup(null).lookup("abc123", null),
                "two equally plausible components sharing the hash must halve the confidence");
    }

    private static String asset(String sha1, String groupId, String artifactId, String version, String extension,
            String classifier) {
        return "{\"checksum\":{\"sha1\":\"" + sha1 + "\"},\"maven2\":{"
                + "\"groupId\":\"" + groupId + "\",\"artifactId\":\"" + artifactId + "\","
                + "\"version\":\"" + version + "\",\"extension\":\"" + extension + "\""
                + (classifier != null ? ",\"classifier\":\"" + classifier + "\"" : "")
                + "}}";
    }

    @Test
    void sendsAuthorizationHeaderWhenConfigured() {
        respondWith(200, "{\"items\":[]}");
        String auth = HttpLookupSupport.basicAuthHeader("alice", "s3cr3t");

        lookup(auth).lookup("abc123", null);

        assertEquals(auth, lastAuthHeader.get());
    }

    @Test
    void sendsNoAuthorizationHeaderWhenAnonymous() {
        respondWith(200, "{\"items\":[]}");

        lookup(null).lookup("abc123", null);

        assertNull(lastAuthHeader.get());
    }

    @Test
    void returnsEmptyWhenNoItemsFound() {
        respondWith(200, "{\"items\":[]}");

        assertTrue(lookup(null).lookup("deadbeef", null).isEmpty());
    }

    @Test
    void returnsEmptyWhenResponseIsNotValidJson() {
        respondWith(200, "<html>not json</html>");

        assertTrue(lookup(null).lookup("abc123", null).isEmpty());
    }

    @Test
    void returnsEmptyOnNon200Status() {
        respondWith(403, "");

        assertTrue(lookup(null).lookup("abc123", null).isEmpty());
    }

    @Test
    void returnsEmptyWhenServerUnreachable() throws IOException {
        NexusCoordinatesLookup nexus = new NexusCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofMillis(500),
                "http://127.0.0.1:" + unreachablePort() + "/service/rest/v1/search?sha1="
                        + NexusCoordinatesLookup.PLACEHOLDER,
                null);

        assertTrue(nexus.lookup("abc123", null).isEmpty());
    }

    @Test
    void substitutesSha1IntoConfiguredSearchUrlAndKeepsExtraParameters() {
        respondWith(200, "{\"items\":[{\"group\":\"com.example\",\"name\":\"lib\",\"version\":\"2.0\"}]}");
        String searchUrl = baseUrl() + "/service/rest/v1/search?sha1=" + NexusCoordinatesLookup.PLACEHOLDER
                + "&repository=my-repo";
        NexusCoordinatesLookup nexus = new NexusCoordinatesLookup(
                HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, null);

        Optional<MavenMatch> result = nexus.lookup("abc123", null);

        assertEquals(Optional.of(new MavenMatch(ArtifactCoords.of("com.example", "lib", "2.0"),
                Identification.remoteCoordinatesLookup())), result);
        assertEquals("sha1=abc123&repository=my-repo", lastQuery.get());
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private NexusCoordinatesLookup lookup(String authHeader) {
        String searchUrl = baseUrl() + "/service/rest/v1/search?sha1=" + NexusCoordinatesLookup.PLACEHOLDER;
        return new NexusCoordinatesLookup(HttpClient.newHttpClient(), Duration.ofSeconds(5), searchUrl, authHeader);
    }

    /**
     * Returns a loopback port nothing is listening on, by briefly binding
     * one and releasing it. Deliberately not a low-numbered port like
     * {@code 1}: those are "privileged" on Linux (require root to bind to),
     * and some sandboxed/firewalled environments handle connection attempts
     * to them differently (e.g. silently dropping instead of refusing),
     * which could make this test flaky or slow depending on where it runs.
     */
    private static int unreachablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
