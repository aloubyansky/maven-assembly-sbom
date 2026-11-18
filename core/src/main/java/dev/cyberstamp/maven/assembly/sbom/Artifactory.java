package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;

import dev.cyberstamp.maven.assembly.sbom.match.ArtifactoryCoordinatesLookup;
import dev.cyberstamp.maven.assembly.sbom.match.CoordinatesLookup;

/**
 * Configures lookup against a JFrog Artifactory instance ({@code <artifactory>}), e.g. with
 * {@code <url>https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}</url>}.
 */
public class Artifactory extends ChecksumSearchMatcherFactory {

    private String serverId;

    /**
     * Returns the {@code settings.xml} {@code <server>} id whose credentials
     * are sent as HTTP Basic authentication.
     *
     * @return the server id, or {@code null} for anonymous access
     */
    public String getServerId() {
        return serverId;
    }

    /**
     * Sets the {@code settings.xml} {@code <server>} id whose credentials are
     * sent as HTTP Basic authentication.
     *
     * @param serverId the server id
     */
    public void setServerId(String serverId) {
        this.serverId = serverId;
    }

    @Override
    String serverId() {
        return serverId;
    }

    @Override
    public String elementName() {
        return "artifactory";
    }

    @Override
    CoordinatesLookup newLookup(HttpClient client, String url, String basicAuthHeader) {
        return new ArtifactoryCoordinatesLookup(client, timeout(), url, basicAuthHeader);
    }
}
