package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

import dev.cyberstamp.maven.assembly.sbom.match.CoordinatesLookup;
import dev.cyberstamp.maven.assembly.sbom.match.MatcherContext;
import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatcher;
import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatchers;

/**
 * Factory for a matcher that looks up a file's SHA-1
 * through a remote repository's search API.
 */
public abstract class ChecksumSearchMatcherFactory extends MavenArtifactMatcherFactory {

    /**
     * Literal marker substituted with the content hash in the search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private String url;
    private int timeoutMillis = 3000;
    private int maxLookups = 200;

    /**
     * Returns the complete search URL with a literal {@code {sha1}} in place
     * of the content hash.
     *
     * @return the search URL, or {@code null} if unset
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the complete search URL, with a literal {@code {sha1}} in place of
     * the content hash. The rest of the URL is used exactly as given, so
     * repository-specific query parameters can be added.
     *
     * @param url the search URL
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Returns the per-request timeout, in milliseconds.
     *
     * @return the timeout in milliseconds
     */
    public int getTimeoutMillis() {
        return timeoutMillis;
    }

    /**
     * Sets the per-request timeout, in milliseconds.
     *
     * @param timeoutMillis the timeout in milliseconds
     */
    public void setTimeoutMillis(int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    /**
     * Returns the maximum number of lookups this matcher performs in one run.
     *
     * @return the maximum number of lookups
     */
    public int getMaxLookups() {
        return maxLookups;
    }

    /**
     * Sets the maximum number of lookups this matcher performs in one run.
     * Exceeding it fails the build rather than silently leaving files
     * unidentified.
     *
     * @param maxLookups the maximum number of lookups
     */
    public void setMaxLookups(int maxLookups) {
        this.maxLookups = maxLookups;
    }

    public Duration timeout() {
        return Duration.ofMillis(Math.max(1, timeoutMillis));
    }

    /**
     * Returns the URL used when none is configured, or {@code null} if a URL
     * is required.
     */
    String defaultUrl() {
        return null;
    }

    /**
     * Returns the {@code settings.xml} server id whose credentials are sent,
     * or {@code null} for anonymous access.
     */
    String serverId() {
        return null;
    }

    abstract CoordinatesLookup newLookup(HttpClient client, String url, String basicAuthHeader);

    @Override
    public boolean isRemote() {
        return true;
    }

    @Override
    public MavenArtifactMatcher create(MatcherContext context) {
        if (maxLookups <= 0) {
            throw new IllegalArgumentException(
                    "<" + elementName() + "> <maxLookups> must be greater than 0: " + maxLookups);
        }
        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException(
                    "<" + elementName() + "> <timeoutMillis> must be greater than 0: " + timeoutMillis);
        }
        String effectiveUrl = url != null && !url.isBlank() ? url.trim() : defaultUrl();
        if (effectiveUrl == null) {
            throw new IllegalArgumentException("<" + elementName() + "> requires a <url>");
        }
        if (!effectiveUrl.contains(PLACEHOLDER)) {
            throw new IllegalArgumentException("<" + elementName() + "> <url> must contain a " + PLACEHOLDER
                    + " placeholder for the content hash: " + effectiveUrl);
        }
        validateUrl(effectiveUrl);
        String authHeader = context.basicAuthHeader(serverId());
        CoordinatesLookup lookup = newLookup(context.httpClient(), effectiveUrl, authHeader);
        return MavenArtifactMatchers.wrapChecksumLookup(
                lookup, elementName(), maxLookups, context, effectiveIncludes(), effectiveExcludes());
    }

    /**
     * Fails fast if the URL, with the placeholder substituted, is not a
     * syntactically valid http(s) URL.
     */
    private void validateUrl(String effectiveUrl) {
        URI uri;
        try {
            uri = URI.create(effectiveUrl.replace(PLACEHOLDER, "0".repeat(40)));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "<" + elementName() + "> <url> is not a valid URL: " + effectiveUrl, e);
        }
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException(
                    "<" + elementName() + "> <url> must be http or https: " + effectiveUrl);
        }
    }
}
