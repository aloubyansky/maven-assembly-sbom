package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.Optional;

/**
 * Looks up Maven coordinates for a SHA-1 content hash against a single
 * remote package repository (e.g. Maven Central, Nexus, Artifactory).
 */
public interface CoordinatesLookup {

    /**
     * Looks up the artifact whose content hash matches the given SHA-1.
     *
     * <p>
     * Implementations must not throw for ordinary "not found", network, or
     * parsing failures; they report those as an empty result and let the
     * caller decide whether to try another backend.
     * </p>
     *
     * @param sha1Hex the lowercase hex-encoded SHA-1 content hash
     * @param fileName the archive entry's own file name, or {@code null} if
     *        unknown; backends that have no better source of classifier
     *        information may use it as a hint (e.g. {@code MavenCentralCoordinatesLookup})
     * @return the matched coordinates and how confidently they were
     *         determined, or {@link Optional#empty()} if no match was found
     *         or the lookup failed
     */
    Optional<MavenMatch> lookup(String sha1Hex, String fileName);
}
