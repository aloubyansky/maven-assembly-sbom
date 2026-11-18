package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.Objects;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.Identification;

/**
 * A Maven artifact identified by a {@link MavenArtifactMatcher}.
 *
 * @param coords the identified coordinates; never {@code null}
 * @param identification how the coordinates were determined; never {@code null}
 */
public record MavenMatch(ArtifactCoords coords, Identification identification) {

    public MavenMatch {
        Objects.requireNonNull(coords, "coords");
        Objects.requireNonNull(identification, "identification");
    }
}
