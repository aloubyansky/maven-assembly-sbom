package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.Optional;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;
import dev.cyberstamp.maven.assembly.sbom.SbomUtils;

/**
 * Adapts a SHA-1-keyed {@link CoordinatesLookup} (one remote repository) to a
 * {@link MavenArtifactMatcher}.
 */
final class ChecksumLookupMatcher implements MavenArtifactMatcher {

    private final CoordinatesLookup lookup;
    private final Sha1Hasher hasher;

    ChecksumLookupMatcher(CoordinatesLookup lookup, Sha1Hasher hasher) {
        this.lookup = lookup;
        this.hasher = hasher;
    }

    @Override
    public Optional<MavenMatch> match(FileEntry file) {
        String fileName = SbomUtils.extractFileName(file.archivePath());
        return hasher.sha1(file).flatMap(sha1 -> lookup.lookup(sha1, fileName));
    }
}
