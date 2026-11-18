package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.List;
import java.util.Optional;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;

/**
 * Identifies an archive entry that no built-in technique could match as a
 * Maven artifact, e.g. by looking up its content hash in a remote repository.
 *
 * <p>
 * A matcher may hold resources for the duration of an SBOM generation run;
 * whoever creates it closes it once the run is done.
 * </p>
 */
public interface MavenArtifactMatcher extends AutoCloseable {

    /**
     * Attempts to identify the given file entry.
     *
     * <p>
     * Implementations must not throw for ordinary "no match" or lookup
     * failures; they report those as an empty result.
     * </p>
     *
     * @param file the unmatched archive entry
     * @return the match, or {@link Optional#empty()} if the entry could not be
     *         identified
     */
    Optional<MavenMatch> match(FileEntry file);

    /**
     * Releases resources held by this matcher. Does nothing by default.
     */
    @Override
    default void close() {
    }

    /**
     * Returns a matcher that offers each entry to the given matchers in order;
     * the first match wins. Closing it closes all given matchers.
     *
     * @param matchers the matchers, in priority order
     * @return the combined matcher
     */
    static MavenArtifactMatcher of(MavenArtifactMatcher... matchers) {
        return of(List.of(matchers));
    }

    /**
     * Returns a matcher that offers each entry to the given matchers in order;
     * the first match wins. Closing it closes all given matchers.
     *
     * @param matchers the matchers, in priority order
     * @return the combined matcher
     */
    static MavenArtifactMatcher of(List<? extends MavenArtifactMatcher> matchers) {
        return new MatcherChain(matchers);
    }
}
