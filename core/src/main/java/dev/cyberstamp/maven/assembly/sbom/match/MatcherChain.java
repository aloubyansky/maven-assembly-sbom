package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.List;
import java.util.Optional;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;

/**
 * Offers each entry to its matchers in order; the first match wins.
 *
 * @see MavenArtifactMatcher#of(List)
 */
final class MatcherChain implements MavenArtifactMatcher {

    private final List<MavenArtifactMatcher> matchers;

    MatcherChain(List<? extends MavenArtifactMatcher> matchers) {
        this.matchers = List.copyOf(matchers);
    }

    @Override
    public Optional<MavenMatch> match(FileEntry file) {
        for (MavenArtifactMatcher matcher : matchers) {
            Optional<MavenMatch> match = matcher.match(file);
            if (match.isPresent()) {
                return match;
            }
        }
        return Optional.empty();
    }

    /**
     * Closes every matcher, even if closing an earlier one fails; the first
     * failure is rethrown with any later ones suppressed.
     */
    @Override
    public void close() {
        RuntimeException failure = null;
        for (MavenArtifactMatcher matcher : matchers) {
            try {
                matcher.close();
            } catch (RuntimeException e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
    }
}
