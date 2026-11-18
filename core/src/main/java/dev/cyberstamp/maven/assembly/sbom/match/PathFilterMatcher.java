package dev.cyberstamp.maven.assembly.sbom.match;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;

/**
 * Offers only entries whose archive-relative path matches at least one include
 * glob and no exclude glob to the delegate.
 */
final class PathFilterMatcher implements MavenArtifactMatcher {

    private final MavenArtifactMatcher delegate;
    private final List<PathMatcher> includes;
    private final List<PathMatcher> excludes;

    private PathFilterMatcher(MavenArtifactMatcher delegate, List<PathMatcher> includes, List<PathMatcher> excludes) {
        this.delegate = delegate;
        this.includes = includes;
        this.excludes = excludes;
    }

    /**
     * Wraps the delegate in a glob filter.
     *
     * @return the filtering matcher, or empty if no include glob was given
     * @throws IllegalArgumentException if a glob's syntax is invalid
     */
    static Optional<MavenArtifactMatcher> of(MavenArtifactMatcher delegate, List<String> includeGlobs,
            List<String> excludeGlobs) {
        List<PathMatcher> includes = compile(includeGlobs);
        if (includes.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new PathFilterMatcher(delegate, includes, compile(excludeGlobs)));
    }

    private static List<PathMatcher> compile(List<String> globs) {
        List<PathMatcher> matchers = new ArrayList<>(globs.size());
        for (String glob : globs) {
            if (glob == null || glob.isBlank()) {
                continue;
            }
            try {
                matchers.add(FileSystems.getDefault().getPathMatcher("glob:" + glob.trim()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "Invalid mavenArtifactMatchers glob pattern '" + glob + "': " + e.getMessage(), e);
            }
        }
        return matchers;
    }

    @Override
    public Optional<MavenMatch> match(FileEntry file) {
        return isCandidate(file.archivePath()) ? delegate.match(file) : Optional.empty();
    }

    boolean isCandidate(String archivePath) {
        Path path = Path.of(archivePath);
        return includes.stream().anyMatch(m -> m.matches(path))
                && excludes.stream().noneMatch(m -> m.matches(path));
    }

    @Override
    public void close() {
        delegate.close();
    }
}
