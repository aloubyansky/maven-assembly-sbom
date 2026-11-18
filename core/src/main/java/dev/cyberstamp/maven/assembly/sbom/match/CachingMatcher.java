package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;

/**
 * Remembers the delegate's result per content SHA-1, so a file that appears
 * several times in the assembly (or identical files at different paths) is
 * matched only once. Entries without a readable source file are passed
 * through uncached.
 */
final class CachingMatcher implements MavenArtifactMatcher {

    private final MavenArtifactMatcher delegate;
    private final Sha1Hasher hasher;
    private final Map<String, Optional<MavenMatch>> cache = new HashMap<>();

    CachingMatcher(MavenArtifactMatcher delegate, Sha1Hasher hasher) {
        this.delegate = delegate;
        this.hasher = hasher;
    }

    @Override
    public Optional<MavenMatch> match(FileEntry file) {
        Optional<String> sha1 = hasher.sha1(file);
        if (sha1.isEmpty()) {
            return delegate.match(file);
        }
        Optional<MavenMatch> cached = cache.get(sha1.get());
        if (cached != null) {
            return cached;
        }
        Optional<MavenMatch> result = delegate.match(file);
        cache.put(sha1.get(), result);
        return result;
    }

    @Override
    public void close() {
        delegate.close();
    }
}
