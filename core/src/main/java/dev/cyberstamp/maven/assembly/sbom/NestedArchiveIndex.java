package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

/**
 * A scoped view of an {@link ArchiveIndex} for a nested archive
 * (e.g. a WAR unpacked inside the distribution). All lookups are
 * automatically translated: paths are prefixed on input and
 * un-prefixed on output.
 *
 * <p>
 * Multi-level nesting is supported — calling {@link #scopedTo}
 * on a {@code NestedArchiveIndex} composes the prefixes against
 * the same root index.
 * </p>
 */
final class NestedArchiveIndex implements ArchiveIndex {

    private final ArchiveIndex root;
    private final String prefix;

    /**
     * @param root the root index to delegate lookups to
     * @param prefix the archive path prefix for this scope
     *        (e.g. {@code "web/app.war/"})
     */
    NestedArchiveIndex(ArchiveIndex root, String prefix) {
        this.root = root;
        this.prefix = prefix;
    }

    @Override
    public String normalizedAlg() {
        return root.normalizedAlg();
    }

    @Override
    public boolean isScoped() {
        return true;
    }

    @Override
    public boolean containsPath(String archivePath) {
        return root.containsPath(prefix + archivePath);
    }

    @Override
    public boolean containsHash(String hash) {
        return findPathByHash(hash) != null;
    }

    @Override
    public List<String> pathsForHash(String hash) {
        throw new UnsupportedOperationException(
                "use findPathByHash on scoped indexes");
    }

    @Override
    public String findPathByHash(String hash) {
        if (hash == null) {
            return null;
        }
        List<String> paths = root.pathsForHash(hash);
        if (paths == null) {
            return null;
        }
        for (String path : paths) {
            if (path.startsWith(prefix)) {
                return path.substring(prefix.length());
            }
        }
        return null;
    }

    @Override
    public ArchiveIndex scopedTo(String parentPathPrefix) {
        if (parentPathPrefix == null) {
            return this;
        }
        return new NestedArchiveIndex(root, prefix + parentPathPrefix);
    }
}
