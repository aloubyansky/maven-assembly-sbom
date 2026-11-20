package dev.cyberstamp.maven.assembly.sbom;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Root (unscoped) implementation of {@link ArchiveIndex} that holds
 * the actual path set and hash-to-path map. All lookups are direct
 * against the stored collections with no prefix translation.
 *
 * <p>
 * Instances are created via {@link ArchiveIndex#of}.
 * </p>
 *
 * @see NestedArchiveIndex
 */
final class RootArchiveIndex implements ArchiveIndex {

    private final Set<String> paths;
    /** Every directory holding at least one file, each ending with '/'; built on first use. */
    private Set<String> directories;
    private final Map<String, List<String>> hashToPath;
    private final String normalizedAlg;

    /**
     * @param paths all archive entry paths (archive-root-relative)
     * @param hashToPath content hash to archive paths mapping
     * @param normalizedAlg the normalized hash algorithm name
     */
    RootArchiveIndex(Set<String> paths,
            Map<String, List<String>> hashToPath,
            String normalizedAlg) {
        this.paths = paths;
        this.hashToPath = hashToPath;
        this.normalizedAlg = normalizedAlg;
    }

    @Override
    public String normalizedAlg() {
        return normalizedAlg;
    }

    @Override
    public boolean isScoped() {
        return false;
    }

    @Override
    public boolean containsPath(String archivePath) {
        return paths.contains(archivePath);
    }

    @Override
    public boolean containsDirectory(String directory) {
        if (directories == null) {
            Set<String> dirs = new HashSet<>();
            for (String path : paths) {
                for (int i = path.indexOf('/'); i >= 0; i = path.indexOf('/', i + 1)) {
                    dirs.add(path.substring(0, i + 1));
                }
            }
            directories = dirs;
        }
        return directories.contains(directory);
    }

    @Override
    public boolean containsHash(String hash) {
        return hash != null && hashToPath.containsKey(hash);
    }

    @Override
    public List<String> pathsForHash(String hash) {
        return hash != null ? hashToPath.get(hash) : null;
    }

    @Override
    public String findPathByHash(String hash) {
        List<String> p = pathsForHash(hash);
        return p != null && !p.isEmpty() ? p.get(0) : null;
    }

    @Override
    public ArchiveIndex scopedTo(String parentPathPrefix) {
        if (parentPathPrefix == null) {
            return this;
        }
        return new NestedArchiveIndex(this, parentPathPrefix);
    }
}
