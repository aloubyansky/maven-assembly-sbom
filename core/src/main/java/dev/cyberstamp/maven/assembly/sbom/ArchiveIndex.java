package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Index of archive file entries, providing path and hash lookups
 * used when filtering external/embedded SBOM components against
 * actual archive contents.
 *
 * <p>
 * Built once from the archive's file entries, this index replaces
 * the separate {@code Set<String>} (paths) and
 * {@code Map<String, List<String>>} (hash-to-paths) that were
 * previously passed as individual parameters.
 * </p>
 *
 * @see NestedArchiveIndex
 */
interface ArchiveIndex {

    /**
     * Returns the normalized hash algorithm name (e.g. {@code "sha256"}).
     *
     * @return the algorithm name, normalized via
     *         {@link SbomUtils#normalizeAlgorithm}
     */
    String normalizedAlg();

    /**
     * Returns {@code true} if this index is scoped to a nested archive.
     * Scoped indexes translate paths relative to their parent mount
     * point; unscoped indexes work with archive-root-relative paths.
     *
     * @return {@code true} for {@link NestedArchiveIndex}, {@code false}
     *         for {@link RootArchiveIndex}
     */
    boolean isScoped();

    /**
     * Returns {@code true} if the archive contains a file at the
     * given path. On a scoped index, the path is interpreted relative
     * to the scope (e.g. {@code "WEB-INF/lib/foo.jar"} checks for
     * {@code "web/app.war/WEB-INF/lib/foo.jar"}).
     *
     * @param archivePath the path to check
     * @return {@code true} if the path exists in the archive
     */
    boolean containsPath(String archivePath);

    /**
     * Returns {@code true} if any archive file has the given content
     * hash. On a scoped index, only files under the scope are
     * considered.
     *
     * @param hash the hex-encoded content hash, or {@code null}
     * @return {@code true} if the hash exists (always {@code false}
     *         for {@code null})
     */
    boolean containsHash(String hash);

    /**
     * Returns all archive paths for the given content hash, or
     * {@code null} if no file with that hash exists. Paths are
     * archive-root-relative regardless of scope.
     *
     * <p>
     * Not supported on scoped indexes — use {@link #findPathByHash}
     * instead.
     * </p>
     *
     * @param hash the hex-encoded content hash, or {@code null}
     * @return the matching paths, or {@code null}
     * @throws UnsupportedOperationException on scoped indexes
     */
    List<String> pathsForHash(String hash);

    /**
     * Finds the first archive path for the given content hash. On a
     * scoped index, only paths under the scope are considered and the
     * returned path has the scope prefix stripped (i.e. it is suitable
     * for use as an occurrence location).
     *
     * @param hash the hex-encoded content hash, or {@code null}
     * @return the first matching path, or {@code null}
     */
    String findPathByHash(String hash);

    /**
     * Returns a view scoped to a nested archive's mount point.
     * The returned index translates paths relative to the scope:
     * {@code containsPath("WEB-INF/lib/foo.jar")} checks for
     * {@code "web/app.war/WEB-INF/lib/foo.jar"} in the root
     * index; {@code findPathByHash} returns paths with the
     * prefix stripped.
     *
     * <p>
     * Multi-level nesting is supported: calling {@code scopedTo} on
     * a scoped index composes the prefixes (e.g. scoping
     * {@code "web/app.war/"} then {@code "subapp/"} produces the
     * combined prefix {@code "web/app.war/subapp/"}).
     * </p>
     *
     * @param parentPathPrefix the mount point (e.g. {@code "web/app.war/"}),
     *        or {@code null} to return this index unchanged
     * @return a scoped view, or {@code this} if the prefix is {@code null}
     */
    ArchiveIndex scopedTo(String parentPathPrefix);

    /**
     * Builds the index from archive entries in a single pass,
     * stripping {@code baseDirPrefix} from each entry's path.
     *
     * @param entries the archive file entries with content hashes
     * @param baseDirPrefix prefix to strip from entry paths, or
     *        {@code null}
     * @param algorithmSpec the hash algorithm spec (e.g. {@code "SHA-256"});
     *        normalized via {@link SbomUtils#normalizeAlgorithm}
     * @return an unscoped {@link RootArchiveIndex}
     */
    static ArchiveIndex of(List<FileEntry> entries,
            String baseDirPrefix, String algorithmSpec) {
        Set<String> paths = new HashSet<>(entries.size());
        Map<String, List<String>> hashToPath = new HashMap<>(entries.size());
        for (var e : entries) {
            String path = e.archivePath();
            if (baseDirPrefix != null && path.startsWith(baseDirPrefix)) {
                path = path.substring(baseDirPrefix.length());
            }
            paths.add(path);
            if (e.hash() != null) {
                hashToPath.computeIfAbsent(e.hash(), k -> new ArrayList<>())
                        .add(path);
            }
        }
        return new RootArchiveIndex(paths, hashToPath,
                SbomUtils.normalizeAlgorithm(algorithmSpec));
    }
}
