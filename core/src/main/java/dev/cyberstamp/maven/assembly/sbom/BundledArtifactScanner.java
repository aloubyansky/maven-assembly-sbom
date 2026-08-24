package dev.cyberstamp.maven.assembly.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Scans an artifact for bundled (shaded) Maven artifacts by reading its
 * {@code META-INF/maven/&#42;/pom.properties} descriptors. This is the single
 * shared implementation used by {@link ShadedJarDetection} (over resolvable
 * artifacts) and by {@link ArchiveAnalyzer} (over JARs nested inside staged
 * archives).
 *
 * <p>
 * An artifact is "shaded" when it carries more than one such descriptor; the
 * non-owner descriptors identify the bundled artifacts. Both packaged JARs and
 * exploded directories (unpacked artifacts) are handled uniformly.
 * </p>
 */
final class BundledArtifactScanner {

    private static final Logger log = LoggerFactory.getLogger(BundledArtifactScanner.class);

    private BundledArtifactScanner() {
    }

    /**
     * Scans an artifact at the given path, handling both forms uniformly: a
     * regular file is opened as a ZIP archive; a directory (an exploded/unpacked
     * artifact, e.g. a reactor module resolved to {@code target/classes}) is
     * walked on the filesystem. A missing path yields no bundled artifacts. No
     * extension filtering is applied — a regular file that is not a ZIP falls
     * through to the graceful error path.
     */
    static List<ArtifactCoords> bundledNonOwner(Path artifact, ArtifactCoords owner) {
        if (artifact == null) {
            return List.of();
        }
        if (Files.isDirectory(artifact)) {
            return bundledNonOwnerFromDirectory(artifact, owner);
        }
        if (!Files.isRegularFile(artifact)) {
            return List.of();
        }
        try (ZipFile zf = new ZipFile(artifact.toFile())) {
            return bundledNonOwner(zf, owner);
        } catch (IOException e) {
            log.debug("Could not scan {} for bundled artifacts", artifact, e);
            return List.of();
        }
    }

    /** Scans an already-open JAR. */
    static List<ArtifactCoords> bundledNonOwner(ZipFile zf, ArtifactCoords owner) {
        List<Properties> props = new ArrayList<>();
        Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (isPomProperties(ze.getName())) {
                try (InputStream is = zf.getInputStream(ze)) {
                    props.add(load(is));
                } catch (IOException e) {
                    log.debug("Could not read {} from {}", ze.getName(), zf.getName(), e);
                }
            }
        }
        return nonOwner(props, owner);
    }

    /** Scans JAR bytes streamed from within another archive. */
    static List<ArtifactCoords> bundledNonOwner(InputStream nestedJar, ArtifactCoords owner) {
        List<Properties> props = new ArrayList<>();
        try {
            ZipInputStream zis = new ZipInputStream(nestedJar);
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                if (isPomProperties(ze.getName())) {
                    props.add(load(zis));
                }
            }
        } catch (IOException e) {
            log.debug("Could not scan nested JAR for bundled artifacts", e);
        }
        return nonOwner(props, owner);
    }

    private static List<ArtifactCoords> bundledNonOwnerFromDirectory(Path dir, ArtifactCoords owner) {
        List<Properties> props = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(dir)) {
            for (Path p : (Iterable<Path>) walk.filter(Files::isRegularFile)
                    .filter(BundledArtifactScanner::isPomPropertiesPath)::iterator) {
                try (InputStream is = Files.newInputStream(p)) {
                    props.add(load(is));
                }
            }
        } catch (IOException e) {
            log.debug("Could not scan exploded artifact {} for bundled artifacts", dir, e);
        }
        return nonOwner(props, owner);
    }

    private static boolean isPomProperties(String name) {
        return name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties");
    }

    private static boolean isPomPropertiesPath(Path p) {
        String s = p.toString().replace('\\', '/');
        return s.contains("/META-INF/maven/") && s.endsWith("/pom.properties");
    }

    private static Properties load(InputStream is) throws IOException {
        Properties p = new Properties();
        p.load(is);
        return p;
    }

    /**
     * Filters already-read descriptors to the coordinates of bundled non-owner
     * artifacts (empty when there is at most one descriptor). Shared with
     * {@link ArchiveAnalyzer}, which reads descriptors itself for owner-by-name
     * resolution and reuses this filter for the bundled remainder.
     */
    static List<ArtifactCoords> nonOwner(List<Properties> all, ArtifactCoords owner) {
        if (all.size() <= 1) {
            return List.of();
        }
        List<ArtifactCoords> result = new ArrayList<>();
        for (Properties p : all) {
            String g = p.getProperty("groupId");
            String a = p.getProperty("artifactId");
            String v = p.getProperty("version");
            if (g == null || a == null || v == null) {
                continue;
            }
            if (g.equals(owner.groupId()) && a.equals(owner.artifactId())
                    && v.equals(owner.version())) {
                continue;
            }
            result.add(ArtifactCoords.of(g, a, v));
        }
        return result;
    }
}
