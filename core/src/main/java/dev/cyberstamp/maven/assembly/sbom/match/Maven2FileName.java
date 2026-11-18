package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;

/**
 * Derives the classifier and extension from a Maven2-layout file name
 * ({@code <artifactId>-<version>[-<classifier>].<extension>}), shared by the
 * checksum-search backends whose own response does not carry classifier
 * information directly (Artifactory's storage path, Maven Central's file name).
 */
final class Maven2FileName {

    /**
     * The {@code yyyyMMdd.HHmmss-buildNumber} part of a timestamped snapshot file name.
     */
    private static final Pattern SNAPSHOT_TIMESTAMP = Pattern.compile("\\d{8}\\.\\d{6}-\\d+");

    private Maven2FileName() {
    }

    /**
     * Derives the classifier and extension from a Maven2-layout file name,
     * including timestamped snapshots
     * ({@code <artifactId>-1.0-20240101.123456-1[-<classifier>].<extension>}).
     * A classifier ends at its first dot, so classifiers that themselves
     * contain a dot are misread. Falls back to coordinates without a
     * classifier if the name does not start with {@code <artifactId>-<version>}.
     */
    static ArtifactCoords classifierAndExtension(String groupId, String artifactId, String version, String fileName) {
        ArtifactCoords plain = ArtifactCoords.of(groupId, artifactId, version);
        String prefix = artifactId + "-";
        if (!fileName.startsWith(prefix)) {
            return plain;
        }
        String rest = fileName.substring(prefix.length());
        int versionLength = fileVersionLength(rest, version);
        if (versionLength < 0) {
            return plain;
        }
        String tail = rest.substring(versionLength);
        if (tail.startsWith(".") && tail.length() > 1) {
            return new ArtifactCoords(groupId, artifactId, version, tail.substring(1), null);
        }
        int dot = tail.indexOf('.');
        if (tail.startsWith("-") && dot > 1 && dot < tail.length() - 1) {
            return new ArtifactCoords(groupId, artifactId, version, tail.substring(dot + 1), tail.substring(1, dot));
        }
        return plain;
    }

    /**
     * Returns the length of the version as it appears at the start of
     * {@code rest}: the version itself, or for a snapshot either
     * {@code X-SNAPSHOT} or its timestamped form; {@code -1} if neither.
     */
    private static int fileVersionLength(String rest, String version) {
        if (rest.startsWith(version)) {
            return version.length();
        }
        String snapshotSuffix = "SNAPSHOT";
        if (!version.endsWith("-" + snapshotSuffix)) {
            return -1;
        }
        String base = version.substring(0, version.length() - snapshotSuffix.length());
        if (!rest.startsWith(base)) {
            return -1;
        }
        Matcher timestamp = SNAPSHOT_TIMESTAMP.matcher(rest).region(base.length(), rest.length());
        return timestamp.lookingAt() ? timestamp.end() : -1;
    }
}
