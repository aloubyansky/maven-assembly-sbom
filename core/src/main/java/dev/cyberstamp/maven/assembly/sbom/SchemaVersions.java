package dev.cyberstamp.maven.assembly.sbom;

import org.cyclonedx.Version;

/**
 * Resolves CycloneDX schema version strings to {@link Version} constants.
 *
 * <p>
 * This is the single source of truth for the schema version a producer should
 * emit: a {@code null} or blank request resolves to {@link #latest()}, the most
 * recent version supported by the integrated CycloneDX library, so the default
 * tracks the library rather than being pinned in code.
 * </p>
 *
 * <p>
 * The class is a stateless utility and cannot be instantiated.
 * </p>
 */
public final class SchemaVersions {

    private SchemaVersions() {
    }

    /**
     * Returns the latest CycloneDX schema version supported by the integrated
     * CycloneDX library.
     *
     * @return the latest supported version, never {@code null}
     */
    public static Version latest() {
        Version[] versions = Version.values();
        return versions[versions.length - 1];
    }

    /**
     * Resolves a user-supplied schema version string (e.g. {@code "1.6"}) to the
     * corresponding {@link Version} constant.
     *
     * @param value the version string, or {@code null}/blank for the default
     * @return the resolved version, never {@code null}
     * @throws IllegalArgumentException if {@code value} is non-blank and matches
     *         no known CycloneDX schema version
     */
    public static Version resolve(String value) {
        if (value == null || value.isBlank()) {
            return latest();
        }
        String trimmed = value.trim();
        for (Version v : Version.values()) {
            if (v.getVersionString().equals(trimmed)) {
                return v;
            }
        }
        throw new IllegalArgumentException(
                "Unsupported CycloneDX schema version: '" + value
                        + "'. Supported values: " + supported());
    }

    /**
     * Returns the supported schema version strings, comma-separated, in ascending
     * order.
     *
     * @return the comma-separated list of supported version strings
     */
    public static String supported() {
        StringBuilder sb = new StringBuilder();
        Version[] versions = Version.values();
        sb.append(versions[0].getVersionString());
        for (int i = 1; i < versions.length; i++) {
            sb.append(", ").append(versions[i].getVersionString());
        }
        return sb.toString();
    }
}
