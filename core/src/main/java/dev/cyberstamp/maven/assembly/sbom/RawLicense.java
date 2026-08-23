package dev.cyberstamp.maven.assembly.sbom;

/**
 * A license declaration as read from a POM, before any SPDX mapping.
 *
 * <p>
 * This is the neutral hand-off between a {@link LicenseSource} (which
 * knows how to obtain POM data) and the {@link SpdxLicenseMapper} (which
 * maps names/URLs to SPDX identifiers). It intentionally carries no Maven
 * or CycloneDX types.
 * </p>
 *
 * @param name the declared license name, or {@code null}
 * @param url the declared license URL, or {@code null}
 */
public record RawLicense(String name, String url) {
}
