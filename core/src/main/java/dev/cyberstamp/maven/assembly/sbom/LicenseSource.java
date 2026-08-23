package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

/**
 * Supplies the raw {@code <licenses>} declarations for a Maven artifact.
 *
 * <p>
 * This is the seam that lets license resolution be shared across
 * environments with different POM-access mechanisms, returning
 * neutral {@link RawLicense} values so the shared {@link SpdxLicenseMapper}
 * and the neutral component model never depend on Maven Model types.
 * </p>
 */
public interface LicenseSource {

    /**
     * Returns the license declarations for the given artifact.
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the declared licenses, or an empty list if none are declared
     *         or the POM cannot be resolved; never {@code null}
     */
    List<RawLicense> licensesFor(String groupId, String artifactId, String version);
}
