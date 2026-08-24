package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

import org.cyclonedx.model.LicenseChoice;

/**
 * Resolves licenses for Maven artifacts from their effective POM models.
 *
 * <p>
 * A thin adapter over {@link LicenseEnrichment} wired with an
 * {@link EffectiveModelLicenseSource}: it exists only to expose the
 * effective-model resolution behind the historical
 * {@link #resolveLicenses}/{@link #resolveLicenseInfos} entry points. All
 * resolution, SPDX mapping, caching, and missing-license policy live in
 * {@link LicenseEnrichment}.
 * </p>
 */
class MavenLicenseResolver {

    private final LicenseEnrichment enrichment;

    /**
     * @param modelResolver resolves effective POM models for artifacts
     * @param failOnMissingLicense if {@code true}, throws on artifacts with no
     *        license information; if {@code false}, logs a warning
     */
    MavenLicenseResolver(EffectiveModelResolver modelResolver, boolean failOnMissingLicense) {
        this.enrichment = new LicenseEnrichment(
                new EffectiveModelLicenseSource(modelResolver), failOnMissingLicense);
    }

    /**
     * Resolves license information as neutral {@link LicenseInfo} values.
     *
     * @return the resolved licenses, or an empty list if none are declared
     * @throws LicenseResolutionException if configured to fail on missing
     *         licenses and none are available
     */
    List<LicenseInfo> resolveLicenseInfos(String groupId, String artifactId, String version) {
        return enrichment.resolve(groupId, artifactId, version);
    }

    /**
     * Resolves license information as a CycloneDX {@link LicenseChoice}.
     *
     * @return the resolved licenses, or {@code null} if none are declared
     * @throws LicenseResolutionException if configured to fail on missing
     *         licenses and none are available
     */
    LicenseChoice resolveLicenses(String groupId, String artifactId, String version) {
        List<LicenseInfo> infos = enrichment.resolve(groupId, artifactId, version);
        return infos.isEmpty() ? null : CycloneDxLicenses.toLicenseChoice(infos);
    }
}
