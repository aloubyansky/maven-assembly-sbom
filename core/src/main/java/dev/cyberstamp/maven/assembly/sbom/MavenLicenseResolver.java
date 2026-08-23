package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cyclonedx.model.LicenseChoice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves CycloneDX {@link LicenseChoice} for Maven artifacts by delegating
 * to a {@link LicenseSource} and {@link SpdxLicenseMapper}.
 *
 * <p>
 * This resolver wraps an {@link EffectiveModelLicenseSource} (which extracts
 * raw license declarations from Maven effective POMs) and an
 * {@link SpdxLicenseMapper} (which maps those declarations to SPDX identifiers).
 * The mapped licenses are then converted to CycloneDX format via
 * {@link CycloneDxLicenses#toLicenseChoice(List)}.
 * </p>
 *
 * <p>
 * Behavior when an artifact has no license information is controlled by the
 * {@code failOnMissingLicense} flag: when {@code true}, a
 * {@link LicenseResolutionException} is thrown; when {@code false} (default),
 * a warning is logged and {@code null} is returned.
 * </p>
 */
class MavenLicenseResolver {

    private static final Logger log = LoggerFactory.getLogger(MavenLicenseResolver.class);

    private final SpdxLicenseMapper mapper;
    private final EffectiveModelLicenseSource licenseSource;
    private final boolean failOnMissingLicense;
    /**
     * Per-GAV resolution cache keyed by coordinates. A stored {@code null}
     * value marks a GAV that resolved to no license information (the
     * missing-license policy already applied on first resolution); a non-null
     * list holds the resolved licenses. {@link #resolveLicenses} derives its
     * {@link LicenseChoice} from the same cached list, so both entry points
     * resolve each GAV exactly once.
     */
    private final Map<ArtifactCoords, List<LicenseInfo>> cache = new HashMap<>();

    /**
     * Creates a license resolver backed by the given model resolver.
     *
     * @param modelResolver resolves effective POM models for artifacts
     * @param failOnMissingLicense if {@code true}, throws on artifacts with
     *        no license information; if {@code false},
     *        logs a warning and returns {@code null}
     */
    MavenLicenseResolver(EffectiveModelResolver modelResolver, boolean failOnMissingLicense) {
        this.mapper = new SpdxLicenseMapper();
        this.licenseSource = new EffectiveModelLicenseSource(modelResolver);
        this.failOnMissingLicense = failOnMissingLicense;
    }

    /**
     * Resolves license information for the given Maven artifact as a
     * neutral {@link LicenseInfo} list.
     *
     * <p>
     * Builds the artifact's effective POM model, extracts its
     * {@code <licenses>} declarations, and maps each to a neutral
     * {@link LicenseInfo} record. This method shares the same cache and
     * {@code failOnMissingLicense} behavior as {@link #resolveLicenses}, and
     * resolves identically for the same GAV.
     * </p>
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the resolved license information, or an empty list if no
     *         licenses are declared in the effective model
     * @throws LicenseResolutionException if {@code failOnMissingLicense} is
     *         {@code true} and no license information is available
     */
    List<LicenseInfo> resolveLicenseInfos(String groupId, String artifactId, String version) {
        ArtifactCoords id = ArtifactCoords.of(groupId, artifactId, version);
        List<LicenseInfo> infos = resolveInfosCached(id, groupId, artifactId, version);
        return infos == null ? List.of() : infos;
    }

    /**
     * Resolves the license information for the given Maven artifact.
     *
     * <p>
     * Builds the artifact's effective POM model, extracts its
     * {@code <licenses>} declarations, and maps each to a CycloneDX
     * {@link License} with an SPDX identifier where possible.
     * </p>
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the resolved license information, or {@code null} if no
     *         licenses are declared in the effective model
     * @throws LicenseResolutionException if {@code failOnMissingLicense} is
     *         {@code true} and no license information is available
     */
    LicenseChoice resolveLicenses(String groupId, String artifactId, String version) {
        ArtifactCoords id = ArtifactCoords.of(groupId, artifactId, version);
        List<LicenseInfo> infos = resolveInfosCached(id, groupId, artifactId, version);
        return infos == null ? null : CycloneDxLicenses.toLicenseChoice(infos);
    }

    /**
     * Resolves the neutral license list for a GAV, caching the result so
     * that both {@link #resolveLicenseInfos} and {@link #resolveLicenses}
     * resolve each GAV exactly once and apply the missing-license policy
     * only on first resolution.
     *
     * @return the resolved licenses, or {@code null} if none are declared
     * @throws LicenseResolutionException if {@code failOnMissingLicense} is
     *         {@code true} and no license information is available
     */
    private List<LicenseInfo> resolveInfosCached(ArtifactCoords id,
            String groupId, String artifactId, String version) {
        if (cache.containsKey(id)) {
            return cache.get(id);
        }
        List<RawLicense> raws = licenseSource.licensesFor(groupId, artifactId, version);
        if (raws.isEmpty()) {
            // Distinguish "no model" vs "model without <licenses>" only for the
            // warning/throw message; both map to the missing-license policy.
            handleMissingLicenses(groupId, artifactId, version,
                    "no license information in the effective model");
            cache.put(id, null);
            return null;
        }
        List<LicenseInfo> infos = new ArrayList<>(raws.size());
        for (RawLicense raw : raws) {
            infos.add(mapper.map(raw));
        }
        cache.put(id, infos);
        return infos;
    }

    /**
     * Handles the case when no license information is available for an
     * artifact, either by throwing or logging depending on configuration.
     *
     * @param groupId the artifact groupId
     * @param artifactId the artifact artifactId
     * @param version the artifact version
     * @param reason a human-readable explanation of why licenses are missing
     * @return always {@code null} (when not throwing)
     * @throws LicenseResolutionException if {@code failOnMissingLicense} is {@code true}
     */
    private LicenseChoice handleMissingLicenses(String groupId, String artifactId,
            String version, String reason) {
        String gav = ArtifactCoords.of(groupId, artifactId, version).toGav();
        if (failOnMissingLicense) {
            throw new LicenseResolutionException(
                    "No license information for " + gav + ": " + reason);
        }
        log.warn("No license information for {}: {}", gav, reason);
        return null;
    }
}
