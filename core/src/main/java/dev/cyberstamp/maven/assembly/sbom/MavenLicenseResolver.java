package dev.cyberstamp.maven.assembly.sbom;

import java.util.HashMap;
import java.util.Map;

import org.apache.maven.model.Model;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.util.LicenseResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves CycloneDX {@link LicenseChoice} for Maven artifacts by reading
 * license declarations from each artifact's effective POM and mapping them
 * to SPDX license identifiers.
 *
 * <p>
 * The resolution strategy for each Maven license entry is:
 * </p>
 * <ol>
 * <li>Try resolving the license URL via the CycloneDX
 * {@link LicenseResolver}, since URLs point to a specific license text
 * and are more reliable than names</li>
 * <li>If the URL does not resolve, try the license name</li>
 * <li>If neither resolves to an SPDX identifier, create a raw
 * {@link License} preserving the original name and URL</li>
 * </ol>
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

    private final EffectiveModelResolver modelResolver;
    private final boolean failOnMissingLicense;
    private final Map<ArtifactCoords, LicenseChoice> cache = new HashMap<>();

    /**
     * Creates a license resolver backed by the given model resolver.
     *
     * @param modelResolver resolves effective POM models for artifacts
     * @param failOnMissingLicense if {@code true}, throws on artifacts with
     *        no license information; if {@code false},
     *        logs a warning and returns {@code null}
     */
    MavenLicenseResolver(EffectiveModelResolver modelResolver, boolean failOnMissingLicense) {
        this.modelResolver = modelResolver;
        this.failOnMissingLicense = failOnMissingLicense;
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
        if (cache.containsKey(id)) {
            return cache.get(id);
        }

        LicenseChoice result = doResolveLicenses(id, groupId, artifactId, version);
        cache.put(id, result);
        return result;
    }

    /**
     * Performs the actual license resolution without caching.
     */
    private LicenseChoice doResolveLicenses(ArtifactCoords id,
            String groupId, String artifactId, String version) {
        Model model = modelResolver.resolveEffectiveModel(groupId, artifactId, version);
        if (model == null) {
            return handleMissingLicenses(groupId, artifactId, version,
                    "effective model could not be resolved");
        }

        var mavenLicenses = model.getLicenses();
        if (mavenLicenses == null || mavenLicenses.isEmpty()) {
            return handleMissingLicenses(groupId, artifactId, version,
                    "no <licenses> declared in the effective POM");
        }

        LicenseChoice result = new LicenseChoice();
        for (var mavenLicense : mavenLicenses) {
            LicenseChoice resolved = resolveToSpdx(mavenLicense.getUrl(), mavenLicense.getName());
            if (resolved != null) {
                if (resolved.getExpression() != null) {
                    result.setExpression(resolved.getExpression());
                } else if (resolved.getLicenses() != null && !resolved.getLicenses().isEmpty()) {
                    result.addLicense(resolved.getLicenses().get(0));
                }
            } else {
                result.addLicense(createRawLicense(mavenLicense.getName(), mavenLicense.getUrl()));
            }
        }
        return result;
    }

    /**
     * Attempts to resolve a single Maven license to an SPDX identifier
     * or expression, trying the URL first and falling back to the name.
     *
     * <p>
     * URLs are preferred because they point to a specific license
     * text, while POM license names are often ambiguous (e.g.,
     * "The BSD License" could mean BSD-3-Clause or BSD-4-Clause).
     * </p>
     *
     * @param url the license URL, or {@code null}
     * @param name the license name, or {@code null}
     * @return a {@link LicenseChoice} containing either an SPDX license
     *         or expression, or {@code null} if no SPDX match was found
     */
    private LicenseChoice resolveToSpdx(String url, String name) {
        LicenseChoice fromUrl = tryResolve(url);
        if (fromUrl != null) {
            return fromUrl;
        }
        return tryResolve(name);
    }

    /**
     * Attempts to resolve the given string (a license name or URL) to
     * an SPDX license or expression via the CycloneDX
     * {@link LicenseResolver}.
     *
     * @param licenseString the string to resolve, or {@code null}
     * @return the resolved {@link LicenseChoice}, or {@code null} if
     *         the string is {@code null}, blank, or does not match any
     *         SPDX entry
     */
    private LicenseChoice tryResolve(String licenseString) {
        if (licenseString == null || licenseString.isBlank()) {
            return null;
        }
        LicenseChoice choice = LicenseResolver.resolve(licenseString, false);
        if (choice == null) {
            return null;
        }
        if (choice.getLicenses() != null && !choice.getLicenses().isEmpty()
                && choice.getLicenses().get(0).getId() != null) {
            return choice;
        }
        if (choice.getExpression() != null && choice.getExpression().getValue() != null) {
            return choice;
        }
        return null;
    }

    /**
     * Creates a raw CycloneDX {@link License} when SPDX resolution fails,
     * preserving the original name and URL.
     *
     * @param name the license name, or {@code null}
     * @param url the license URL, or {@code null}
     * @return a license with name and/or URL set (no SPDX id)
     */
    private License createRawLicense(String name, String url) {
        License license = new License();
        if (name != null) {
            license.setName(name.trim());
        }
        if (url != null) {
            license.setUrl(url.trim());
        }
        return license;
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
