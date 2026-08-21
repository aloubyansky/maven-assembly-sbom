package dev.cyberstamp.maven.assembly.sbom;

import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.util.LicenseResolver;

/**
 * Maps a raw POM license declaration to a neutral {@link LicenseInfo},
 * resolving SPDX identifiers via the CycloneDX {@link LicenseResolver}.
 *
 * <p>
 * The resolution strategy for each declaration is:
 * </p>
 * <ol>
 * <li>try the URL (URLs point to a specific license text and are more
 * reliable than names);</li>
 * <li>fall back to the name;</li>
 * <li>if neither resolves to an SPDX id or expression, return a raw
 * {@link LicenseInfo} preserving the original name and URL.</li>
 * </ol>
 *
 * <p>
 * This class depends only on CycloneDX (no Maven, no Aether), so it is
 * shared by every {@link LicenseSource}-backed resolver.
 * </p>
 */
final class SpdxLicenseMapper {

    /**
     * Maps a raw license declaration to a neutral license descriptor.
     *
     * @param raw the raw declaration; never {@code null}
     * @return the mapped {@link LicenseInfo}; SPDX id/expression when
     *         resolvable, otherwise a raw (trimmed) name/URL descriptor
     */
    LicenseInfo map(RawLicense raw) {
        LicenseInfo resolved = resolveToSpdx(raw.url(), raw.name());
        if (resolved != null) {
            return resolved;
        }
        return LicenseInfo.raw(trimToNull(raw.name()), trimToNull(raw.url()));
    }

    /**
     * Attempts SPDX resolution, trying the URL first and the name second.
     *
     * @param url the license URL, or {@code null}
     * @param name the license name, or {@code null}
     * @return an SPDX-id or SPDX-expression {@link LicenseInfo}, or
     *         {@code null} if neither input resolves
     */
    private LicenseInfo resolveToSpdx(String url, String name) {
        LicenseInfo fromUrl = tryResolve(url);
        if (fromUrl != null) {
            return fromUrl;
        }
        return tryResolve(name);
    }

    /**
     * Resolves a single string (name or URL) via the CycloneDX resolver.
     *
     * @param licenseString the string to resolve, or {@code null}
     * @return an SPDX-id or SPDX-expression {@link LicenseInfo}, or
     *         {@code null} if the string is blank or unmatched
     */
    private LicenseInfo tryResolve(String licenseString) {
        if (licenseString == null || licenseString.isBlank()) {
            return null;
        }
        LicenseChoice choice = LicenseResolver.resolve(licenseString, false);
        if (choice == null) {
            return null;
        }
        if (choice.getLicenses() != null && !choice.getLicenses().isEmpty()
                && choice.getLicenses().get(0).getId() != null) {
            org.cyclonedx.model.License resolved = choice.getLicenses().get(0);
            return LicenseInfo.spdx(resolved.getId(), resolved.getUrl());
        }
        if (choice.getExpression() != null && choice.getExpression().getValue() != null) {
            return LicenseInfo.expression(choice.getExpression().getValue());
        }
        return null;
    }

    /**
     * Trims a string, returning {@code null} for {@code null} input.
     *
     * @param s the string, or {@code null}
     * @return the trimmed string, or {@code null}
     */
    private static String trimToNull(String s) {
        return s == null ? null : s.trim();
    }
}
