package dev.cyberstamp.maven.assembly.sbom;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.cyclonedx.model.License;
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
        LicenseInfo fromUrl = resolveUrl(url);
        if (fromUrl != null) {
            return fromUrl;
        }
        return tryResolve(name);
    }

    /**
     * Resolves a license URL to an SPDX id, accounting for opensource.org URL churn.
     *
     * <p>
     * OSI license pages have lived at {@code opensource.org/licenses/<slug>} and
     * {@code opensource.org/license/<slug>}, and some slugs were renamed. SPDX
     * license list 3.29.0 rewrote its {@code seeAlso} URLs to
     * {@code opensource.org/license/<SPDX-ID>}, while POMs in the wild keep using
     * the older spellings. The CycloneDX resolver only matches URLs present in the
     * SPDX list it bundles, so for opensource.org URLs this method:
     * </p>
     * <ol>
     * <li>does not resolve bare GNU-family URLs ({@code GPL-2.0}, {@code LGPL-2.1},
     * {@code AGPL-3.0}, ...) at all: they do not say whether the license is
     * "-only" or "-or-later", so the license name decides instead;</li>
     * <li>maps slugs OSI renamed via {@link #OSI_RENAMED_SLUGS};</li>
     * <li>otherwise tries the URL as given, then in both {@code /license/} and
     * {@code /licenses/} spellings.</li>
     * </ol>
     *
     * @param url the license URL, or {@code null}
     * @return an SPDX-id or SPDX-expression {@link LicenseInfo}, or {@code null}
     */
    private LicenseInfo resolveUrl(String url) {
        String slug = osiSlug(url);
        if (slug == null) {
            return tryResolve(url);
        }
        if (AMBIGUOUS_GNU_SLUG.matcher(slug).matches()) {
            return null;
        }
        String renamedId = OSI_RENAMED_SLUGS.get(slug);
        if (renamedId != null) {
            return tryResolve(renamedId);
        }
        LicenseInfo resolved = tryResolve(url);
        if (resolved == null) {
            resolved = tryResolve("https://opensource.org/license/" + slug);
        }
        if (resolved == null) {
            resolved = tryResolve("https://opensource.org/licenses/" + slug);
        }
        return resolved;
    }

    /**
     * Extracts the license slug from an opensource.org license URL.
     *
     * @param url the license URL, or {@code null}
     * @return the lower-cased slug without trailing slashes (e.g. {@code mit} for
     *         {@code https://opensource.org/licenses/MIT/}), or {@code null} if
     *         the URL is not an opensource.org license URL
     */
    static String osiSlug(String url) {
        if (url == null) {
            return null;
        }
        String u = url.trim().toLowerCase(Locale.ROOT);
        int i = u.indexOf("opensource.org/");
        if (i < 0) {
            return null;
        }
        String path = u.substring(i + "opensource.org/".length());
        if (path.startsWith("licenses/")) {
            path = path.substring("licenses/".length());
        } else if (path.startsWith("license/")) {
            path = path.substring("license/".length());
        } else {
            return null;
        }
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.isEmpty() ? null : path;
    }

    /**
     * GNU-family OSI slugs without an "-only"/"-or-later" qualifier.
     */
    private static final Pattern AMBIGUOUS_GNU_SLUG = Pattern.compile("[al]?gpl-\\d+(\\.\\d+)?");

    /**
     * Legacy OSI slugs that do not match the SPDX id of the license they denote.
     * Taken from the {@code seeAlso} URLs of SPDX license list 3.28.0, each of
     * which pointed to exactly one license.
     */
    private static final Map<String, String> OSI_RENAMED_SLUGS = Map.ofEntries(
            Map.entry("apache-2-0", "Apache-2.0"),
            Map.entry("artistic-license-2.0", "Artistic-2.0"),
            Map.entry("attribution", "AAL"),
            Map.entry("bsdpluspatent", "BSD-2-Clause-Patent"),
            Map.entry("cddl1", "CDDL-1.0"),
            Map.entry("nosl3.0", "NPOSL-3.0"),
            Map.entry("olfl-1-3", "OLFL-1.3"),
            Map.entry("opl-2.1", "OSET-PL-2.1"),
            Map.entry("osc-license-1-0", "OSC-1.0"),
            Map.entry("upl", "UPL-1.0"));

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
            License resolved = choice.getLicenses().get(0);
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
