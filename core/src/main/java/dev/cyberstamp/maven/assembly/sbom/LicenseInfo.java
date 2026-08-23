package dev.cyberstamp.maven.assembly.sbom;

/**
 * An ecosystem- and format-neutral license descriptor.
 *
 * <p>
 * Exactly one representation is meaningful per instance:
 * </p>
 * <ul>
 * <li>an SPDX license id ({@link #spdxId()}), e.g. {@code "Apache-2.0"};</li>
 * <li>an SPDX license expression ({@link #expression()}), e.g.
 * {@code "(CDDL-1.0 OR GPL-2.0-with-classpath-exception)"}; or</li>
 * <li>a raw name and/or URL ({@link #name()}/{@link #url()}) when no SPDX
 * match was found.</li>
 * </ul>
 *
 * <p>
 * Keeping this type free of CycloneDX classes lets the neutral component
 * model stay independent of the SBOM output format; a renderer converts
 * {@code LicenseInfo} into CycloneDX license structures.
 * </p>
 *
 * @param spdxId the SPDX license id, or {@code null}
 * @param expression the SPDX license expression, or {@code null}
 * @param name the raw license name, or {@code null}
 * @param url the raw license URL, or {@code null}
 */
public record LicenseInfo(String spdxId, String expression, String name, String url) {

    /**
     * Creates a license identified by an SPDX id, carrying the resolver's
     * canonical URL for that license so renderers can reproduce it.
     *
     * @param spdxId the SPDX license id
     * @param url the resolved canonical license URL, or {@code null}
     * @return an SPDX-id license
     */
    public static LicenseInfo spdx(String spdxId, String url) {
        return new LicenseInfo(spdxId, null, null, url);
    }

    /**
     * Creates a license identified by an SPDX id with no URL.
     *
     * @param spdxId the SPDX license id
     * @return an SPDX-id license
     */
    public static LicenseInfo spdx(String spdxId) {
        return spdx(spdxId, null);
    }

    /**
     * Creates a license identified by an SPDX license expression.
     *
     * @param expression the SPDX license expression
     * @return an expression license
     */
    public static LicenseInfo expression(String expression) {
        return new LicenseInfo(null, expression, null, null);
    }

    /**
     * Creates a raw license preserving the original name and/or URL.
     *
     * @param name the license name, or {@code null}
     * @param url the license URL, or {@code null}
     * @return a raw license
     */
    public static LicenseInfo raw(String name, String url) {
        return new LicenseInfo(null, null, name, url);
    }

    /**
     * @return {@code true} if this is an SPDX-id license
     */
    public boolean isSpdx() {
        return spdxId != null;
    }

    /**
     * @return {@code true} if this is an SPDX-expression license
     */
    public boolean isExpression() {
        return expression != null;
    }

    /**
     * @return {@code true} if this is a raw (non-SPDX) license
     */
    public boolean isRaw() {
        return spdxId == null && expression == null;
    }
}
