package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.license.Expression;

/**
 * Converts neutral {@link LicenseInfo} to CycloneDX {@link LicenseChoice}.
 *
 * <p>
 * This is the single authority for mapping ecosystem-neutral license
 * descriptors into the CycloneDX SBOM format. Both {@code MavenLicenseResolver}
 * (which resolves from Maven POMs) and {@code BomRenderer} (which renders
 * components into BOMs) delegate to this converter, ensuring consistent
 * license encoding across the assembly.
 * </p>
 */
public final class CycloneDxLicenses {

    private CycloneDxLicenses() {
        // utility class
    }

    /**
     * Converts a list of neutral license descriptors into a CycloneDX
     * {@link LicenseChoice}.
     *
     * <p>
     * Mapping rules:
     * </p>
     * <ul>
     * <li><strong>SPDX id</strong> ({@link LicenseInfo#isSpdx()}) → emits
     * {@link License#setId(String)} plus {@link License#setUrl(String)} if
     * the info carries a resolved URL;</li>
     * <li><strong>SPDX expression</strong>
     * ({@link LicenseInfo#isExpression()}) → emits
     * {@link LicenseChoice#setExpression(Expression)} with the expression
     * text;</li>
     * <li><strong>Raw</strong> ({@link LicenseInfo#isRaw()}) → emits a
     * {@link License} with {@link License#setName(String)} and/or
     * {@link License#setUrl(String)} from the info's {@link LicenseInfo#name()}
     * and {@link LicenseInfo#url()} (null-checked).</li>
     * </ul>
     *
     * <p>
     * Returns {@code null} for a {@code null} or empty input list, allowing
     * callers to omit the {@code <licenses>} element entirely when no license
     * metadata is available.
     * </p>
     *
     * @param infos a list of license descriptors, or {@code null}
     * @return the CycloneDX license choice, or {@code null} if the input is
     *         {@code null} or empty
     */
    public static LicenseChoice toLicenseChoice(List<LicenseInfo> infos) {
        if (infos == null || infos.isEmpty()) {
            return null;
        }
        LicenseChoice result = new LicenseChoice();
        for (LicenseInfo info : infos) {
            if (info.isExpression()) {
                result.setExpression(new Expression(info.expression()));
            } else if (info.isSpdx()) {
                License license = new License();
                license.setId(info.spdxId());
                if (info.url() != null) {
                    license.setUrl(info.url());
                }
                result.addLicense(license);
            } else {
                License license = new License();
                if (info.name() != null) {
                    license.setName(info.name());
                }
                if (info.url() != null) {
                    license.setUrl(info.url());
                }
                result.addLicense(license);
            }
        }
        return result;
    }
}
