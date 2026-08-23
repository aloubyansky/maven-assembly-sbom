package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.cyclonedx.model.LicenseChoice;
import org.junit.jupiter.api.Test;

class CycloneDxLicensesTest {

    @Test
    void spdxEmitsIdAndUrl() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(
                List.of(LicenseInfo.spdx("Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0")));
        assertEquals(1, lc.getLicenses().size());
        assertEquals("Apache-2.0", lc.getLicenses().get(0).getId());
        assertEquals("https://www.apache.org/licenses/LICENSE-2.0", lc.getLicenses().get(0).getUrl());
        assertNull(lc.getLicenses().get(0).getName());
    }

    @Test
    void expressionEmitsExpression() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(
                List.of(LicenseInfo.expression("(CDDL-1.0 OR GPL-2.0-with-classpath-exception)")));
        assertNotNull(lc.getExpression());
        assertEquals("(CDDL-1.0 OR GPL-2.0-with-classpath-exception)", lc.getExpression().getValue());
    }

    @Test
    void rawEmitsNameAndUrl() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(List.of(LicenseInfo.raw("Proprietary XYZ", "https://x/l")));
        assertEquals("Proprietary XYZ", lc.getLicenses().get(0).getName());
        assertEquals("https://x/l", lc.getLicenses().get(0).getUrl());
        assertNull(lc.getLicenses().get(0).getId());
    }

    @Test
    void nullOrEmptyYieldsNull() {
        assertNull(CycloneDxLicenses.toLicenseChoice(null));
        assertNull(CycloneDxLicenses.toLicenseChoice(List.of()));
    }

    @Test
    void spdxWithoutUrlEmitsIdOnly() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(
                List.of(LicenseInfo.spdx("MIT", null)));
        assertEquals(1, lc.getLicenses().size());
        assertEquals("MIT", lc.getLicenses().get(0).getId());
        assertNull(lc.getLicenses().get(0).getUrl());
    }

    @Test
    void rawWithOnlyUrl() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(
                List.of(LicenseInfo.raw(null, "https://example.com")));
        assertEquals(1, lc.getLicenses().size());
        assertNull(lc.getLicenses().get(0).getName());
        assertEquals("https://example.com", lc.getLicenses().get(0).getUrl());
    }

    @Test
    void rawWithOnlyName() {
        LicenseChoice lc = CycloneDxLicenses.toLicenseChoice(
                List.of(LicenseInfo.raw("Custom License", null)));
        assertEquals(1, lc.getLicenses().size());
        assertEquals("Custom License", lc.getLicenses().get(0).getName());
        assertNull(lc.getLicenses().get(0).getUrl());
    }
}
