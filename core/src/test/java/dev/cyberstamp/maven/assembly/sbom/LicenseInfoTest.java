package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class LicenseInfoTest {

    @Test
    void spdxFactory() {
        LicenseInfo li = LicenseInfo.spdx("Apache-2.0");
        assertEquals("Apache-2.0", li.spdxId());
        assertTrue(li.isSpdx());
        assertFalse(li.isExpression());
        assertFalse(li.isRaw());
    }

    @Test
    void expressionFactory() {
        LicenseInfo li = LicenseInfo.expression("(MIT OR Apache-2.0)");
        assertEquals("(MIT OR Apache-2.0)", li.expression());
        assertTrue(li.isExpression());
        assertFalse(li.isSpdx());
        assertFalse(li.isRaw());
    }

    @Test
    void rawFactory() {
        LicenseInfo li = LicenseInfo.raw("Proprietary XYZ", "https://example.com/license");
        assertEquals("Proprietary XYZ", li.name());
        assertEquals("https://example.com/license", li.url());
        assertTrue(li.isRaw());
        assertFalse(li.isSpdx());
        assertFalse(li.isExpression());
    }

    @Test
    void rawWithOnlyNameStillRaw() {
        LicenseInfo li = LicenseInfo.raw("Some License", null);
        assertTrue(li.isRaw());
        assertNull(li.url());
    }
}
