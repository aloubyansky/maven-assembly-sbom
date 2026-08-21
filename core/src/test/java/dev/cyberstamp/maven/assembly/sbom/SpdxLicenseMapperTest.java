package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SpdxLicenseMapperTest {

    private final SpdxLicenseMapper mapper = new SpdxLicenseMapper();

    @Test
    void mapsApacheNameToSpdxId() {
        LicenseInfo li = mapper.map(new RawLicense("The Apache Software License, Version 2.0", null));
        assertTrue(li.isSpdx());
        assertEquals("Apache-2.0", li.spdxId());
    }

    @Test
    void prefersUrlOverAmbiguousName() {
        LicenseInfo li = mapper.map(
                new RawLicense("The BSD License", "https://opensource.org/licenses/BSD-3-Clause"));
        assertTrue(li.isSpdx());
        assertEquals("BSD-3-Clause", li.spdxId());
    }

    @Test
    void mapsDualLicenseNameToExpression() {
        LicenseInfo li = mapper.map(new RawLicense("CDDL + GPLv2 with classpath exception", null));
        assertTrue(li.isExpression());
        assertEquals("(CDDL-1.0 OR GPL-2.0-with-classpath-exception)", li.expression());
    }

    @Test
    void fallsBackToRawWhenNoSpdxMatch() {
        LicenseInfo li = mapper.map(new RawLicense("Proprietary License XYZ", "https://example.com/license"));
        assertTrue(li.isRaw());
        assertEquals("Proprietary License XYZ", li.name());
        assertEquals("https://example.com/license", li.url());
    }

    @Test
    void trimsRawNameAndUrl() {
        LicenseInfo li = mapper.map(new RawLicense("  Weird Name  ", "  https://example.com/x  "));
        assertTrue(li.isRaw());
        assertEquals("Weird Name", li.name());
        assertEquals("https://example.com/x", li.url());
    }

    @Test
    void rawWithNullNameAndUrlStaysNull() {
        LicenseInfo li = mapper.map(new RawLicense(null, null));
        assertTrue(li.isRaw());
        assertNull(li.name());
        assertNull(li.url());
    }

    @Test
    void spdxResolutionPreservesResolvedUrl() {
        SpdxLicenseMapper mapper = new SpdxLicenseMapper();
        LicenseInfo info = mapper.map(new RawLicense("Apache License 2.0", "https://www.apache.org/licenses/LICENSE-2.0"));
        assertTrue(info.isSpdx());
        assertEquals("Apache-2.0", info.spdxId());
        assertNotNull(info.url(),
                "resolved SPDX licenses must retain the canonical URL (byte-identity with MavenLicenseResolver)");
    }
}
