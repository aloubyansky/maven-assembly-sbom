package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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

    /**
     * The SPDX license list changed OSI URLs from {@code opensource.org/licenses/X}
     * to {@code opensource.org/license/X} (3.29.0), and POMs in the wild use both.
     * Both spellings must resolve regardless of which list the CycloneDX library bundles.
     */
    @ParameterizedTest
    @CsvSource({
            "https://opensource.org/licenses/MIT, MIT",
            "http://opensource.org/licenses/MIT, MIT",
            "https://opensource.org/license/MIT, MIT",
            "https://opensource.org/license/mit, MIT",
            "https://opensource.org/licenses/BSD-3-Clause, BSD-3-Clause",
            "https://opensource.org/license/BSD-3-Clause, BSD-3-Clause",
            "https://opensource.org/licenses/bsd-3-clause, BSD-3-Clause",
            "https://opensource.org/license/bsd-3-clause, BSD-3-Clause"
    })
    void resolvesBothOpensourceOrgUrlForms(String url, String expectedId) {
        LicenseInfo li = mapper.map(new RawLicense("My Custom License", url));
        assertTrue(li.isSpdx(), () -> url + " should resolve to an SPDX id");
        assertEquals(expectedId, li.spdxId());
    }

    /**
     * OSI slugs that were renamed (or used a different spelling) before
     * SPDX 3.29.0 rewrote OSI URLs to {@code opensource.org/license/<SPDX-ID>}.
     */
    @ParameterizedTest
    @CsvSource({
            "https://opensource.org/license/mit/, MIT",
            "https://opensource.org/licenses/MIT/, MIT",
            "https://opensource.org/license/apache-2-0, Apache-2.0",
            "https://opensource.org/licenses/artistic-license-2.0, Artistic-2.0",
            "https://opensource.org/licenses/attribution, AAL",
            "https://opensource.org/licenses/BSDplusPatent, BSD-2-Clause-Patent",
            "https://opensource.org/licenses/cddl1, CDDL-1.0",
            "https://opensource.org/licenses/CDDL-1.0, CDDL-1.0",
            "https://opensource.org/licenses/NOSL3.0, NPOSL-3.0",
            "https://opensource.org/license/olfl-1-3/, OLFL-1.3",
            "https://opensource.org/licenses/OPL-2.1, OSET-PL-2.1",
            "https://opensource.org/license/osc-license-1-0, OSC-1.0",
            "https://opensource.org/licenses/UPL, UPL-1.0"
    })
    void resolvesRenamedOpensourceOrgSlugs(String url, String expectedId) {
        LicenseInfo li = mapper.map(new RawLicense("My Custom License", url));
        assertTrue(li.isSpdx(), () -> url + " should resolve to an SPDX id");
        assertEquals(expectedId, li.spdxId());
        assertNotNull(li.url(), "resolved SPDX licenses must retain the canonical URL");
    }

    /**
     * Bare GNU-family OSI URLs do not say "-only" or "-or-later", so they must
     * not decide the SPDX id; the license name does.
     */
    @ParameterizedTest
    @CsvSource({
            "https://opensource.org/licenses/GPL-2.0, GPL-2.0-only",
            "https://opensource.org/license/GPL-2.0, GPL-2.0-only",
            "https://opensource.org/licenses/GPL-3.0, GPL-3.0-or-later",
            "https://opensource.org/licenses/LGPL-2.1, LGPL-2.1-or-later",
            "https://opensource.org/licenses/LGPL-3.0, LGPL-3.0-only",
            "https://opensource.org/licenses/AGPL-3.0, AGPL-3.0-only"
    })
    void bareGnuOpensourceOrgUrlDefersToName(String url, String nameId) {
        LicenseInfo li = mapper.map(new RawLicense(nameId, url));
        assertTrue(li.isSpdx());
        assertEquals(nameId, li.spdxId());
    }

    @Test
    void bareGnuOpensourceOrgUrlWithUnknownNameStaysRaw() {
        LicenseInfo li = mapper.map(
                new RawLicense("My Custom License", "https://opensource.org/licenses/GPL-2.0"));
        assertTrue(li.isRaw(), "a bare GPL URL must not guess -only vs -or-later");
        assertEquals("https://opensource.org/licenses/GPL-2.0", li.url());
    }

    @Test
    void qualifiedGnuOpensourceOrgUrlResolves() {
        LicenseInfo li = mapper.map(
                new RawLicense("My Custom License", "https://opensource.org/license/GPL-2.0-only"));
        assertTrue(li.isSpdx());
        assertEquals("GPL-2.0-only", li.spdxId());
    }

    @Test
    void osiPython20UrlResolvesToPython20() {
        LicenseInfo li = mapper.map(
                new RawLicense("My Custom License", "https://opensource.org/licenses/Python-2.0"));
        assertTrue(li.isSpdx());
        assertEquals("Python-2.0", li.spdxId());
    }

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {
            "https://opensource.org/licenses/MIT, mit",
            "http://www.opensource.org/licenses/BSD-3-Clause/, bsd-3-clause",
            "https://opensource.org/license/mit//, mit",
            "https://opensource.org/licenses/, NULL",
            "https://opensource.org/about, NULL",
            "https://example.com/licenses/MIT, NULL"
    })
    void extractsOsiSlug(String url, String expectedSlug) {
        assertEquals(expectedSlug, SpdxLicenseMapper.osiSlug(url));
    }

    @Test
    void doesNotRewriteNonOpensourceOrgUrls() {
        LicenseInfo li = mapper.map(new RawLicense("Proprietary", "https://example.com/licenses/MIT"));
        assertTrue(li.isRaw());
        assertEquals("https://example.com/licenses/MIT", li.url());
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
