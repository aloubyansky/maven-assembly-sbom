package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class LicenseSourceTest {

    @Test
    void rawLicenseHoldsNameAndUrl() {
        RawLicense raw = new RawLicense("Apache License 2.0", "https://apache.org/licenses/LICENSE-2.0");
        assertEquals("Apache License 2.0", raw.name());
        assertEquals("https://apache.org/licenses/LICENSE-2.0", raw.url());
    }

    @Test
    void licenseSourceReturnsPerGav() {
        RawLicense apache = new RawLicense("Apache License 2.0", null);
        LicenseSource source = (g, a, v) -> Map.of("org.example:foo:1.0", List.of(apache))
                .getOrDefault(g + ":" + a + ":" + v, List.of());

        assertEquals(List.of(apache), source.licensesFor("org.example", "foo", "1.0"));
        assertTrue(source.licensesFor("org.example", "bar", "9.9").isEmpty());
    }
}
