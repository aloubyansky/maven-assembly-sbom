package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link EffectiveModelLicenseSource}.
 */
class EffectiveModelLicenseSourceTest {

    /**
     * Verifies that Maven Model licenses are correctly mapped to RawLicense records.
     */
    @Test
    void mapsModelLicensesToRawLicenses() {
        org.apache.maven.model.Model model = new org.apache.maven.model.Model();
        org.apache.maven.model.License l = new org.apache.maven.model.License();
        l.setName("Apache License 2.0");
        l.setUrl("https://www.apache.org/licenses/LICENSE-2.0");
        model.addLicense(l);
        EffectiveModelLicenseSource source = EffectiveModelLicenseSource.forTesting(coords -> model);
        List<RawLicense> raws = source.licensesFor("g", "a", "1");
        assertEquals(1, raws.size());
        assertEquals("Apache License 2.0", raws.get(0).name());
        assertEquals("https://www.apache.org/licenses/LICENSE-2.0", raws.get(0).url());
    }

    /**
     * Verifies that a null model results in an empty license list.
     */
    @Test
    void returnsEmptyForNullModel() {
        EffectiveModelLicenseSource source = EffectiveModelLicenseSource.forTesting(coords -> null);
        assertTrue(source.licensesFor("g", "a", "1").isEmpty());
    }

    /**
     * Verifies that a model with null or empty licenses list returns an empty list.
     */
    @Test
    void returnsEmptyWhenModelHasNullLicenses() {
        org.apache.maven.model.Model model = new org.apache.maven.model.Model();
        EffectiveModelLicenseSource source = EffectiveModelLicenseSource.forTesting(coords -> model);
        assertTrue(source.licensesFor("g", "a", "1").isEmpty());
    }

    /**
     * Verifies that license order from the model is preserved in the returned list.
     */
    @Test
    void preservesLicenseOrder() {
        org.apache.maven.model.Model model = new org.apache.maven.model.Model();
        org.apache.maven.model.License l1 = new org.apache.maven.model.License();
        l1.setName("MIT");
        l1.setUrl("https://opensource.org/licenses/MIT");
        model.addLicense(l1);

        org.apache.maven.model.License l2 = new org.apache.maven.model.License();
        l2.setName("Apache-2.0");
        l2.setUrl("https://www.apache.org/licenses/LICENSE-2.0");
        model.addLicense(l2);

        EffectiveModelLicenseSource source = EffectiveModelLicenseSource.forTesting(coords -> model);
        List<RawLicense> raws = source.licensesFor("g", "a", "1");

        assertEquals(2, raws.size());
        assertEquals("MIT", raws.get(0).name());
        assertEquals("https://opensource.org/licenses/MIT", raws.get(0).url());
        assertEquals("Apache-2.0", raws.get(1).name());
        assertEquals("https://www.apache.org/licenses/LICENSE-2.0", raws.get(1).url());
    }
}
