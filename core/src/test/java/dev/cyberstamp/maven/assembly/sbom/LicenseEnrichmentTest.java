package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class LicenseEnrichmentTest {

    /** A LicenseSource backed by a fixed GAV -> raw-license map. */
    private static LicenseSource source(Map<String, List<RawLicense>> byGav) {
        return (g, a, v) -> byGav.getOrDefault(g + ":" + a + ":" + v, List.of());
    }

    @Test
    void resolveMapsRawToSpdx() {
        LicenseEnrichment enrichment = new LicenseEnrichment(
                source(Map.of("org.example:foo:1.0",
                        List.of(new RawLicense("Apache License 2.0", null)))),
                false);
        List<LicenseInfo> infos = enrichment.resolve("org.example", "foo", "1.0");
        assertEquals(1, infos.size());
        assertTrue(infos.get(0).isSpdx());
        assertEquals("Apache-2.0", infos.get(0).spdxId());
    }

    @Test
    void resolveEmptyWhenNoLicensesAndNotFailing() {
        LicenseEnrichment enrichment = new LicenseEnrichment(source(Map.of()), false);
        assertTrue(enrichment.resolve("g", "a", "1").isEmpty());
    }

    @Test
    void resolveThrowsWhenFailingOnMissing() {
        LicenseEnrichment enrichment = new LicenseEnrichment(source(Map.of()), true);
        assertThrows(LicenseResolutionException.class,
                () -> enrichment.resolve("g", "a", "1"));
    }

    @Test
    void applyAttachesLicensesToTopLevelAndNested() {
        LicenseEnrichment enrichment = new LicenseEnrichment(
                source(Map.of(
                        "org.example:parent:1.0", List.of(new RawLicense("Apache License 2.0", null)),
                        "com.bundled:child:2.0", List.of(new RawLicense("MIT License", null)))),
                false);
        PackageComponent child = PackageComponent.of(
                ArtifactCoords.of("com.bundled", "child", "2.0"), null, null);
        PackageComponent parent = new PackageComponent(
                ArtifactCoords.of("org.example", "parent", "1.0"), "lib/p.jar", "h",
                List.of(), List.of(child));
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(parent);

        enrichment.apply(model);

        PackageComponent enrichedParent = (PackageComponent) model.components().get(0);
        assertEquals("Apache-2.0", enrichedParent.licenses().get(0).spdxId());
        PackageComponent enrichedChild = (PackageComponent) enrichedParent.nested().get(0);
        assertEquals("MIT", enrichedChild.licenses().get(0).spdxId());
    }

    @Test
    void applyDoesNotOverwriteExistingLicenses() {
        LicenseEnrichment enrichment = new LicenseEnrichment(
                source(Map.of("org.example:foo:1.0",
                        List.of(new RawLicense("Apache License 2.0", null)))),
                false);
        PackageComponent pre = new PackageComponent(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null,
                List.of(LicenseInfo.spdx("EPL-2.0")), List.of());
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(pre);

        enrichment.apply(model);

        PackageComponent after = (PackageComponent) model.components().get(0);
        assertEquals("EPL-2.0", after.licenses().get(0).spdxId());
    }

    @Test
    void resolveCachesPerGav() {
        int[] calls = { 0 };
        LicenseSource counting = (g, a, v) -> {
            calls[0]++;
            return List.of(new RawLicense("Apache License 2.0", null));
        };
        LicenseEnrichment enrichment = new LicenseEnrichment(counting, false);
        enrichment.resolve("g", "a", "1");
        enrichment.resolve("g", "a", "1");
        assertEquals(1, calls[0]);
    }
}
