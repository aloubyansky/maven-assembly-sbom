package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;

class SbomPipelineOrchestratorTest {

    private static AssemblyComponents model(PackageComponent... comps) {
        AssemblyComponents m = new AssemblyComponents();
        AssemblyMetadata md = new AssemblyMetadata();
        md.setProjectGroupId("g");
        md.setProjectArtifactId("a");
        md.setProjectVersion("1");
        md.setHashAlgorithmSpec("SHA-256");
        m.setMetadata(md);
        for (PackageComponent c : comps) {
            m.addComponent(c);
        }
        return m;
    }

    @Test
    void enrichRunsLicenseSourceWhenProvided() {
        LicenseSource src = (g, a, v) -> List.of(new RawLicense("Apache License 2.0", null));
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        SbomPipeline.forModel(m).licenseSource(src).enrich();
        PackageComponent pc = (PackageComponent) m.components().get(0);
        assertEquals("Apache-2.0", pc.licenses().get(0).spdxId());
    }

    @Test
    void enrichSkipsLicensesWhenNoSource() {
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        SbomPipeline.forModel(m).enrich();
        assertTrue(((PackageComponent) m.components().get(0)).licenses().isEmpty());
    }

    @Test
    void renderProducesBom() {
        AssemblyComponents m = model(PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null));
        Bom bom = SbomPipeline.forModel(m).render();
        assertNotNull(bom.getComponents());
        assertFalse(bom.getComponents().isEmpty());
    }
}
