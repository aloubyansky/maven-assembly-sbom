package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;

class AssemblyComponentsTest {

    @Test
    void accumulatesComponents() {
        AssemblyComponents model = new AssemblyComponents();
        assertTrue(model.components().isEmpty());
        PackageComponent pc = PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null);
        model.addComponent(pc);
        assertEquals(1, model.components().size());
        assertSame(pc, model.components().get(0));
    }

    @Test
    void accumulatesDependencyEdges() {
        AssemblyComponents model = new AssemblyComponents();
        PackageRef parent = ArtifactCoords.of("g", "parent", "1");
        PackageRef child = ArtifactCoords.of("g", "child", "1");
        model.addDependencyEdge(new DependencyEdge(parent, child, false));
        assertEquals(1, model.dependencyEdges().size());
        assertEquals(parent, model.dependencyEdges().get(0).parent());
        assertEquals(child, model.dependencyEdges().get(0).child());
    }

    @Test
    void accumulatesDiscoveredSboms() {
        AssemblyComponents model = new AssemblyComponents();
        Bom bom = new Bom();
        PackageRef owner = ArtifactCoords.of("g", "a", "1");
        model.addDiscoveredSbom(new DiscoveredSbom("META-INF/sbom.cdx.json", bom, owner));
        assertEquals(1, model.discoveredSboms().size());
        assertSame(bom, model.discoveredSboms().get(0).parsedBom());
        assertEquals(owner, model.discoveredSboms().get(0).owner());
    }

    @Test
    void holdsOptionalProduct() {
        AssemblyComponents model = new AssemblyComponents();
        assertNull(model.product());
        ProductInfo product = new ProductInfo();
        model.setProduct(product);
        assertSame(product, model.product());
    }

    @Test
    void exposedListsAreUnmodifiable() {
        AssemblyComponents model = new AssemblyComponents();
        assertThrows(UnsupportedOperationException.class,
                () -> model.components().add(
                        PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null)));
    }

    @Test
    void providesNonNullMetadataByDefault() {
        AssemblyComponents model = new AssemblyComponents();
        assertNotNull(model.metadata());
    }

    @Test
    void roundTripsMetadata() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        model.setMetadata(metadata);

        assertSame(metadata, model.metadata());
        assertEquals("org.example", model.metadata().getProjectGroupId());
        assertEquals("my-app", model.metadata().getProjectArtifactId());
    }

    @Test
    void productDelegatesToMetadata() {
        AssemblyComponents model = new AssemblyComponents();
        assertNull(model.product());

        ProductInfo product = new ProductInfo();
        product.setCpe("cpe:2.3:a:example:myapp:1.0:*:*:*:*:*:*:*");
        model.setProduct(product);

        assertSame(product, model.product());
        assertSame(product, model.metadata().getProduct());
    }
}
