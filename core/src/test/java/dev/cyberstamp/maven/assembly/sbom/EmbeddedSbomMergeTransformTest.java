package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;

class EmbeddedSbomMergeTransformTest {

    @Test
    void ignoreModeIsNoOp() {
        Bom targetBom = buildTargetBom();
        Bom embeddedBom = buildEmbeddedBom();
        PackageRef libARef = new ArtifactCoords("org.a", "lib-a", "1.0", null, null);
        DiscoveredSbom discovered = new DiscoveredSbom(
                "lib/lib-a-1.0.jar!/META-INF/sbom.json",
                embeddedBom,
                libARef);
        AssemblyComponents model = new AssemblyComponents();
        model.addDiscoveredSbom(discovered);
        ArchiveIndex index = ArchiveIndex.of(List.of(), null, "SHA-256");

        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                "ignore", index);

        int initialSize = targetBom.getComponents() != null ? targetBom.getComponents().size() : 0;
        transform.apply(targetBom, model, owner -> "pkg:maven/org.a/lib-a@1.0");

        int finalSize = targetBom.getComponents() != null ? targetBom.getComponents().size() : 0;
        assertEquals(initialSize, finalSize,
                "ignore mode should not modify the BOM");
    }

    @Test
    void linkModeAddsBomReference() {
        Bom targetBom = buildTargetBom();
        Bom embeddedBom = buildEmbeddedBom();
        PackageRef libARef = new ArtifactCoords("org.a", "lib-a", "1.0", null, null);
        DiscoveredSbom discovered = new DiscoveredSbom(
                "lib/lib-a-1.0.jar!/META-INF/sbom.json",
                embeddedBom,
                libARef);
        AssemblyComponents model = new AssemblyComponents();
        model.addDiscoveredSbom(discovered);
        ArchiveIndex index = ArchiveIndex.of(List.of(), null, "SHA-256");

        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                "link", index);

        transform.apply(targetBom, model, owner -> "pkg:maven/org.a/lib-a@1.0");

        Component libA = targetBom.getComponents().get(0);
        assertNotNull(libA.getExternalReferences(),
                "component should have external references");
        boolean foundBomRef = false;
        for (ExternalReference ref : libA.getExternalReferences()) {
            if (ref.getType() == ExternalReference.Type.BOM
                    && "lib/lib-a-1.0.jar!/META-INF/sbom.json".equals(ref.getUrl())) {
                foundBomRef = true;
                break;
            }
        }
        assertTrue(foundBomRef, "should add BOM external reference");
    }

    @Test
    void mergeModeUnderParent() {
        Bom targetBom = buildTargetBom();
        Component nested = createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1");
        Bom embeddedBom = new Bom();
        embeddedBom.setComponents(new ArrayList<>(List.of(nested)));

        PackageRef libARef = new ArtifactCoords("org.a", "lib-a", "1.0", null, null);
        DiscoveredSbom discovered = new DiscoveredSbom(
                "lib/lib-a-1.0.jar!/META-INF/sbom.json",
                embeddedBom,
                libARef);
        AssemblyComponents model = new AssemblyComponents();
        model.addDiscoveredSbom(discovered);
        ArchiveIndex index = ArchiveIndex.of(List.of(), null, "SHA-256");

        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                "merge", index);

        transform.apply(targetBom, model, owner -> "pkg:maven/org.a/lib-a@1.0");

        Component libA = targetBom.getComponents().get(0);
        assertNotNull(libA.getComponents(), "parent should have nested components");
        assertEquals(1, libA.getComponents().size());
        assertEquals("react", libA.getComponents().get(0).getName());
    }

    @Test
    void mergeModeFlat() {
        Bom targetBom = buildTargetBom();
        Component additional = createLibrary("org.b", "lib-b", "2.0", "pkg:maven/org.b/lib-b@2.0");
        Bom embeddedBom = new Bom();
        embeddedBom.setComponents(new ArrayList<>(List.of(additional)));

        // PackageRef that doesn't match any component in target BOM
        PackageRef unknownRef = new ArtifactCoords("org.x", "unknown", "1.0", null, null);
        DiscoveredSbom discovered = new DiscoveredSbom(
                "lib/unknown.jar!/META-INF/sbom.json",
                embeddedBom,
                unknownRef);
        AssemblyComponents model = new AssemblyComponents();
        model.addDiscoveredSbom(discovered);
        ArchiveIndex index = ArchiveIndex.of(List.of(), null, "SHA-256");

        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                "merge", index);

        // Resolver returns parent ref but component not found -> flat merge
        transform.apply(targetBom, model, owner -> "pkg:maven/org.x/unknown@1.0");

        assertEquals(2, targetBom.getComponents().size(),
                "should add component to top-level when parent not found");
        boolean foundLibB = false;
        for (Component comp : targetBom.getComponents()) {
            if ("lib-b".equals(comp.getName())) {
                foundLibB = true;
                break;
            }
        }
        assertTrue(foundLibB, "lib-b should be merged at top-level");
    }

    @Test
    void parentRefResolverInvoked() {
        Bom targetBom = buildTargetBom();
        Bom embeddedBom = buildEmbeddedBom();
        PackageRef ownerRef = new ArtifactCoords("org.a", "lib-a", "1.0", null, null);
        DiscoveredSbom discovered = new DiscoveredSbom(
                "lib/lib-a-1.0.jar!/META-INF/sbom.json",
                embeddedBom,
                ownerRef);
        AssemblyComponents model = new AssemblyComponents();
        model.addDiscoveredSbom(discovered);
        ArchiveIndex index = ArchiveIndex.of(List.of(), null, "SHA-256");

        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                "link", index);

        boolean[] resolverCalled = { false };
        transform.apply(targetBom, model, owner -> {
            resolverCalled[0] = true;
            assertSame(ownerRef, owner, "resolver should receive the discovered SBOM owner");
            return "pkg:maven/org.a/lib-a@1.0";
        });

        assertTrue(resolverCalled[0], "parent ref resolver should be invoked");
    }

    private static Bom buildTargetBom() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef("pkg:maven/com.example/app@1.0");
        metadata.setComponent(main);
        bom.setMetadata(metadata);

        Component libA = createLibrary("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0");
        bom.setComponents(new ArrayList<>(List.of(libA)));
        return bom;
    }

    private static Bom buildEmbeddedBom() {
        Bom bom = new Bom();
        Component comp = createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21");
        bom.setComponents(new ArrayList<>(List.of(comp)));
        return bom;
    }

    private static Component createLibrary(String group, String name, String version,
            String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setGroup(group);
        comp.setName(name);
        comp.setVersion(version);
        comp.setBomRef(bomRef);
        comp.setPurl(bomRef);
        return comp;
    }
}
