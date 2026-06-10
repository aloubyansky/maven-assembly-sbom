package io.github.aloubyansky.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;

class BomMergerTest {

    @Test
    void mergeAddsComponentsAsNestedUnderParent() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib-a@1.0", source);

        Component parent = target.getComponents().get(0);
        assertNotNull(parent.getComponents(), "parent should have nested components");
        assertEquals(2, parent.getComponents().size());
        assertEquals("lodash", parent.getComponents().get(0).getName(),
                "nested components should be sorted by name");
        assertEquals("react", parent.getComponents().get(1).getName());
    }

    @Test
    void mergeImportsDependencyEntries() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "lib-a", "1.0", "pkg:maven/org.a/lib-a@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Dependency reactDep = new Dependency("pkg:npm/react@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/loose-envify@1.4.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "loose-envify", "1.4.0", "pkg:npm/loose-envify@1.4.0"));
        source.addDependency(reactDep);
        source.addDependency(new Dependency("pkg:npm/loose-envify@1.4.0"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/lib-a@1.0", source);

        assertEquals(3, target.getDependencies().size(),
                "target should have original dep + 2 imported deps");
        assertTrue(target.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())),
                "react dependency should be imported");
    }

    @Test
    void mergeDoesNotCreateCrossEcosystemDependencyEdges() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        Dependency mainDep = target.getDependencies().stream()
                .filter(d -> "pkg:maven/com.example/app@1.0".equals(d.getRef()))
                .findFirst().orElse(null);
        assertNotNull(mainDep);
        if (mainDep.getDependencies() != null) {
            assertFalse(mainDep.getDependencies().stream()
                    .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())),
                    "no cross-ecosystem edge from main to npm component");
        }
    }

    @Test
    void mergeUnderMainComponent() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/com.example/app@1.0", source);

        Component main = target.getMetadata().getComponent();
        assertNotNull(main.getComponents(), "main component should have nested components");
        assertEquals(1, main.getComponents().size());
        assertEquals("react", main.getComponents().get(0).getName());
    }

    @Test
    void mergePreservesExistingNestedComponents() {
        Component existingNested = createLibrary("org.b", "nested-lib", "2.0",
                "pkg:maven/org.b/nested-lib@2.0");
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        parent.addComponent(existingNested);

        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertEquals(2, parent.getComponents().size(),
                "existing nested component should be preserved");
        assertTrue(parent.getComponents().stream()
                .anyMatch(c -> "nested-lib".equals(c.getName())));
        assertTrue(parent.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())));
    }

    @Test
    void mergeWithUnknownParentBomRefDoesNothing() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");
        int originalComponentCount = target.getComponents() != null
                ? target.getComponents().size()
                : 0;

        Bom source = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"));

        BomMerger.mergeUnder(target, "pkg:maven/nonexistent@1.0", source);

        int afterCount = target.getComponents() != null
                ? target.getComponents().size()
                : 0;
        assertEquals(originalComponentCount, afterCount, "no changes when parent not found");
    }

    @Test
    void mergeWithEmptySourceBomIsNoOp() {
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Bom source = new Bom();

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war@1.0", source);

        assertNull(parent.getComponents(), "no nested components should be added");
    }

    @Test
    void addBomReferenceCreatesExternalRef() {
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        BomMerger.addBomReference(target, "pkg:maven/org.a/war@1.0",
                "web/console.war/bom.cdx.json");

        List<ExternalReference> refs = parent.getExternalReferences();
        assertNotNull(refs, "parent should have external references");
        assertEquals(1, refs.size());
        assertEquals(ExternalReference.Type.BOM, refs.get(0).getType());
        assertEquals("web/console.war/bom.cdx.json", refs.get(0).getUrl());
    }

    @Test
    void addBomReferenceWithUnknownParentDoesNothing() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0");

        BomMerger.addBomReference(target, "pkg:maven/nonexistent@1.0", "bom.cdx.json");

        Component main = target.getMetadata().getComponent();
        assertNull(main.getExternalReferences(), "no external reference should be added");
    }

    @Test
    void findComponentByBomRefSearchesNestedComponents() {
        Component nested = createLibrary("org.b", "nested", "2.0",
                "pkg:maven/org.b/nested@2.0");
        Component parent = createLibrary("org.a", "war", "1.0", "pkg:maven/org.a/war@1.0");
        parent.addComponent(nested);

        Bom bom = buildTargetBom("pkg:maven/com.example/app@1.0", parent);

        Component found = BomMerger.findComponentByBomRef(bom, "pkg:maven/org.b/nested@2.0");
        assertNotNull(found, "should find nested component");
        assertEquals("nested", found.getName());
    }

    @Test
    void duplicateDependencyRefsNotImported() {
        Bom target = buildTargetBom("pkg:maven/com.example/app@1.0",
                createLibrary("org.a", "war-a", "1.0", "pkg:maven/org.a/war-a@1.0"),
                createLibrary("org.b", "war-b", "1.0", "pkg:maven/org.b/war-b@1.0"));
        target.addDependency(new Dependency("pkg:maven/com.example/app@1.0"));

        Dependency sharedDep = new Dependency("pkg:npm/lodash@4.17.21");
        Dependency reactDep = new Dependency("pkg:npm/react@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));

        Bom sourceA = buildSourceBom(
                createLibrary(null, "react", "18.3.1", "pkg:npm/react@18.3.1"),
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));
        sourceA.addDependency(reactDep);
        sourceA.addDependency(sharedDep);

        Bom sourceB = buildSourceBom(
                createLibrary(null, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"));
        sourceB.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));

        BomMerger.mergeUnder(target, "pkg:maven/org.a/war-a@1.0", sourceA);
        BomMerger.mergeUnder(target, "pkg:maven/org.b/war-b@1.0", sourceB);

        long lodashCount = target.getDependencies().stream()
                .filter(d -> "pkg:npm/lodash@4.17.21".equals(d.getRef()))
                .count();
        assertEquals(1, lodashCount,
                "shared dependency ref should appear only once");
        assertEquals(3, target.getDependencies().size(),
                "target should have original + react + lodash (no duplicate)");
    }

    private static Bom buildTargetBom(String mainBomRef, Component... components) {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef(mainBomRef);
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        if (components.length > 0) {
            bom.setComponents(new java.util.ArrayList<>(List.of(components)));
        }
        return bom;
    }

    private static Bom buildSourceBom(Component... components) {
        Bom bom = new Bom();
        bom.setComponents(new java.util.ArrayList<>(List.of(components)));
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
