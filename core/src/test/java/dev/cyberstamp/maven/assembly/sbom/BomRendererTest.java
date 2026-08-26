package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link BomRenderer}: rendering {@link AssemblyComponents} to
 * CycloneDX {@link Bom}.
 */
class BomRendererTest {

    /**
     * (a) One Maven top-level component with hash + one archivePath →
     * correct purl/bom-ref/hash/evidence(Occurrence+Identity)/license.
     */
    @Test
    void testSingleMavenComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setTimestamp(new Date(1234567890000L));
        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        PackageComponent pkg = new PackageComponent(
                coords,
                "lib/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of());
        model.addComponent(pkg);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertNotNull(bom);
        assertNotNull(bom.getMetadata());
        assertNotNull(bom.getComponents());
        assertEquals(1, bom.getComponents().size());

        org.cyclonedx.model.Component comp = bom.getComponents().get(0);
        assertEquals("com.example", comp.getGroup());
        assertEquals("lib", comp.getName());
        assertEquals("2.0.0", comp.getVersion());
        assertEquals(org.cyclonedx.model.Component.Type.LIBRARY, comp.getType());

        String expectedPurl = "pkg:maven/com.example/lib@2.0.0";
        assertEquals(expectedPurl, comp.getPurl());
        assertEquals(expectedPurl, comp.getBomRef());

        assertNotNull(comp.getHashes());
        assertEquals(1, comp.getHashes().size());
        Hash hash = comp.getHashes().get(0);
        assertEquals("SHA-256", hash.getAlgorithm());
        assertEquals("abc123", hash.getValue());

        Evidence evidence = comp.getEvidence();
        assertNotNull(evidence);
        assertNotNull(evidence.getOccurrences());
        assertEquals(1, evidence.getOccurrences().size());
        assertEquals("lib/lib-2.0.0.jar", evidence.getOccurrences().get(0).getLocation());

        assertNotNull(evidence.getIdentities());
        assertEquals(1, evidence.getIdentities().size());
        assertEquals(org.cyclonedx.model.component.evidence.Identity.Field.PURL,
                evidence.getIdentities().get(0).getField());
        assertEquals(1.0, evidence.getIdentities().get(0).getConfidence());

        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        License license = comp.getLicenses().getLicenses().get(0);
        assertEquals("Apache-2.0", license.getId());
    }

    /**
     * (b) Same coords added twice at two paths → single component with two
     * Occurrences, licenses from the first.
     */
    @Test
    void testOccurrenceMerge() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        // First occurrence with license and hash
        PackageComponent pkg1 = new PackageComponent(
                coords,
                "lib/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of());
        model.addComponent(pkg1);

        // Second occurrence at different path, different license (should be ignored)
        PackageComponent pkg2 = new PackageComponent(
                coords,
                "other/lib-2.0.0.jar",
                "abc123",
                List.of(LicenseInfo.spdx("MIT")),
                List.of());
        model.addComponent(pkg2);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        // Should result in a single component
        assertEquals(1, bom.getComponents().size());

        org.cyclonedx.model.Component comp = bom.getComponents().get(0);
        assertEquals("com.example", comp.getGroup());
        assertEquals("lib", comp.getName());
        assertEquals("2.0.0", comp.getVersion());

        // Should have two occurrences
        Evidence evidence = comp.getEvidence();
        assertNotNull(evidence);
        assertNotNull(evidence.getOccurrences());
        assertEquals(2, evidence.getOccurrences().size());
        assertEquals("lib/lib-2.0.0.jar", evidence.getOccurrences().get(0).getLocation());
        assertEquals("other/lib-2.0.0.jar", evidence.getOccurrences().get(1).getLocation());

        // License should be from the first occurrence
        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        assertEquals("Apache-2.0", comp.getLicenses().getLicenses().get(0).getId());
    }

    /**
     * (c) A nested Maven artifact under a parent → nested + sorted.
     */
    @Test
    void testNestedComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords nestedCoords = ArtifactCoords.of("com.nested", "dep", "1.0");
        PackageComponent nested = new PackageComponent(
                nestedCoords,
                "lib/parent.war/WEB-INF/lib/dep-1.0.jar",
                "def456",
                List.of(LicenseInfo.spdx("MIT")),
                List.of());

        ArtifactCoords parentCoords = ArtifactCoords.of("com.example", "parent", "2.0.0");
        PackageComponent parent = new PackageComponent(
                parentCoords,
                "lib/parent.war",
                "abc123",
                List.of(LicenseInfo.spdx("Apache-2.0")),
                List.of(nested));
        model.addComponent(parent);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertEquals(1, bom.getComponents().size());
        org.cyclonedx.model.Component parentComp = bom.getComponents().get(0);
        assertEquals("com.example", parentComp.getGroup());
        assertEquals("parent", parentComp.getName());

        assertNotNull(parentComp.getComponents());
        assertEquals(1, parentComp.getComponents().size());
        org.cyclonedx.model.Component nestedComp = parentComp.getComponents().get(0);
        assertEquals("com.nested", nestedComp.getGroup());
        assertEquals("dep", nestedComp.getName());
        assertEquals("1.0", nestedComp.getVersion());
        assertEquals("pkg:maven/com.nested/dep@1.0", nestedComp.getPurl());
    }

    /**
     * (d) A FileComponent → file: bom-ref + generic purl + project license.
     */
    @Test
    void testFileComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setProjectLicenses(List.of(LicenseInfo.spdx("Apache-2.0")));
        model.setMetadata(metadata);

        FileComponent file = new FileComponent(
                "bin/script.sh",
                "xyz789",
                List.of());
        model.addComponent(file);

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertEquals(1, bom.getComponents().size());
        org.cyclonedx.model.Component comp = bom.getComponents().get(0);
        assertEquals(org.cyclonedx.model.Component.Type.FILE, comp.getType());
        assertEquals("script.sh", comp.getName());
        assertEquals("file:bin/script.sh", comp.getBomRef());

        String purl = comp.getPurl();
        assertTrue(purl.startsWith("pkg:generic/script.sh"));
        assertTrue(purl.contains("checksum=sha256:xyz789"));

        // File should have project licenses
        assertNotNull(comp.getLicenses());
        assertNotNull(comp.getLicenses().getLicenses());
        assertEquals(1, comp.getLicenses().getLicenses().size());
        assertEquals("Apache-2.0", comp.getLicenses().getLicenses().get(0).getId());
    }

    /**
     * A generic (non-Maven) package component — e.g. a Galleon-assembled shaded
     * JAR — must render with its name and version, a {@code pkg:generic} purl,
     * and its nested dependencies.
     */
    @Test
    void testGenericPackageComponent() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        PackageComponent nested = PackageComponent.of(
                ArtifactCoords.of("org.jboss", "dep-a", "1.0"), null, null);
        PackageComponent shaded = new PackageComponent(
                new GenericPackageRef("jboss-cli-client", "31.0.0.Final"),
                "bin/client/jboss-cli-client.jar", null,
                List.of(), List.of(nested));
        model.addComponent(shaded);

        Bom bom = new BomRenderer().render(model);

        org.cyclonedx.model.Component comp = bom.getComponents().stream()
                .filter(c -> "jboss-cli-client".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(comp);
        assertEquals(org.cyclonedx.model.Component.Type.LIBRARY, comp.getType());
        assertEquals("31.0.0.Final", comp.getVersion());
        assertEquals("pkg:generic/jboss-cli-client@31.0.0.Final", comp.getPurl());
        assertEquals("pkg:generic/jboss-cli-client@31.0.0.Final", comp.getBomRef());
        assertNotNull(comp.getComponents());
        assertEquals(1, comp.getComponents().size());
        assertEquals("dep-a", comp.getComponents().get(0).getName());
    }

    /**
     * When {@code mainComponentPurl} is set, the main component uses it verbatim
     * for both {@code purl} and {@code bom-ref} (rather than a derived Maven
     * purl), and the dependency-graph root references that same bom-ref. This
     * lets non-Maven producers (e.g. a provisioned distribution) give the main
     * component a synthetic identity.
     */
    @Test
    void testMainComponentSyntheticPurlOverride() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectArtifactId("JBoss EAP");
        metadata.setProjectVersion("8.1 Update 7.1");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setMainComponentPurl("pkg:generic/jboss-eap@8.1-update-7.1");
        model.setMetadata(metadata);
        model.addComponent(PackageComponent.of(
                ArtifactCoords.of("org.example", "lib", "1.0"), "lib/lib-1.0.jar", "h"));

        Bom bom = new BomRenderer().render(model);

        org.cyclonedx.model.Component main = bom.getMetadata().getComponent();
        assertEquals("JBoss EAP", main.getName());
        assertEquals("8.1 Update 7.1", main.getVersion());
        assertEquals("pkg:generic/jboss-eap@8.1-update-7.1", main.getPurl());
        assertEquals("pkg:generic/jboss-eap@8.1-update-7.1", main.getBomRef());
        assertTrue(bom.getDependencies().stream()
                .anyMatch(d -> "pkg:generic/jboss-eap@8.1-update-7.1".equals(d.getRef())),
                "dependency-graph root must reference the synthetic bom-ref");
    }

    /**
     * (e) A small dependency graph → sorted dependency tree + main dep filtering.
     */
    @Test
    void testDependencyGraph() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords lib1 = ArtifactCoords.of("com.example", "lib1", "1.0");
        ArtifactCoords lib2 = ArtifactCoords.of("com.example", "lib2", "2.0");

        model.addComponent(PackageComponent.of(lib1, "lib/lib1-1.0.jar", "hash1"));
        model.addComponent(PackageComponent.of(lib2, "lib/lib2-2.0.jar", "hash2"));

        // lib1 depends on lib2
        model.addDependencyEdge(new DependencyEdge(lib1, lib2, false));

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        assertNotNull(bom.getDependencies());
        assertTrue(bom.getDependencies().size() >= 3); // main, lib1, lib2

        // Find main dependency
        String mainPurl = "pkg:maven/org.example/my-app@1.0.0";
        Dependency mainDep = bom.getDependencies().stream()
                .filter(d -> mainPurl.equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(mainDep);

        // Main should only have lib1 as direct child (lib2 is transitive through lib1)
        assertEquals(1, mainDep.getDependencies().size());
        assertEquals("pkg:maven/com.example/lib1@1.0", mainDep.getDependencies().get(0).getRef());

        // lib1 should have lib2 as a dependency
        Dependency lib1Dep = bom.getDependencies().stream()
                .filter(d -> "pkg:maven/com.example/lib1@1.0".equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(lib1Dep);
        assertEquals(1, lib1Dep.getDependencies().size());
        assertEquals("pkg:maven/com.example/lib2@2.0", lib1Dep.getDependencies().get(0).getRef());
    }

    @Test
    void renderDoesNotSetSerialNumber() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        metadata.setTimestamp(new Date(1234567890000L));
        model.setMetadata(metadata);

        ArtifactCoords coords = ArtifactCoords.of("com.example", "lib", "2.0.0");
        model.addComponent(PackageComponent.of(coords, "lib/lib-2.0.0.jar", "abc123"));

        Bom bom = new BomRenderer().render(model);
        assertNull(bom.getSerialNumber());
    }

    /**
     * Tests nested-child filter: a PackageComponent with a nested JAR
     * AND a DependencyEdge(parent → jar) should render a parent Dependency with
     * ZERO children (the nested jar is filtered out per BomBuilder.mergeDependencyGraphs L707).
     */
    @Test
    void testNestedComponentFilteredFromDependencyGraph() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords jarCoords = ArtifactCoords.of("com.example", "lib", "1.0");
        PackageComponent nestedJar = PackageComponent.of(
                jarCoords, "lib/app-2.0.0.jar/WEB-INF/lib/lib-1.0.jar", "nestedhash");

        ArtifactCoords parentCoords = ArtifactCoords.of("com.example", "app", "2.0.0");
        PackageComponent parent = new PackageComponent(
                parentCoords,
                "lib/app-2.0.0.jar",
                "parenthash",
                List.of(),
                List.of(nestedJar)); // jar is nested under parent

        model.addComponent(parent);

        // Add a dependency edge parent → jar (should be filtered out because jar is nested)
        model.addDependencyEdge(new DependencyEdge(parentCoords, jarCoords, false));

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        // Find the parent's dependency entry
        String parentPurl = "pkg:maven/com.example/app@2.0.0";
        Dependency parentDep = null;
        for (Dependency d : bom.getDependencies()) {
            if (parentPurl.equals(d.getRef())) {
                parentDep = d;
                break;
            }
        }
        assertNotNull(parentDep, "Parent should have a dependency entry");

        // The parent's dependency should have ZERO children (nested jar filtered out)
        // CycloneDX represents empty dependencies as null or empty list
        int childCount = parentDep.getDependencies() == null ? 0 : parentDep.getDependencies().size();
        assertEquals(0, childCount,
                "Parent dependency should have no children (nested jar filtered out)");
    }

    /**
     * Tests occurrence merge with dependencies: a component that appears at
     * two paths (occurrence merge) and is also a dependency parent should
     * still get its dependency entries.
     */
    @Test
    void testOccurrenceMergeWithDependencies() {
        AssemblyComponents model = new AssemblyComponents();
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");
        metadata.setHashAlgorithmSpec("SHA-256");

        model.setMetadata(metadata);

        ArtifactCoords parent = ArtifactCoords.of("com.example", "parent", "1.0");
        ArtifactCoords child = ArtifactCoords.of("com.example", "child", "2.0");

        // Parent appears at two paths (should trigger occurrence merge)
        model.addComponent(PackageComponent.of(parent, "lib/parent-1.0.jar", "hash1"));
        model.addComponent(PackageComponent.of(parent, "other/parent-1.0.jar", "hash1"));

        // Child appears once
        model.addComponent(PackageComponent.of(child, "lib/child-2.0.jar", "hash2"));

        // parent depends on child
        model.addDependencyEdge(new DependencyEdge(parent, child, false));

        BomRenderer renderer = new BomRenderer();
        Bom bom = renderer.render(model);

        // Should result in 2 components (parent merged, child separate)
        assertEquals(2, bom.getComponents().size());

        // Parent should have 2 occurrences
        org.cyclonedx.model.Component parentComp = bom.getComponents().stream()
                .filter(c -> "parent".equals(c.getName()))
                .findFirst()
                .orElse(null);
        assertNotNull(parentComp);
        assertEquals(2, parentComp.getEvidence().getOccurrences().size());

        // Parent's dependency entry should still exist with child
        String parentPurl = "pkg:maven/com.example/parent@1.0";
        Dependency parentDep = bom.getDependencies().stream()
                .filter(d -> parentPurl.equals(d.getRef()))
                .findFirst()
                .orElse(null);
        assertNotNull(parentDep, "Parent should have a dependency entry");
        assertEquals(1, parentDep.getDependencies().size());
        assertEquals("pkg:maven/com.example/child@2.0", parentDep.getDependencies().get(0).getRef());
    }

}
