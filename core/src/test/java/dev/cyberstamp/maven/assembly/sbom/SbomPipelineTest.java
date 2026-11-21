package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

/**
 * Integration-style tests that model the Artemis SBOM pipeline:
 * npm SBOM → WAR SBOM → distribution SBOM, merging each SBOM into the
 * next by anchoring its components to the copies already there.
 */
class SbomPipelineTest {

    // ── Test A: WAR with external npm SBOM (mergeFlat) ──────────────

    @Test
    void mergeFlatExternalNpmSbomIntoWarBom() {
        // WAR BOM with Maven libraries
        Bom warBom = newBom("pkg:maven/org.example/app-war@1.0?type=war");
        addComp(warBom, library("jersey-server", "pkg:maven/org.glassfish/jersey-server@3.1",
                "WEB-INF/lib/jersey-server-3.1.jar", "hash-jersey"));
        addComp(warBom, library("jackson-core", "pkg:maven/com.fasterxml/jackson-core@2.18",
                "WEB-INF/lib/jackson-core-2.18.jar", "hash-jackson"));
        addComp(warBom, library("slf4j-api", "pkg:maven/org.slf4j/slf4j-api@2.0",
                "WEB-INF/lib/slf4j-api-2.0.jar", "hash-slf4j"));
        Dependency warMainDep = new Dependency("pkg:maven/org.example/app-war@1.0?type=war");
        warMainDep.addDependency(new Dependency("pkg:maven/org.glassfish/jersey-server@3.1"));
        warMainDep.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.18"));
        warBom.addDependency(warMainDep);

        // External npm SBOM from cdxgen
        Bom npmBom = newBom("pkg:npm/console-app@1.0");
        addComp(npmBom, npmLib("react", "pkg:npm/react@18.3.1"));
        addComp(npmBom, npmLib("react-dom", "pkg:npm/react-dom@18.3.1"));
        addComp(npmBom, npmFramework("keycloak-js", "pkg:npm/keycloak-js@26.1.4"));
        addComp(npmBom, npmLib("lodash", "pkg:npm/lodash@4.17.21"));
        addComp(npmBom, npmLib("bail", "pkg:npm/bail@2.0.2"));
        Dependency npmMainDep = new Dependency("pkg:npm/console-app@1.0");
        npmMainDep.addDependency(new Dependency("pkg:npm/react@18.3.1"));
        npmMainDep.addDependency(new Dependency("pkg:npm/react-dom@18.3.1"));
        npmMainDep.addDependency(new Dependency("pkg:npm/keycloak-js@26.1.4"));
        npmBom.addDependency(npmMainDep);
        Dependency reactDep = new Dependency("pkg:npm/react-dom@18.3.1");
        reactDep.addDependency(new Dependency("pkg:npm/react@18.3.1"));
        npmBom.addDependency(reactDep);
        npmBom.addDependency(new Dependency("pkg:npm/react@18.3.1"));
        npmBom.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));
        npmBom.addDependency(new Dependency("pkg:npm/bail@2.0.2"));

        BomMerger.mergeFlat(warBom, npmBom);

        // All npm components added as top-level
        assertEquals(8, warBom.getComponents().size(),
                "3 maven + 5 npm components");
        assertTrue(warBom.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())));
        assertTrue(warBom.getComponents().stream()
                .anyMatch(c -> "keycloak-js".equals(c.getName())));

        // Framework type preserved
        Component keycloak = warBom.getComponents().stream()
                .filter(c -> "keycloak-js".equals(c.getName()))
                .findFirst().orElseThrow();
        assertEquals(Component.Type.FRAMEWORK, keycloak.getType());

        // Source main deps adopted into target main
        Dependency mainDep = warBom.getDependencies().stream()
                .filter(d -> "pkg:maven/org.example/app-war@1.0?type=war".equals(d.getRef()))
                .findFirst().orElseThrow();
        Set<String> mainChildren = new HashSet<>();
        for (Dependency d : mainDep.getDependencies()) {
            mainChildren.add(d.getRef());
        }
        assertTrue(mainChildren.contains("pkg:npm/react@18.3.1"),
                "npm deps adopted into WAR main");
        assertTrue(mainChildren.contains("pkg:maven/org.glassfish/jersey-server@3.1"),
                "original maven deps preserved");

        // npm dependency entries imported
        assertTrue(warBom.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/react-dom@18.3.1".equals(d.getRef())));
        assertTrue(warBom.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/lodash@4.17.21".equals(d.getRef())));

        // No duplicate dependency refs
        List<String> allRefs = new ArrayList<>();
        for (Dependency d : warBom.getDependencies()) {
            allRefs.add(d.getRef());
        }
        assertEquals(allRefs.size(), new HashSet<>(allRefs).size(),
                "no duplicate dependency refs");
    }

    // ── Test B: Distribution with unpacked WAR + embedded SBOM ──────

    @Test
    void mergeEmbeddedSbomUnderUnpackedWar() {
        // Distribution BOM
        Bom distBom = newBom("pkg:maven/org.example/dist@1.0");

        // Top-level libraries in lib/
        Component caffeine = library("caffeine",
                "pkg:maven/com.github.ben-manes/caffeine@3.2.4",
                "lib/caffeine-3.2.4.jar", "hash-caffeine");
        Component guava = library("guava",
                "pkg:maven/com.google/guava@33.6",
                "lib/guava-33.6.jar", "hash-guava");
        // Shared lib: exists at lib/ AND inside WAR
        Component jspecify = library("jspecify",
                "pkg:maven/org.jspecify/jspecify@1.0.0",
                "lib/jspecify-1.0.0.jar", "hash-jspecify");
        Evidence jspecEvidence = jspecify.getEvidence();
        jspecEvidence.addOccurrence(occ("web/console.war/WEB-INF/lib/jspecify-1.0.0.jar"));

        // Unpacked WAR at web/console.war/
        Component consoleWar = library("artemis-console",
                "pkg:maven/org.example/artemis-console@1.0?type=war",
                null, null);
        consoleWar.setEvidence(evidenceWith("web/console.war/"));

        addComp(distBom, caffeine);
        addComp(distBom, guava);
        addComp(distBom, jspecify);
        addComp(distBom, consoleWar);

        distBom.addDependency(new Dependency(
                "pkg:maven/org.example/dist@1.0"));

        // Embedded SBOM from the WAR (simulating META-INF/sbom/bom.cdx.json)
        // Note: uses ?type=jar convention from cyclonedx-maven-plugin
        Bom embeddedSbom = new Bom();
        embeddedSbom.setComponents(new ArrayList<>(List.of(
                // the WAR's copy of the top-level jspecify: split out under the WAR
                library("jspecify", "pkg:maven/org.jspecify/jspecify@1.0.0?type=jar",
                        "WEB-INF/lib/jspecify-1.0.0.jar", "hash-jspecify"),
                // Maven lib only in WAR
                library("error-prone", "pkg:maven/com.google/error-prone@2.36",
                        "WEB-INF/lib/error-prone-2.36.jar", "hash-errorprone"),
                // caffeine appears in SBOM but was excluded from unpack
                library("caffeine", "pkg:maven/com.github.ben-manes/caffeine@3.2.4?type=jar",
                        "WEB-INF/lib/caffeine-3.2.4.jar", "hash-caffeine"),
                // npm components (no file occurrences in archive)
                npmLib("react", "pkg:npm/react@18.3.1"),
                npmLib("lodash", "pkg:npm/lodash@4.17.21"),
                // File component from the WAR
                fileComp("hawtconfig.json", "file:hawtconfig.json",
                        "hawtconfig.json", "hash-hawtconfig"))));

        Dependency embJspec = new Dependency("pkg:maven/org.jspecify/jspecify@1.0.0?type=jar");
        Dependency embError = new Dependency("pkg:maven/com.google/error-prone@2.36");
        Dependency embReact = new Dependency("pkg:npm/react@18.3.1");
        embeddedSbom.addDependency(embJspec);
        embeddedSbom.addDependency(embError);
        embeddedSbom.addDependency(embReact);
        embeddedSbom.addDependency(new Dependency("pkg:npm/lodash@4.17.21"));
        embeddedSbom.addDependency(new Dependency("file:hawtconfig.json"));

        // Simulate archive contents — what actually exists in the distribution
        // caffeine is NOT in web/console.war/WEB-INF/lib/ (excluded from unpack)
        ArchiveIndex archiveIndex = ArchiveIndex.of(List.of(
                new FileEntry("lib/caffeine-3.2.4.jar", "hash-caffeine"),
                new FileEntry("lib/guava-33.6.jar", "hash-guava"),
                new FileEntry("lib/jspecify-1.0.0.jar", "hash-jspecify"),
                new FileEntry("web/console.war/WEB-INF/lib/jspecify-1.0.0.jar", "hash-jspecify"),
                new FileEntry("web/console.war/WEB-INF/lib/error-prone-2.36.jar", "hash-errorprone"),
                new FileEntry("web/console.war/hawtconfig.json", "hash-hawtconfig")),
                null, "sha256");

        // Merge
        AnchoredMerge.merge(distBom, embeddedSbom, AnchoredMerge.Scope.of(BomMerger.findComponentByBomRef(distBom,
                "pkg:maven/org.example/artemis-console@1.0?type=war"), archiveIndex));

        // jspecify: occurrence at web/console.war/ should migrate to nested,
        // top-level keeps lib/ occurrence
        assertEquals(1, jspecify.getEvidence().getOccurrences().size());
        assertEquals("lib/jspecify-1.0.0.jar",
                jspecify.getEvidence().getOccurrences().get(0).getLocation());
        assertTrue(distBom.getComponents().contains(jspecify),
                "jspecify should remain top-level (still has lib/ occurrence)");

        // Console WAR should have nested components
        assertNotNull(consoleWar.getComponents());

        // npm components should be kept and nested
        assertTrue(consoleWar.getComponents().stream()
                .anyMatch(c -> "react".equals(c.getName())),
                "npm components should be kept");
        assertTrue(consoleWar.getComponents().stream()
                .anyMatch(c -> "lodash".equals(c.getName())));

        // error-prone should be nested (matches archive path with prefix)
        assertTrue(consoleWar.getComponents().stream()
                .anyMatch(c -> "error-prone".equals(c.getName())));

        // caffeine should NOT be nested (excluded from unpack — not in archive under web/console.war/)
        assertFalse(consoleWar.getComponents().stream()
                .anyMatch(c -> "caffeine".equals(c.getName())),
                "caffeine was excluded from unpack and should not appear as nested");

        // hawtconfig file component should be nested with prefixed bomRef
        Component nestedHawt = consoleWar.getComponents().stream()
                .filter(c -> "hawtconfig.json".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(nestedHawt, "file component should be nested");
        assertEquals("file:web/console.war/hawtconfig.json",
                nestedHawt.getBomRef(),
                "file bomRef should be prefixed with parent path");

        // jspecify should also appear as the WAR's own nested copy
        assertTrue(consoleWar.getComponents().stream()
                .anyMatch(c -> "jspecify".equals(c.getName())));

        // Dependencies imported
        assertTrue(distBom.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/react@18.3.1".equals(d.getRef())));
        assertTrue(distBom.getDependencies().stream()
                .anyMatch(d -> "pkg:npm/lodash@4.17.21".equals(d.getRef())));

        // No duplicate dependency refs
        assertNoDuplicateDepRefs(distBom);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static Bom newBom(String mainBomRef) {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef(mainBomRef);
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        return bom;
    }

    private static void addComp(Bom bom, Component comp) {
        if (bom.getComponents() == null) {
            bom.setComponents(new ArrayList<>());
        }
        bom.getComponents().add(comp);
    }

    private static Component library(String name, String purl,
            String occurrencePath, String hashValue) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(purl);
        comp.setPurl(purl);
        if (occurrencePath != null) {
            comp.setEvidence(evidenceWith(occurrencePath));
        }
        if (hashValue != null) {
            comp.addHash(new Hash(Hash.Algorithm.SHA_256, hashValue));
        }
        return comp;
    }

    private static Component npmLib(String name, String purl) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(purl);
        comp.setPurl(purl);
        return comp;
    }

    private static Component npmFramework(String name, String purl) {
        Component comp = new Component();
        comp.setType(Component.Type.FRAMEWORK);
        comp.setName(name);
        comp.setBomRef(purl);
        comp.setPurl(purl);
        return comp;
    }

    private static Component fileComp(String name, String bomRef,
            String occurrencePath, String hashValue) {
        Component comp = new Component();
        comp.setType(Component.Type.FILE);
        comp.setName(name);
        comp.setBomRef(bomRef);
        comp.setPurl("pkg:generic/" + name);
        comp.setEvidence(evidenceWith(occurrencePath));
        if (hashValue != null) {
            comp.addHash(new Hash(Hash.Algorithm.SHA_256, hashValue));
        }
        return comp;
    }

    private static Evidence evidenceWith(String location) {
        Evidence evidence = new Evidence();
        evidence.addOccurrence(occ(location));
        return evidence;
    }

    private static Occurrence occ(String location) {
        Occurrence occ = new Occurrence();
        occ.setLocation(location);
        return occ;
    }

    private static void assertNoDuplicateDepRefs(Bom bom) {
        if (bom.getDependencies() == null) {
            return;
        }
        List<String> refs = new ArrayList<>();
        for (Dependency d : bom.getDependencies()) {
            refs.add(d.getRef());
        }
        assertEquals(refs.size(), new HashSet<>(refs).size(),
                "no duplicate dependency refs");
    }

    private static Set<String> collectAllBomRefs(Bom bom) {
        Set<String> refs = new HashSet<>();
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            refs.add(bom.getMetadata().getComponent().getBomRef());
        }
        if (bom.getComponents() != null) {
            collectBomRefs(bom.getComponents(), refs);
        }
        return refs;
    }

    private static void collectBomRefs(List<Component> comps, Set<String> refs) {
        for (Component c : comps) {
            if (c.getBomRef() != null) {
                refs.add(c.getBomRef());
            }
            if (c.getComponents() != null) {
                collectBomRefs(c.getComponents(), refs);
            }
        }
    }

    // ── Test C: Merge external SBOM with ?type=jar bom-refs ────────

    @Test
    void mergeFlatWithTypeJarBomRefsProducesNoOrphanDeps() {
        // Assembly handler produces components without ?type=jar
        Bom distBom = newBom("pkg:maven/org.example/dist@1.0");
        addComp(distBom, library("jackson-core",
                "pkg:maven/com.fasterxml/jackson-core@2.22.0",
                "lib/jackson-core-2.22.0.jar", "hash-jcore"));
        addComp(distBom, library("jackson-databind",
                "pkg:maven/com.fasterxml/jackson-databind@2.22.0",
                "lib/jackson-databind-2.22.0.jar", "hash-jdb"));
        addComp(distBom, library("snakeyaml",
                "pkg:maven/org.yaml/snakeyaml@2.0",
                "lib/snakeyaml-2.0.jar", "hash-snake"));

        Dependency distMain = new Dependency("pkg:maven/org.example/dist@1.0");
        distMain.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0"));
        distMain.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-databind@2.22.0"));
        distMain.addDependency(new Dependency("pkg:maven/org.yaml/snakeyaml@2.0"));
        distBom.addDependency(distMain);
        distBom.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0"));
        Dependency distDbDep = new Dependency("pkg:maven/com.fasterxml/jackson-databind@2.22.0");
        distDbDep.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0"));
        distBom.addDependency(distDbDep);
        distBom.addDependency(new Dependency("pkg:maven/org.yaml/snakeyaml@2.0"));

        // Quarkus SBOM uses ?type=jar in bom-refs (same artifacts)
        Bom quarkusBom = newBom("pkg:generic/quarkus-run.jar@1.0");
        addComp(quarkusBom, library("jackson-core",
                "pkg:maven/com.fasterxml/jackson-core@2.22.0?type=jar",
                null, "hash-jcore"));
        addComp(quarkusBom, library("jackson-databind",
                "pkg:maven/com.fasterxml/jackson-databind@2.22.0?type=jar",
                null, "hash-jdb"));
        addComp(quarkusBom, library("snakeyaml",
                "pkg:maven/org.yaml/snakeyaml@2.0?type=jar",
                null, "hash-snake"));

        Dependency qMain = new Dependency("pkg:generic/quarkus-run.jar@1.0");
        qMain.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0?type=jar"));
        qMain.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-databind@2.22.0?type=jar"));
        quarkusBom.addDependency(qMain);
        Dependency qCoreDep = new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0?type=jar");
        quarkusBom.addDependency(qCoreDep);
        Dependency qDbDep = new Dependency("pkg:maven/com.fasterxml/jackson-databind@2.22.0?type=jar");
        qDbDep.addDependency(new Dependency("pkg:maven/com.fasterxml/jackson-core@2.22.0?type=jar"));
        quarkusBom.addDependency(qDbDep);
        quarkusBom.addDependency(new Dependency("pkg:maven/org.yaml/snakeyaml@2.0?type=jar"));

        BomMerger.mergeFlat(distBom, quarkusBom);

        // No dependency ref with a #N suffix should exist without a matching component
        Set<String> allBomRefs = collectAllBomRefs(distBom);
        for (Dependency dep : distBom.getDependencies()) {
            if (dep.getRef().contains("#")) {
                assertTrue(allBomRefs.contains(dep.getRef()),
                        "dependency ref " + dep.getRef()
                                + " has a #N suffix but no matching component");
            }
        }

        // No duplicate dependency refs
        assertNoDuplicateDepRefs(distBom);
    }

    // ── Test D: External SBOM with transitive deps not in archive ──

    @Test
    void mergeFlatExternalSbomDoesNotCreateOrphanTransitiveDeps() {
        // Assembly BOM with components matching archive JARs
        Bom distBom = newBom("pkg:maven/org.example/dist@1.0");
        addComp(distBom, library("narayana-jta",
                "pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4",
                "lib/narayana-jta-7.3.4.jar", "hash-njta"));
        addComp(distBom, library("jboss-logging",
                "pkg:maven/org.jboss.logging/jboss-logging@3.6.3",
                "lib/jboss-logging-3.6.3.jar", "hash-jlog"));

        Dependency distMain = new Dependency("pkg:maven/org.example/dist@1.0");
        distMain.addDependency(new Dependency("pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4"));
        distMain.addDependency(new Dependency("pkg:maven/org.jboss.logging/jboss-logging@3.6.3"));
        distBom.addDependency(distMain);
        Dependency njtaDep = new Dependency("pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4");
        njtaDep.addDependency(new Dependency("pkg:maven/org.jboss.logging/jboss-logging@3.6.3"));
        distBom.addDependency(njtaDep);
        distBom.addDependency(new Dependency("pkg:maven/org.jboss.logging/jboss-logging@3.6.3"));

        // External SBOM from Quarkus — includes transitive deps NOT in the archive
        Bom quarkusBom = newBom("pkg:generic/quarkus-run.jar@1.0");
        addComp(quarkusBom, library("narayana-jta",
                "pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4?type=jar",
                null, "hash-njta"));
        // These transitive deps have JARs NOT in the distribution archive
        addComp(quarkusBom, library("arjuna",
                "pkg:maven/org.jboss.narayana.arjunacore/arjuna@7.3.4?type=jar",
                null, "hash-arjuna"));
        addComp(quarkusBom, library("common",
                "pkg:maven/org.jboss.narayana/common@7.3.4?type=jar",
                null, "hash-common"));

        Dependency qMain = new Dependency("pkg:generic/quarkus-run.jar@1.0");
        qMain.addDependency(new Dependency("pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4?type=jar"));
        quarkusBom.addDependency(qMain);
        Dependency qNjta = new Dependency("pkg:maven/org.jboss.narayana.jta/narayana-jta@7.3.4?type=jar");
        qNjta.addDependency(new Dependency("pkg:maven/org.jboss.narayana.arjunacore/arjuna@7.3.4?type=jar"));
        qNjta.addDependency(new Dependency("pkg:maven/org.jboss.narayana/common@7.3.4?type=jar"));
        quarkusBom.addDependency(qNjta);
        quarkusBom.addDependency(new Dependency("pkg:maven/org.jboss.narayana.arjunacore/arjuna@7.3.4?type=jar"));
        quarkusBom.addDependency(new Dependency("pkg:maven/org.jboss.narayana/common@7.3.4?type=jar"));

        // Filter external SBOM by archive contents (arjuna and common are NOT in archive)
        ArchiveIndex archiveIndex = ArchiveIndex.of(List.of(
                new FileEntry("lib/narayana-jta-7.3.4.jar", "hash-njta"),
                new FileEntry("lib/jboss-logging-3.6.3.jar", "hash-jlog")),
                null, "sha256");

        AnchoredMerge.merge(distBom, quarkusBom,
                AnchoredMerge.Scope.of(distBom.getMetadata().getComponent(), archiveIndex));

        // Transitive deps not in archive should not appear in dependency graph
        Set<String> allBomRefs = collectAllBomRefs(distBom);
        for (Dependency dep : distBom.getDependencies()) {
            assertTrue(allBomRefs.contains(dep.getRef()),
                    "dependency ref " + dep.getRef()
                            + " should have a matching component (no orphan transitive deps)");
            if (dep.getDependencies() != null) {
                for (Dependency child : dep.getDependencies()) {
                    assertTrue(allBomRefs.contains(child.getRef()),
                            "dependsOn ref " + child.getRef()
                                    + " should have a matching component");
                }
            }
        }
    }
}
