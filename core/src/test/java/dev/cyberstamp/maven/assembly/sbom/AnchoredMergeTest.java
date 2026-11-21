package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class AnchoredMergeTest {

    private static final ArchiveIndex LAYOUT = ArchiveIndex.of(List.of(), null, "SHA-256");

    @Test
    void hashAnchoredComponentEnrichesTheCopy() {
        Component copy = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(copy);
        Component described = lib("a", "pkg:maven/g/a@1", "aa", "x/a.jar");
        described.setLicenses(mit());
        Property p = new Property();
        p.setName("k");
        p.setValue("v");
        described.addProperty(p);

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(described), flat(target, LAYOUT));

        assertEquals(1, target.getComponents().size());
        assertSame(copy, target.getComponents().get(0));
        assertEquals("MIT", copy.getLicenses().getLicenses().get(0).getId());
        assertEquals("k", copy.getProperties().get(0).getName());
        assertEquals(List.of("lib/a.jar"), locations(copy), "the copy keeps its own location");
        assertEquals("pkg:maven/g/a@1", result.refMap().get("pkg:maven/g/a@1"));
        assertEquals(1, result.anchored());
    }

    @Test
    void locationAnchorUsesTheDerivedRootOffset() {
        // Keycloak: the Quarkus SBOM's root is the dist's lib/
        Component run = lib("quarkus-run.jar", "pkg:generic/quarkus-run.jar@1", "r1", "lib/quarkus-run.jar");
        Component core = lib("core", "pkg:maven/io.quarkus/core@1", null, "lib/lib/main/core.jar");
        Bom target = bom(run, core);
        Bom source = bom(lib("core", "pkg:maven/io.quarkus/core@1", null, "lib/main/core.jar"));
        source.getMetadata().setComponent(lib("quarkus-run.jar", "pkg:generic/quarkus-run.jar@1", "r1",
                "quarkus-run.jar"));

        assertEquals("lib/", AnchoredMerge.rootOffset(source, MergeTarget.of(target)));
        AnchoredMerge.Result result = AnchoredMerge.merge(target, source, flat(target, LAYOUT));

        assertEquals(2, target.getComponents().size());
        assertEquals(1, result.anchored());
    }

    @Test
    void locationWithDifferentHashDoesNotAnchor() {
        Component copy = lib("a", "pkg:maven/g/a@2", "new", "lib/a.jar");
        Bom target = bom(copy);

        AnchoredMerge.Result result = AnchoredMerge.merge(target,
                bom(lib("a", "pkg:maven/g/a@1", "old", "lib/a.jar")), flat(target, LAYOUT));

        assertEquals(0, result.anchored());
        assertEquals(List.of(copy), target.getComponents(), "an older build of the file is not shipped");
    }

    @Test
    void twoSourceComponentsWithOneHashEnrichOneCopy() {
        Component copy = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(copy);

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(
                lib("a", "pkg:maven/g/a@1", "aa", null), lib("a-alias", "pkg:maven/g/a-alias@1", "aa", null)),
                flat(target, LAYOUT));

        assertEquals(1, target.getComponents().size());
        assertEquals("pkg:maven/g/a@1", result.refMap().get("pkg:maven/g/a-alias@1"));
    }

    @Test
    void shadedChildAnchorsByPurlWithinItsJar() {
        Component nestedCopy = lib("x", "pkg:maven/g/x@1", null, null);
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar", nestedCopy);
        Bom target = bom(jar);
        Component shaded = lib("x", "pkg:maven/g/x@1?type=jar", null, null);
        shaded.setLicenses(mit());

        AnchoredMerge.merge(target, bom(lib("a", "pkg:maven/g/a@1", "aa", null, shaded)), flat(target, LAYOUT));

        assertEquals(List.of(nestedCopy), jar.getComponents());
        assertEquals("MIT", nestedCopy.getLicenses().getLicenses().get(0).getId());
    }

    @Test
    void shadedChildWithoutCopyIsKeptUnderItsJar() {
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(jar);

        AnchoredMerge.Result result = AnchoredMerge.merge(target,
                bom(lib("a", "pkg:maven/g/a@1", "aa", null, lib("x", "pkg:maven/g/x@1", null, null))),
                flat(target, LAYOUT));

        assertEquals("pkg:maven/g/x@1", jar.getComponents().get(0).getPurl());
        assertEquals(1, result.kept());
    }

    @Test
    void npmPackageWithoutFileIsKeptUnderTheMergeParent() {
        Bom target = bom();

        AnchoredMerge.merge(target, bom(npm("react", "pkg:npm/react@19", "sha", "node_modules/react/index.js")),
                flat(target, LAYOUT));

        assertEquals("pkg:npm/react@19", target.getComponents().get(0).getBomRef());
    }

    @Test
    void unanchoredMavenPackageIsDroppedWithALayout() {
        Bom target = bom();

        AnchoredMerge.Result result = AnchoredMerge.merge(target,
                bom(lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar")), flat(target, LAYOUT));

        assertTrue(target.getComponents().isEmpty());
        assertEquals(1, result.dropped());
        assertNull(result.refMap().get("pkg:maven/g/x@1"));
    }

    @Test
    void unanchoredMavenPackageIsKeptWithoutALayout() {
        Bom target = bom();

        AnchoredMerge.merge(target, bom(lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar")), flat(target, null));

        assertEquals("pkg:maven/g/x@1", target.getComponents().get(0).getBomRef());
    }

    @Test
    void keptComponentWithTakenRefGetsNextSuffix() {
        // p@1 is already used inside a jar: not a sibling, so only its ref is taken
        Component other = npm("p", "pkg:npm/p@1", "p1", null);
        Bom target = bom(lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar", other));

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(npm("p", "pkg:npm/p@1", "p2", null)),
                flat(target, LAYOUT));

        assertEquals("pkg:npm/p@1#2", result.refMap().get("pkg:npm/p@1"));
        assertEquals("pkg:npm/p@1#2", target.getComponents().get(1).getBomRef());
        assertEquals(1, target.getComponents().get(0).getComponents().size());
    }

    @Test
    void fileCopyAnchoredByLibraryTakesItsIdentity() {
        Component file = new Component();
        file.setType(Component.Type.FILE);
        file.setName("lodash.js");
        file.setBomRef("file:web/lodash.js");
        file.addHash(new Hash("SHA-256", "ld"));
        file.setEvidence(evidence("web/lodash.js"));
        Bom target = bom(file);

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(lib("lodash", "pkg:npm/lodash@4", "ld", null)),
                flat(target, LAYOUT));

        assertEquals(Component.Type.LIBRARY, file.getType());
        assertEquals("pkg:npm/lodash@4", file.getPurl());
        assertEquals("pkg:npm/lodash@4", file.getBomRef());
        assertEquals(List.of("web/lodash.js"), locations(file));
        assertEquals("pkg:npm/lodash@4", result.refMap().get("pkg:npm/lodash@4"));
    }

    @Test
    void excludedComponentNeverAnchors() {
        Component copy = lib("a", "pkg:maven/g/a@2", "aa", "lib/a.jar");
        Bom target = bom(copy);
        Component rejected = lib("a", "pkg:maven/g/a@1", "aa", null);
        Set<Component> excluded = Collections.newSetFromMap(new IdentityHashMap<>());
        excluded.add(rejected);

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(rejected),
                new AnchoredMerge.Scope(target.getMetadata().getComponent(), LAYOUT, excluded, Set.of()));

        assertEquals(0, result.anchored());
        assertEquals("pkg:maven/g/a@2", copy.getPurl());
        assertFalse(result.refMap().containsKey("pkg:maven/g/a@1"));
    }

    @Test
    void shippedComponentIsKeptWhereTheAnalyzerFoundIt() {
        Bom target = bom();
        Component matched = lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar");
        Set<Component> shipped = Collections.newSetFromMap(new IdentityHashMap<>());
        shipped.add(matched);

        AnchoredMerge.merge(target, bom(matched),
                new AnchoredMerge.Scope(target.getMetadata().getComponent(), LAYOUT, Set.of(), shipped));

        assertEquals(List.of("lib/x.jar"), locations(target.getComponents().get(0)));
    }

    @Test
    void sourceEdgesConnectTheMappedCopies() {
        Component x = lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar");
        Bom target = bom(x, lib("w", "pkg:maven/g/w@1", "ww", "lib/w.jar", npm("y", "pkg:npm/y@1", "other", null)));
        Bom source = bom(npm("y", "pkg:npm/y@1", "yy", null), lib("x", "pkg:maven/g/x@1", "xx", null));
        source.addDependency(dependency("pkg:npm/y@1", "pkg:maven/g/x@1"));

        AnchoredMerge.merge(target, source, flat(target, LAYOUT));

        assertEquals(List.of("pkg:maven/g/x@1"), dependsOn(target, "pkg:npm/y@1#2"));
    }

    @Test
    void edgeWithDroppedEndIsDropped() {
        Bom target = bom();
        Bom source = bom(npm("y", "pkg:npm/y@1", "yy", null), lib("z", "pkg:maven/g/z@1", "zz", "lib/z.jar"));
        source.addDependency(dependency("pkg:npm/y@1", "pkg:maven/g/z@1"));

        AnchoredMerge.merge(target, source, flat(target, LAYOUT));

        assertEquals(List.of(), dependsOn(target, "pkg:npm/y@1"));
    }

    @Test
    void sourceMainEdgeToContentIsContainmentNotADependency() {
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(jar);
        Bom source = bom(lib("x", "pkg:maven/g/x@1", null, null));
        source.getMetadata().getComponent().setBomRef("pkg:maven/g/a@1?type=jar");
        source.addDependency(dependency("pkg:maven/g/a@1?type=jar", "pkg:maven/g/x@1"));

        AnchoredMerge.merge(target, source, AnchoredMerge.Scope.of(jar, LAYOUT));

        assertEquals("pkg:maven/g/x@1", jar.getComponents().get(0).getBomRef(), "shaded in the jar");
        assertEquals(List.of(), dependsOn(target, "pkg:maven/g/a@1"), "the source's main entry lands on the jar, "
                + "but x is nested in it: containment, not a dependency");
    }

    @Test
    void sourceMainEdgesGoToTheMergeParent() {
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Component y = lib("y", "pkg:maven/g/y@1", "yy", "lib/y.jar");
        Bom target = bom(jar, y);
        Bom source = bom(lib("y", "pkg:maven/g/y@1", "yy", null));
        source.getMetadata().getComponent().setBomRef("pkg:maven/g/a@1?type=jar");
        source.addDependency(dependency("pkg:maven/g/a@1?type=jar", "pkg:maven/g/y@1"));

        AnchoredMerge.merge(target, source, AnchoredMerge.Scope.of(jar, LAYOUT));

        assertEquals(List.of("pkg:maven/g/y@1"), dependsOn(target, "pkg:maven/g/a@1"));
    }

    @Test
    void anchoredCopyWithoutEntryGetsTheSourceEntry() {
        Bom target = bom(lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar"), lib("y", "pkg:maven/g/y@1", "yy", "lib/y.jar"));
        Bom source = bom(lib("x", "pkg:maven/g/x@1", "xx", null), lib("y", "pkg:maven/g/y@1", "yy", null));
        source.addDependency(dependency("pkg:maven/g/x@1", "pkg:maven/g/y@1"));
        source.addDependency(dependency("pkg:maven/g/y@1"));

        AnchoredMerge.merge(target, source, flat(target, LAYOUT));

        assertEquals(List.of("pkg:maven/g/y@1"), dependsOn(target, "pkg:maven/g/x@1"));
        assertEquals(List.of(), dependsOn(target, "pkg:maven/g/y@1"), "the source says y has none");
    }

    @Test
    void mergingTheSameSbomTwiceAddsNothing() {
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(jar);

        AnchoredMerge.merge(target, sbomOfJar(), flat(target, LAYOUT));
        int components = target.getComponents().size();
        int entries = target.getDependencies().size();
        AnchoredMerge.Result second = AnchoredMerge.merge(target, sbomOfJar(), flat(target, LAYOUT));

        assertEquals(0, second.kept());
        assertEquals(components, target.getComponents().size());
        assertEquals(1, jar.getComponents().size());
        assertEquals(entries, target.getDependencies().size());
        assertTrue(target.getDependencies().stream().noneMatch(d -> d.getRef().contains("#")));
    }

    private static Bom sbomOfJar() {
        Bom source = bom(lib("a", "pkg:maven/g/a@1", "aa", null, lib("x", "pkg:maven/g/x@1", null, null)),
                npm("react", "pkg:npm/react@19", "rr", null));
        source.addDependency(dependency("pkg:npm/react@19"));
        source.addDependency(dependency("pkg:maven/g/a@1", "pkg:maven/g/x@1"));
        return source;
    }

    static org.cyclonedx.model.Dependency dependency(String ref, String... children) {
        org.cyclonedx.model.Dependency d = new org.cyclonedx.model.Dependency(ref);
        for (String child : children) {
            d.addDependency(new org.cyclonedx.model.Dependency(child));
        }
        return d;
    }

    /** The sorted refs an entry lists; fails if the entry is missing. */
    static List<String> dependsOn(Bom bom, String ref) {
        org.cyclonedx.model.Dependency entry = bom.getDependencies() == null ? null
                : bom.getDependencies().stream().filter(d -> ref.equals(d.getRef())).findFirst().orElse(null);
        if (entry == null) {
            throw new AssertionError("no entry for " + ref + " in "
                    + (bom.getDependencies() == null ? "[]"
                            : bom.getDependencies().stream().map(org.cyclonedx.model.Dependency::getRef).toList()));
        }
        return entry.getDependencies() == null ? List.of()
                : entry.getDependencies().stream().map(org.cyclonedx.model.Dependency::getRef).sorted().toList();
    }

    @Test
    void flatSbomTopComponentAnchorsToItsCopy() {
        // Keycloak: the Quarkus SBOM's top component is quarkus-run.jar, shipped in the dist
        Component run = lib("quarkus-run.jar", "pkg:generic/quarkus-run.jar@1", "r1", "lib/quarkus-run.jar");
        Component core = lib("core", "pkg:maven/io.quarkus/core@1", "c1", "lib/lib/main/core.jar");
        Bom target = bom(run, core);
        Bom source = bom(lib("core", "pkg:maven/io.quarkus/core@1", "c1", "lib/main/core.jar"));
        source.getMetadata().setComponent(lib("quarkus-run.jar", "pkg:generic/quarkus-run.jar@1", "r1",
                "quarkus-run.jar"));
        source.addDependency(dependency("pkg:generic/quarkus-run.jar@1", "pkg:maven/io.quarkus/core@1"));

        AnchoredMerge.merge(target, source, flat(target, LAYOUT));

        assertEquals(List.of("pkg:maven/io.quarkus/core@1"), dependsOn(target, "pkg:generic/quarkus-run.jar@1"));
    }

    // Final review findings

    @Test
    void rejectedComponentIsNotAddedEvenThoughItsHashShips() {
        // the external SBOM claims g:a:1 for lib/a.jar; its pom.properties say 2
        Component copy = lib("a", "pkg:maven/g/a@2", "aa", "lib/a.jar");
        Bom target = bom(copy);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("lib/a.jar", "aa"),
                new FileEntry("lib/x.jar", "xx")), null, "SHA-256");
        Component matchedChild = lib("x", "pkg:maven/g/x@1", "xx", "lib/x.jar");
        Component rejected = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar", matchedChild);
        Set<Component> excluded = Collections.newSetFromMap(new IdentityHashMap<>());
        excluded.add(rejected);
        Set<Component> shipped = Collections.newSetFromMap(new IdentityHashMap<>());
        shipped.add(matchedChild);

        AnchoredMerge.merge(target, bom(rejected),
                new AnchoredMerge.Scope(target.getMetadata().getComponent(), layout, excluded, shipped));

        assertEquals(List.of("pkg:maven/g/a@2", "pkg:maven/g/x@1"),
                target.getComponents().stream().map(Component::getPurl).toList(),
                "the rejected claim is dropped; its matched child is lifted to its place");
    }

    @Test
    void thinJarsUnshippedDependencyIsNotRecordedAsShaded() {
        // a cyclonedx-maven-plugin SBOM inside a.jar lists its dependencies flat, hashed, unlocated
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom target = bom(jar);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("lib/a.jar", "aa")), null, "SHA-256");

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(lib("y", "pkg:maven/g/y@1", "yy", null)),
                AnchoredMerge.Scope.of(jar, layout));

        assertEquals(1, result.dropped());
        assertNull(jar.getComponents());
    }

    @Test
    void hashMatchPrefersTheCopyInTheParentsContext() {
        // guava ships in war1's WEB-INF/lib and at lib/; a.jar in war1 names guava
        Component warGuava = lib("guava", "pkg:maven/g/guava@1", "gg", "web/war1/WEB-INF/lib/guava.jar");
        warGuava.setBomRef("pkg:maven/g/guava@1#2");
        Component jar = lib("a", "pkg:maven/g/a@1", "aa", "web/war1/WEB-INF/lib/a.jar");
        Component war1 = war("pkg:maven/g/war1@1?type=war", "web/war1/", jar, warGuava);
        Bom target = bom(lib("guava", "pkg:maven/g/guava@1", "gg", "lib/guava.jar"), war1);
        Bom source = bom(lib("guava", "pkg:maven/g/guava@1", "gg", null));
        source.getMetadata().getComponent().setBomRef("a");
        source.addDependency(dependency("a", "pkg:maven/g/guava@1"));

        AnchoredMerge.merge(target, source, AnchoredMerge.Scope.of(jar, LAYOUT));

        assertEquals(List.of("pkg:maven/g/guava@1#2"), dependsOn(target, "pkg:maven/g/a@1"));
    }

    @Test
    void splitOutCopyKeepsItsSourceRefForEdges() {
        // syft-style UUID bom-refs; x is merged at the top level from lib/ and the war
        Component x = lib("x", "pkg:maven/g/x@1", null, "lib/x.jar");
        x.getEvidence().addOccurrence(evidence("web/war/WEB-INF/lib/x.jar").getOccurrences().get(0));
        Component war = war("pkg:maven/g/war@1?type=war", "web/war/");
        Bom target = bom(war, x);
        Component y = npm("y", "pkg:npm/y@1", "y1", null);
        y.setBomRef("uuid-y");
        Component sx = lib("x", "pkg:maven/g/x@1", null, "WEB-INF/lib/x.jar");
        sx.setBomRef("uuid-x");
        Bom source = bom(y, sx);
        source.addDependency(dependency("uuid-y", "uuid-x"));

        AnchoredMerge.merge(target, source, AnchoredMerge.Scope.of(war, null));

        Component warX = war.getComponents().stream().filter(c -> "x".equals(c.getName())).findFirst().orElseThrow();
        assertEquals(List.of(warX.getBomRef()), dependsOn(target, y.getBomRef()), "y keeps its own ref, " + y.getBomRef());
    }

    // Regression tests from the Artemis comparison

    private static Component war(String purl, String directory, Component... nested) {
        Component war = lib("war", purl, null, directory, nested);
        return war;
    }

    @Test
    void fileWithAnotherHashAtAShippedPathIsNotShipped() {
        // the WAR's SBOM lists its original web.xml; the distribution ships a replaced one
        Component shipped = new Component();
        shipped.setType(Component.Type.FILE);
        shipped.setName("web.xml");
        shipped.setBomRef("file:web/app.war/WEB-INF/web.xml");
        shipped.addHash(new Hash("SHA-256", "new"));
        shipped.setEvidence(evidence("web/app.war/WEB-INF/web.xml"));
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/");
        Bom target = bom(war, shipped);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("web/app.war/WEB-INF/web.xml", "new")), null,
                "SHA-256");
        Component original = new Component();
        original.setType(Component.Type.FILE);
        original.setName("web.xml");
        original.setBomRef("file:WEB-INF/web.xml");
        original.addHash(new Hash("SHA-256", "old"));

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(original), AnchoredMerge.Scope.of(war, layout));

        assertEquals(1, result.dropped());
        assertEquals(2, target.getComponents().size());
    }

    @Test
    void jarExcludedFromAnUnpackedWarIsNotTheTopLevelCopy() {
        // guava ships at lib/ and is excluded from the unpacked WAR its SBOM lists it in
        Component guava = lib("guava", "pkg:maven/g/guava@1", "gg", "lib/guava.jar");
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/");
        Bom target = bom(war, guava);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("lib/guava.jar", "gg"),
                new FileEntry("web/app.war/index.html", "ii")), null, "SHA-256");
        Bom source = bom(lib("guava", "pkg:maven/g/guava@1", "gg", "WEB-INF/lib/guava.jar"),
                lib("ep", "pkg:maven/g/ep@1", "ee", "WEB-INF/lib/ep.jar"));
        source.addDependency(dependency("pkg:maven/g/guava@1", "pkg:maven/g/ep@1"));

        AnchoredMerge.Result result = AnchoredMerge.merge(target, source, AnchoredMerge.Scope.of(war, layout));

        assertEquals(2, result.dropped(), "neither ships inside the WAR");
        assertTrue(target.getDependencies() == null || target.getDependencies().stream()
                .noneMatch(d -> d.getRef().equals("pkg:maven/g/guava@1")), "no edge reaches the top-level guava");
    }

    @Test
    void upstreamWarUnpackedAtTheSbomRootShipsAsItsDirectory() {
        // the overlay's SBOM lists the upstream WAR at its root, with the packed WAR's hash
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/");
        Bom target = bom(war);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("web/app.war/index.html", "ii")), null, "SHA-256");
        Component upstream = lib("upstream", "pkg:maven/g/upstream@1?type=war", "packed-war-hash", null);
        upstream.setEvidence(evidence(""));

        AnchoredMerge.merge(target, bom(upstream), AnchoredMerge.Scope.of(war, layout));

        assertEquals("pkg:maven/g/upstream@1?type=war", war.getComponents().get(0).getPurl());
        assertEquals(List.of("web/app.war/"), locations(war.getComponents().get(0)));
    }

    // Follow-up fixes

    @Test
    void distributionRelativeLocationsOfAnUnpackedWarAreNotPrefixedTwice() {
        // the WAR's SBOM already uses paths relative to the distribution root
        Component x = lib("x", "pkg:maven/g/x@1", "xx", "web/app.war/WEB-INF/lib/x.jar");
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/", x);
        Bom target = bom(war);
        Component react = npm("react", "pkg:npm/react@19", "rr", "web/app.war/js/app.js");

        AnchoredMerge.merge(target, bom(lib("x", "pkg:maven/g/x@1", "xx", "web/app.war/WEB-INF/lib/x.jar"), react),
                AnchoredMerge.Scope.of(war, null));

        assertEquals(List.of("web/app.war/js/app.js"), locations(react));
    }

    @Test
    void splitOutCopyOwnsItsLocationForLaterComponents() {
        // x is merged at the top level from lib/ and the war; the war's SBOM
        // lists x twice at its war location (as a file and as a library)
        Component x = lib("x", "pkg:maven/g/x@1", null, "lib/x.jar");
        x.getEvidence().addOccurrence(evidence("web/war/WEB-INF/lib/x.jar").getOccurrences().get(0));
        Component war = war("pkg:maven/g/war@1?type=war", "web/war/");
        Bom target = bom(war, x);
        Component file = new Component();
        file.setType(Component.Type.FILE);
        file.setName("x.jar");
        file.setBomRef("file:WEB-INF/lib/x.jar");
        file.setEvidence(evidence("WEB-INF/lib/x.jar"));

        AnchoredMerge.merge(target, bom(file, lib("x", "pkg:maven/g/x@1", null, "WEB-INF/lib/x.jar")),
                AnchoredMerge.Scope.of(war, null));

        assertEquals(1, war.getComponents().size(), "both describe the war's one copy of x");
    }

    @Test
    void edgeToAFileCopyThatTookALibraryIdentityFollowsTheRename() {
        Component copy = new Component();
        copy.setType(Component.Type.FILE);
        copy.setName("a.jar");
        copy.setBomRef("file:lib/a.jar");
        copy.addHash(new Hash("SHA-256", "aa"));
        copy.setEvidence(evidence("lib/a.jar"));
        Bom target = bom(copy);
        Component file = new Component();
        file.setType(Component.Type.FILE);
        file.setName("a.jar");
        file.setBomRef("file:lib/a.jar");
        file.addHash(new Hash("SHA-256", "aa"));
        Component y = npm("y", "pkg:npm/y@1", "y1", null);
        y.setBomRef("uuid-y");
        Bom source = bom(file, lib("lib-a", "pkg:maven/g/lib-a@1", "aa", null), y);
        source.addDependency(dependency("uuid-y", "file:lib/a.jar"));

        AnchoredMerge.merge(target, source, flat(target, null));

        assertEquals("pkg:maven/g/lib-a@1", copy.getBomRef());
        assertEquals(List.of("pkg:maven/g/lib-a@1"), dependsOn(target, "uuid-y"));
    }

    @Test
    void hashesDifferingOnlyInCaseAreOneHash() {
        Component copy = lib("a", "pkg:maven/g/a@1", "AA", "lib/a.jar");
        Bom target = bom(copy);
        Component described = lib("a", "pkg:maven/g/a@1", "aa", null);
        described.addHash(new Hash("SHA-1", "s1"));

        AnchoredMerge.merge(target, bom(described), flat(target, null));

        assertEquals(List.of("SHA-256", "SHA-1"), copy.getHashes().stream().map(Hash::getAlgorithm).toList());
    }

    @Test
    void directoryOccurrenceWithNothingUnderItIsDropped() {
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/");
        Bom target = bom(war);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("web/app.war/index.html", "ii")), null, "SHA-256");
        Component sub = lib("sub", "pkg:maven/g/sub@1?type=war", null, null);
        sub.setEvidence(evidence("sub/"));

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(sub), AnchoredMerge.Scope.of(war, layout));

        assertEquals(1, result.dropped());
        assertNull(war.getComponents());
    }

    @Test
    void hashShippedOnlyOutsideAnUnpackedWarDoesNotShipInIt() {
        Component war = war("pkg:maven/g/app@1?type=war", "web/app.war/");
        Bom target = bom(war);
        ArchiveIndex layout = ArchiveIndex.of(List.of(new FileEntry("conf/x.txt", "ll"),
                new FileEntry("web/app.war/index.html", "ii")), null, "SHA-256");
        Component file = new Component();
        file.setType(Component.Type.FILE);
        file.setName("x.txt");
        file.setBomRef("file:WEB-INF/x.txt");
        file.addHash(new Hash("SHA-256", "ll"));

        AnchoredMerge.Result result = AnchoredMerge.merge(target, bom(file), AnchoredMerge.Scope.of(war, layout));

        assertEquals(1, result.dropped());
    }

    static AnchoredMerge.Scope flat(Bom target, ArchiveIndex layout) {
        return AnchoredMerge.Scope.of(target.getMetadata().getComponent(), layout);
    }

    static Bom bom(Component... components) {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("app");
        main.setBomRef("app");
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        bom.setComponents(new ArrayList<>(List.of(components)));
        return bom;
    }

    static Component lib(String name, String purl, String sha256, String location, Component... nested) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName(name);
        c.setPurl(purl);
        c.setBomRef(purl);
        if (sha256 != null) {
            c.addHash(new Hash("SHA-256", sha256));
        }
        if (location != null) {
            c.setEvidence(evidence(location));
        }
        if (nested.length > 0) {
            c.setComponents(new ArrayList<>(List.of(nested)));
        }
        return c;
    }

    /** An npm package: its integrity hash is SHA-512, which no layout verifies. */
    static Component npm(String name, String purl, String sha512, String location) {
        Component c = lib(name, purl, null, location);
        c.addHash(new Hash("SHA-512", sha512));
        return c;
    }

    @Test
    void unfindablePackageIsKeptEvenWithASourceTreeLocation() {
        Bom target = bom();

        AnchoredMerge.merge(target, bom(npm("react", "pkg:npm/react@19", "rr", "node_modules/react/index.js")),
                flat(target, LAYOUT));

        assertEquals(1, target.getComponents().size());
    }

    @Test
    void hashedGenericFileNotInTheLayoutIsDropped() {
        Bom target = bom();

        AnchoredMerge.Result result = AnchoredMerge.merge(target,
                bom(lib("tool", "pkg:generic/tool.jar@1", "tt", "lib/tool.jar")), flat(target, LAYOUT));

        assertEquals(1, result.dropped());
    }

    static Evidence evidence(String location) {
        Evidence evidence = new Evidence();
        Occurrence occurrence = new Occurrence();
        occurrence.setLocation(location);
        evidence.addOccurrence(occurrence);
        return evidence;
    }

    static List<String> locations(Component c) {
        return c.getEvidence() == null || c.getEvidence().getOccurrences() == null ? List.of()
                : c.getEvidence().getOccurrences().stream().map(Occurrence::getLocation).toList();
    }

    private static LicenseChoice mit() {
        License license = new License();
        license.setId("MIT");
        LicenseChoice choice = new LicenseChoice();
        choice.addLicense(license);
        return choice;
    }
}
