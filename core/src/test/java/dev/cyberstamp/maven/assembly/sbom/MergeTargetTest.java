package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class MergeTargetTest {

    @Test
    void findsByHashAtAnyDepth() {
        Component nested = library("x", "pkg:maven/g/x@1", "aa11", null);
        Component jar = library("a", "pkg:maven/g/a@1", "bb22", "lib/a.jar", nested);
        MergeTarget target = MergeTarget.of(bomOf(jar));

        assertSame(nested, target.byHash(new Hash("SHA-256", "AA11")));
        assertSame(jar, target.byHash(new Hash("SHA-256", "bb22")));
        assertNull(target.byHash(new Hash("SHA-1", "aa11")), "another algorithm is another hash");
    }

    @Test
    void findsByOccurrenceLocation() {
        Component jar = library("a", "pkg:maven/g/a@1", "bb22", "lib/a.jar");
        MergeTarget target = MergeTarget.of(bomOf(jar));

        assertSame(jar, target.byLocation("lib/a.jar"));
        assertNull(target.byLocation("lib/b.jar"));
    }

    @Test
    void purlLookupIsScopedToTheParent() {
        Component inA = library("x", "pkg:maven/g/x@1", null, null);
        Component inB = library("x", "pkg:maven/g/x@1", null, null);
        Component a = library("a", "pkg:maven/g/a@1", "aa", "lib/a.jar", inA);
        Component b = library("b", "pkg:maven/g/b@1", "bb", "lib/b.jar", inB);
        MergeTarget target = MergeTarget.of(bomOf(a, b));

        assertSame(inA, target.byPurlWithin(a, "pkg:maven/g/x@1?type=jar"));
        assertSame(inB, target.byPurlWithin(b, "pkg:maven/g/x@1"));
        assertNull(target.byPurlWithin(a, "pkg:maven/g/b@1"));
        assertSame(a, target.parentOf(inA));
        assertNull(target.parentOf(a));
    }

    @Test
    void claimRefSuffixesTakenRefs() {
        MergeTarget target = MergeTarget.of(bomOf(library("p", "p", null, null)));

        assertEquals("p#2", target.claimRef("p"));
        assertEquals("p#3", target.claimRef("p"));
        assertEquals("q", target.claimRef("q"));
        assertEquals("app", MergeTarget.of(bomOf()).main().getBomRef());
        assertEquals("app#2", MergeTarget.of(bomOf()).claimRef("app"), "the main component's ref is taken too");
    }

    @Test
    void addedComponentsAreIndexed() {
        Component parent = library("a", "pkg:maven/g/a@1", "aa", "lib/a.jar");
        Bom bom = bomOf(parent);
        MergeTarget target = MergeTarget.of(bom);
        Component child = library("x", "pkg:maven/g/x@1", "cc", null, library("y", "pkg:maven/g/y@1", "dd", null));
        Component top = library("t", "pkg:npm/t@1", null, null);

        target.add(child, parent);
        target.add(top, target.main());

        assertSame(child, target.byHash(new Hash("SHA-256", "cc")));
        assertSame(child, target.parentOf(target.byHash(new Hash("SHA-256", "dd"))));
        assertSame(parent, target.parentOf(child));
        assertEquals(List.of(child), parent.getComponents());
        assertEquals(2, bom.getComponents().size(), "a child of the main component is a top-level component");
        assertEquals("pkg:maven/g/x@1#2", target.claimRef("pkg:maven/g/x@1"));
    }

    /** A BOM whose main component is {@code app}, with the given top-level components. */
    private static Bom bomOf(Component... components) {
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

    /** A library whose bom-ref is its purl, with an optional SHA-256 hash, location and nested copies. */
    private static Component library(String name, String purl, String sha256, String location, Component... nested) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName(name);
        c.setPurl(purl);
        c.setBomRef(purl);
        if (sha256 != null) {
            c.addHash(new Hash("SHA-256", sha256));
        }
        if (location != null) {
            Evidence evidence = new Evidence();
            Occurrence occurrence = new Occurrence();
            occurrence.setLocation(location);
            evidence.addOccurrence(occurrence);
            c.setEvidence(evidence);
        }
        if (nested.length > 0) {
            c.setComponents(new ArrayList<>(List.of(nested)));
        }
        return c;
    }
}
