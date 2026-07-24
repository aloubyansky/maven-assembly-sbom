package io.github.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;
import org.junit.jupiter.api.Test;

class DependencyListTest {

    @Test
    void ofBomNullDeps() {
        Bom bom = new Bom();
        assertNull(bom.getDependencies());

        DependencyList list = DependencyList.of(bom);

        assertTrue(list.isEmpty());
        assertNotNull(bom.getDependencies(),
                "null deps should be replaced with empty list");

        list.add(new Dependency("ref-a"));
        assertEquals(1, bom.getDependencies().size(),
                "mutations should be visible through bom.getDependencies()");
    }

    @Test
    void ofBomUnmodifiableDeps() {
        Bom bom = new Bom();
        bom.setDependencies(List.of(new Dependency("ref-a")));

        DependencyList list = DependencyList.of(bom);

        assertEquals(1, list.size());
        assertTrue(bom.getDependencies() instanceof ArrayList,
                "unmodifiable list should be replaced with mutable ArrayList");

        list.add(new Dependency("ref-b"));
        assertEquals(2, bom.getDependencies().size());
    }

    @Test
    void ofBomExistingDeps() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("ref-a"));
        List<Dependency> original = bom.getDependencies();

        DependencyList list = DependencyList.of(bom);

        assertEquals(1, list.size());
        assertSame(original, bom.getDependencies(),
                "existing mutable list should be reused");
    }

    @Test
    void ofChildrenNullDeps() {
        Dependency parent = new Dependency("parent-ref");
        assertNull(parent.getDependencies());

        DependencyList list = DependencyList.ofChildren(parent);

        assertTrue(list.isEmpty());
        assertNotNull(parent.getDependencies());

        list.add(new Dependency("child-ref"));
        assertEquals(1, parent.getDependencies().size());
    }

    @Test
    void ofChildrenUnmodifiable() {
        Dependency parent = new Dependency("parent-ref");
        parent.setDependencies(List.of(new Dependency("child-ref")));

        DependencyList list = DependencyList.ofChildren(parent);

        assertEquals(1, list.size());
        assertTrue(parent.getDependencies() instanceof ArrayList,
                "unmodifiable list should be replaced with ArrayList");

        list.add(new Dependency("child-2"));
        assertEquals(2, parent.getDependencies().size());
    }

    @Test
    void findByRefNormalized() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("pkg:maven/g/a@1.0?type=jar"));

        DependencyList list = DependencyList.of(bom);

        assertNotNull(list.findByRef("pkg:maven/g/a@1.0"),
                "should find by normalized ref (without ?type=jar)");
        assertNotNull(list.findByRef("pkg:maven/g/a@1.0?type=jar"),
                "should find by original ref too");
    }

    @Test
    void findByRefNull() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("ref-a"));

        DependencyList list = DependencyList.of(bom);

        assertNull(list.findByRef(null));
    }

    @Test
    void containsRef() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("ref-a"));

        DependencyList list = DependencyList.of(bom);

        assertTrue(list.containsRef("ref-a"));
        assertFalse(list.containsRef("ref-b"));
        assertFalse(list.containsRef(null));
    }

    @Test
    void addUpdatesIndex() {
        Bom bom = new Bom();
        DependencyList list = DependencyList.of(bom);

        assertFalse(list.containsRef("ref-a"));

        list.add(new Dependency("ref-a"));

        assertTrue(list.containsRef("ref-a"));
    }

    @Test
    void removeUpdatesIndex() {
        Bom bom = new Bom();
        Dependency dep = new Dependency("ref-a");
        bom.addDependency(dep);

        DependencyList list = DependencyList.of(bom);
        assertTrue(list.containsRef("ref-a"));

        list.remove(dep);

        assertFalse(list.containsRef("ref-a"));
        assertTrue(list.isEmpty());
    }

    @Test
    void removeByRefs() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("ref-a"));
        bom.addDependency(new Dependency("ref-b"));
        bom.addDependency(new Dependency("ref-c"));

        DependencyList list = DependencyList.of(bom);

        list.removeByRefs(Set.of("ref-a", "ref-c"));

        assertEquals(1, list.size());
        assertTrue(list.containsRef("ref-b"));
        assertFalse(list.containsRef("ref-a"));
        assertFalse(list.containsRef("ref-c"));
    }

    @Test
    void removeIfInvalidatesIndex() {
        Bom bom = new Bom();
        bom.addDependency(new Dependency("ref-a"));
        bom.addDependency(new Dependency("ref-b"));

        DependencyList list = DependencyList.of(bom);
        assertTrue(list.containsRef("ref-a"));

        list.removeIf(d -> "ref-a".equals(d.getRef()));

        assertEquals(1, list.size());
        assertFalse(list.containsRef("ref-a"),
                "index should be rebuilt without removed dependency");
        assertTrue(list.containsRef("ref-b"));
    }

    @Test
    void isEmptyAndSize() {
        Bom bom = new Bom();
        DependencyList list = DependencyList.of(bom);

        assertTrue(list.isEmpty());
        assertEquals(0, list.size());

        list.add(new Dependency("ref-a"));
        assertFalse(list.isEmpty());
        assertEquals(1, list.size());
    }
}
