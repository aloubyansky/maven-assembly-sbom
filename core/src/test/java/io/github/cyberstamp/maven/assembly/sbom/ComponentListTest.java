package io.github.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;

class ComponentListTest {

    @Test
    void ofBomNullComponents() {
        Bom bom = new Bom();
        assertNull(bom.getComponents());

        ComponentList list = ComponentList.of(bom);

        assertTrue(list.isEmpty());
        assertNotNull(bom.getComponents(), "null should be replaced with empty list");

        list.add(createComp("a", "ref-a", "pkg:maven/g/a@1.0"));
        assertEquals(1, bom.getComponents().size(),
                "mutations should be visible through bom.getComponents()");
    }

    @Test
    void ofBomUnmodifiableComponents() {
        Bom bom = new Bom();
        Component comp = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        bom.setComponents(List.of(comp));

        ComponentList list = ComponentList.of(bom);

        assertEquals(1, list.size());
        assertTrue(bom.getComponents() instanceof ArrayList,
                "unmodifiable list should be replaced with mutable ArrayList");

        list.add(createComp("b", "ref-b", "pkg:maven/g/b@1.0"));
        assertEquals(2, bom.getComponents().size());
    }

    @Test
    void ofBomMutableComponents() {
        Bom bom = new Bom();
        ArrayList<Component> original = new ArrayList<>();
        original.add(createComp("a", "ref-a", "pkg:maven/g/a@1.0"));
        bom.setComponents(original);

        ComponentList list = ComponentList.of(bom);

        assertSame(original, bom.getComponents(),
                "mutable ArrayList should be reused, not copied");
        assertEquals(1, list.size());
    }

    @Test
    void ofNestedNullComponents() {
        Component parent = new Component();
        assertNull(parent.getComponents());

        ComponentList list = ComponentList.ofNested(parent);

        assertTrue(list.isEmpty());
        assertNotNull(parent.getComponents());

        list.add(createComp("child", "ref-child", "pkg:maven/g/child@1.0"));
        assertEquals(1, parent.getComponents().size());
    }

    @Test
    void ofNestedUnmodifiableComponents() {
        Component parent = new Component();
        Component child = createComp("child", "ref-child", "pkg:maven/g/child@1.0");
        parent.setComponents(List.of(child));

        ComponentList list = ComponentList.ofNested(parent);

        assertEquals(1, list.size());
        assertTrue(parent.getComponents() instanceof ArrayList);
    }

    @Test
    void findByPurlNormalized() {
        Bom bom = new Bom();
        Component comp = createComp("lib", "pkg:maven/g/lib@1.0?type=jar",
                "pkg:maven/g/lib@1.0?type=jar");
        bom.setComponents(new ArrayList<>(List.of(comp)));

        ComponentList list = ComponentList.of(bom);

        assertSame(comp, list.findByPurl("pkg:maven/g/lib@1.0"),
                "should find by normalized PURL (without ?type=jar)");
        assertSame(comp, list.findByPurl("pkg:maven/g/lib@1.0?type=jar"),
                "should find by original PURL too");
    }

    @Test
    void findByPurlNull() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(
                createComp("a", "ref-a", "pkg:maven/g/a@1.0"))));

        ComponentList list = ComponentList.of(bom);

        assertNull(list.findByPurl(null));
    }

    @Test
    void findByPurlNoMatch() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(
                createComp("a", "ref-a", "pkg:maven/g/a@1.0"))));

        ComponentList list = ComponentList.of(bom);

        assertNull(list.findByPurl("pkg:maven/g/nonexistent@1.0"));
    }

    @Test
    void findByBomRefNormalized() {
        Bom bom = new Bom();
        Component comp = createComp("lib", "pkg:maven/g/lib@1.0?type=jar",
                "pkg:maven/g/lib@1.0?type=jar");
        bom.setComponents(new ArrayList<>(List.of(comp)));

        ComponentList list = ComponentList.of(bom);

        assertSame(comp, list.findByBomRef("pkg:maven/g/lib@1.0"),
                "should find by normalized bom-ref");
    }

    @Test
    void containsPurl() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(
                createComp("a", "ref-a", "pkg:maven/g/a@1.0"))));

        ComponentList list = ComponentList.of(bom);

        assertTrue(list.containsPurl("pkg:maven/g/a@1.0"));
        assertFalse(list.containsPurl("pkg:maven/g/b@1.0"));
        assertFalse(list.containsPurl(null));
    }

    @Test
    void addUpdatesPurlIndex() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>());
        ComponentList list = ComponentList.of(bom);

        assertFalse(list.containsPurl("pkg:maven/g/a@1.0"));

        Component comp = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        list.add(comp);

        assertTrue(list.containsPurl("pkg:maven/g/a@1.0"));
        assertSame(comp, list.findByPurl("pkg:maven/g/a@1.0"));
    }

    @Test
    void addUpdatesBomRefIndex() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>());
        ComponentList list = ComponentList.of(bom);

        assertFalse(list.containsBomRef("ref-a"));

        Component comp = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        list.add(comp);

        assertTrue(list.containsBomRef("ref-a"));
        assertSame(comp, list.findByBomRef("ref-a"));
    }

    @Test
    void removeUpdatesIndex() {
        Component comp = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(comp)));
        ComponentList list = ComponentList.of(bom);

        assertTrue(list.containsPurl("pkg:maven/g/a@1.0"));

        list.remove(comp);

        assertFalse(list.containsPurl("pkg:maven/g/a@1.0"));
        assertFalse(list.containsBomRef("ref-a"));
        assertTrue(list.isEmpty());
    }

    @Test
    void removeIfReturnsRemovedAndInvalidatesIndex() {
        Component a = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        Component b = createComp("b", "ref-b", "pkg:maven/g/b@1.0");
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(a, b)));
        ComponentList list = ComponentList.of(bom);

        assertTrue(list.containsPurl("pkg:maven/g/a@1.0"));

        List<Component> removed = list.removeIf(
                c -> "a".equals(c.getName()));

        assertEquals(1, removed.size());
        assertSame(a, removed.get(0));
        assertEquals(1, list.size());

        assertFalse(list.containsPurl("pkg:maven/g/a@1.0"),
                "index should be rebuilt and not contain removed component");
        assertTrue(list.containsPurl("pkg:maven/g/b@1.0"));
    }

    @Test
    void multipleSequentialMutations() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>());
        ComponentList list = ComponentList.of(bom);

        Component a = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        Component b = createComp("b", "ref-b", "pkg:maven/g/b@1.0");
        Component c = createComp("c", "ref-c", "pkg:maven/g/c@1.0");

        list.add(a);
        list.add(b);
        list.add(c);
        assertEquals(3, list.size());
        assertTrue(list.containsPurl("pkg:maven/g/b@1.0"));

        list.remove(b);
        assertEquals(2, list.size());
        assertFalse(list.containsPurl("pkg:maven/g/b@1.0"));
        assertTrue(list.containsPurl("pkg:maven/g/a@1.0"));
        assertTrue(list.containsPurl("pkg:maven/g/c@1.0"));
    }

    @Test
    void sortedReturnsCopyPreservingOriginal() {
        Component b = createComp("b", "ref-b", "pkg:maven/g/b@1.0");
        Component a = createComp("a", "ref-a", "pkg:maven/g/a@1.0");
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(List.of(b, a)));
        ComponentList list = ComponentList.of(bom);

        List<Component> sorted = list.sorted(Comparator.comparing(Component::getName));

        assertEquals("a", sorted.get(0).getName());
        assertEquals("b", sorted.get(1).getName());
        assertEquals("b", bom.getComponents().get(0).getName(),
                "original list should not be modified by sorted()");
    }

    @Test
    void isEmptyAndSize() {
        Bom bom = new Bom();
        ComponentList list = ComponentList.of(bom);

        assertTrue(list.isEmpty());
        assertEquals(0, list.size());

        list.add(createComp("a", "ref-a", "pkg:maven/g/a@1.0"));
        assertFalse(list.isEmpty());
        assertEquals(1, list.size());
    }

    private static Component createComp(String name, String bomRef, String purl) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(bomRef);
        comp.setPurl(purl);
        return comp;
    }
}
