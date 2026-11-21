package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.junit.jupiter.api.Test;

class BomFinalizerTest {

    @Test
    void sortDependenciesOrdersEntriesAndTheirChildrenByRef() {
        // entries cloned or imported after rendering are appended unsorted
        Bom bom = new Bom();
        Dependency b = new Dependency("ref-b");
        b.addDependency(new Dependency("ref-z"));
        b.addDependency(new Dependency("ref-a#2"));
        b.addDependency(new Dependency("ref-a"));
        bom.addDependency(b);
        bom.addDependency(new Dependency("ref-a#2"));
        bom.addDependency(new Dependency("ref-a"));

        BomFinalizer.sortDependencies(bom);

        assertEquals(List.of("ref-a", "ref-a#2", "ref-b"),
                bom.getDependencies().stream().map(Dependency::getRef).toList());
        assertEquals(List.of("ref-a", "ref-a#2", "ref-z"),
                bom.getDependencies().get(2).getDependencies().stream().map(Dependency::getRef).toList());
    }

    /** A library with the given name and bom-ref. */
    private static Component createLibrary(String name, String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(bomRef);
        return comp;
    }

}
