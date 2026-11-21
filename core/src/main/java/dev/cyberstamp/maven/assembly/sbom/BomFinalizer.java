package dev.cyberstamp.maven.assembly.sbom;

import java.util.Comparator;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;

/**
 * Final steps on a rendered BOM, after anything merged into it: sorts the
 * dependency entries. Bom-refs need no repair here: the renderer gives every
 * component copy a unique one, and a merge gives every component it adds a
 * unique one too.
 */
final class BomFinalizer {

    private BomFinalizer() {
    }

    /**
     * Sorts the dependency entries, and each entry's children, by ref. The
     * renderer emits them sorted, but merging SBOMs and making bom-refs unique
     * append entries and children afterwards.
     */
    static void sortDependencies(Bom bom) {
        if (bom.getDependencies() == null) {
            return;
        }
        Comparator<Dependency> byRef = Comparator.comparing(Dependency::getRef,
                Comparator.nullsFirst(Comparator.naturalOrder()));
        bom.getDependencies().sort(byRef);
        for (Dependency dep : bom.getDependencies()) {
            if (dep.getDependencies() != null) {
                dep.getDependencies().sort(byRef);
            }
        }
    }

}
