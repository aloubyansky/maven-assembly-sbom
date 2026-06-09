package io.github.aloubyansky.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Merges or links external CycloneDX SBOMs into a distribution SBOM.
 *
 * <p>
 * This utility supports two integration modes:
 * </p>
 * <ul>
 * <li><b>Merge</b> — imports the source BOM's components as nested
 * sub-components of a parent component in the target BOM, and
 * imports its dependency entries into the target's dependency
 * section. No cross-ecosystem dependency edges are created;
 * nesting already captures the containment relationship.</li>
 * <li><b>Link</b> — adds a CycloneDX {@code externalReference} of
 * type {@code bom} to the parent component, pointing to the
 * SBOM file's location within the archive.</li>
 * </ul>
 */
final class BomMerger {

    private static final Logger log = LoggerFactory.getLogger(BomMerger.class);

    private static final Comparator<Component> COMPONENT_ORDER = BomBuilder.COMPONENT_ORDER;

    private BomMerger() {
    }

    /**
     * Merges the source BOM's components as nested sub-components
     * under the specified parent component in the target BOM.
     *
     * <p>
     * Source components are sorted by group/name/version and appended
     * to the parent's existing nested component list (if any).
     * Dependency entries from the source BOM are imported into the
     * target BOM's top-level dependency section.
     * </p>
     *
     * <p>
     * If the parent component cannot be found, a warning is logged
     * and no changes are made.
     * </p>
     *
     * @param targetBom the distribution BOM to merge into
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param sourceBom the external BOM whose components to import
     */
    static void mergeUnder(Bom targetBom, String parentBomRef, Bom sourceBom) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            log.warn("Cannot merge SBOM: parent component with bom-ref '{}' not found",
                    parentBomRef);
            return;
        }
        nestComponents(parent, sourceBom.getComponents());
        importDependencies(targetBom, sourceBom.getDependencies());
    }

    /**
     * Adds a CycloneDX external reference of type {@code bom} to the
     * specified parent component, pointing to the given archive path.
     *
     * <p>
     * If the parent component cannot be found, a warning is logged
     * and no changes are made.
     * </p>
     *
     * @param targetBom the distribution BOM
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param bomPath the archive-internal path to the SBOM file
     */
    static void addBomReference(Bom targetBom, String parentBomRef, String bomPath) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            log.warn("Cannot add BOM reference: parent component with bom-ref '{}' not found",
                    parentBomRef);
            return;
        }
        ExternalReference ref = new ExternalReference();
        ref.setType(ExternalReference.Type.BOM);
        ref.setUrl(bomPath);
        parent.addExternalReference(ref);
    }

    /**
     * Sorts and appends components to the parent's nested component list.
     */
    private static void nestComponents(Component parent, List<Component> components) {
        if (components == null || components.isEmpty()) {
            return;
        }
        List<Component> sorted = new ArrayList<>(components);
        sorted.sort(COMPONENT_ORDER);
        for (Component comp : sorted) {
            parent.addComponent(comp);
        }
    }

    /**
     * Imports dependency entries into the target BOM's dependency section.
     */
    private static void importDependencies(Bom targetBom, List<Dependency> dependencies) {
        if (dependencies == null) {
            return;
        }
        for (Dependency dep : dependencies) {
            targetBom.addDependency(dep);
        }
    }

    /**
     * Searches for a component by {@code bom-ref} in the target BOM.
     *
     * <p>
     * Checks the metadata component first, then top-level components,
     * then recursively searches nested component trees.
     * </p>
     *
     * @param bom the BOM to search
     * @param bomRef the {@code bom-ref} to match
     * @return the matching component, or {@code null} if not found
     */
    static Component findComponentByBomRef(Bom bom, String bomRef) {
        if (bomRef == null) {
            return null;
        }
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component main = bom.getMetadata().getComponent();
            if (bomRef.equals(main.getBomRef())) {
                return main;
            }
        }
        return searchComponentTree(bom.getComponents(), bomRef);
    }

    /**
     * Recursively searches a list of components and their children
     * for a matching {@code bom-ref}.
     */
    private static Component searchComponentTree(List<Component> components, String bomRef) {
        if (components == null) {
            return null;
        }
        for (Component comp : components) {
            if (bomRef.equals(comp.getBomRef())) {
                return comp;
            }
            Component nested = searchComponentTree(comp.getComponents(), bomRef);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }
}
