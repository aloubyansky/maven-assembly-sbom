package dev.cyberstamp.maven.assembly.sbom;

import java.util.function.Function;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;

/**
 * Merges embedded (discovered) SBOMs into the assembly BOM according to the
 * configured mode ("ignore" | "link" | merge). Extracted verbatim from
 * SbomGenerator.processDiscoveredSboms so the merge policy lives in one
 * transform; SbomGenerator delegates to it with no behavior change.
 */
final class EmbeddedSbomMergeTransform {

    private final String mode;
    private final ArchiveIndex archiveIndex;

    EmbeddedSbomMergeTransform(String mode, ArchiveIndex archiveIndex) {
        this.mode = mode;
        this.archiveIndex = archiveIndex;
    }

    /**
     * Applies embedded SBOM merge to the target BOM.
     *
     * @param bom the target BOM to merge into
     * @param model the assembly components model containing discovered SBOMs
     * @param parentRefResolver resolves a {@link DiscoveredSbom#owner()} id
     *        (possibly {@code null}) to the bom-ref of the component to merge
     *        under, e.g. from {@link RenderedBom#bomRefs()}
     */
    void apply(Bom bom, AssemblyComponents model,
            Function<ComponentId, String> parentRefResolver) {
        if ("ignore".equalsIgnoreCase(mode)) {
            return;
        }
        for (DiscoveredSbom detected : model.discoveredSboms()) {
            String parentRef = parentRefResolver.apply(detected.owner());
            if ("link".equalsIgnoreCase(mode)) {
                BomMerger.addBomReference(bom, parentRef, detected.archivePath());
            } else {
                // The SBOM describes the copy it was found in; without one it
                // describes the assembly. The layout drops what does not ship.
                Component parent = BomMerger.findComponentByBomRef(bom, parentRef);
                if (parent == null) {
                    parent = bom.getMetadata().getComponent();
                }
                AnchoredMerge.merge(bom, detected.parsedBom(), AnchoredMerge.Scope.of(parent, archiveIndex));
            }
        }
    }
}
