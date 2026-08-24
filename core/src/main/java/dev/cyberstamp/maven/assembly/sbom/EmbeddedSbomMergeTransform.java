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
     * @param parentRefResolver resolves a DiscoveredSbom owner PackageRef to a
     *        parent bom-ref (mirrors SbomGenerator.resolveParentBomRef)
     */
    void apply(Bom bom, AssemblyComponents model,
            Function<PackageRef, String> parentRefResolver) {
        if ("ignore".equalsIgnoreCase(mode)) {
            return;
        }
        for (DiscoveredSbom detected : model.discoveredSboms()) {
            String parentRef = parentRefResolver.apply(detected.owner());
            if ("link".equalsIgnoreCase(mode)) {
                BomMerger.addBomReference(bom, parentRef, detected.archivePath());
            } else {
                Component parent = BomMerger.findComponentByBomRef(bom, parentRef);
                String parentPrefix = parent != null
                        ? BomMerger.getParentPathPrefix(parent)
                        : null;
                Bom filtered = SbomGenerator.filterSbomByArchive(
                        detected.parsedBom(), archiveIndex, parentPrefix);
                if (parent != null) {
                    BomMerger.mergeUnder(bom, parentRef, filtered);
                } else {
                    BomMerger.mergeFlat(bom, filtered);
                }
            }
        }
    }
}
