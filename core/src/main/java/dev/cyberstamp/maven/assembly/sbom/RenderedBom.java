package dev.cyberstamp.maven.assembly.sbom;

import java.util.Map;

import org.cyclonedx.model.Bom;

/**
 * A rendered BOM together with the bom-ref each model component copy was
 * given.
 *
 * <p>
 * Steps that run after rendering (merging an embedded SBOM under the copy it
 * was found in, for instance) address a specific copy through this map
 * instead of looking a component up by purl, which is ambiguous when an
 * artifact ships more than once.
 * </p>
 *
 * @param bom the rendered BOM
 * @param bomRefs the bom-ref of every rendered copy, by its
 *        {@link AssemblyComponent#id() id}; top-level copies of one purl merged
 *        into a single component all map to that component's bom-ref
 */
record RenderedBom(Bom bom, Map<ComponentId, String> bomRefs) {
}
