package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The root of the neutral SBOM component model: the accumulated set of
 * components, dependency edges, and detected embedded SBOMs for a single
 * assembly, plus assembly metadata and optional product metadata.
 *
 * <p>
 * Both discovery front-ends — hash-based archive analysis and event-driven
 * provisioning — populate an instance of this class, which a single
 * renderer then turns into a CycloneDX BOM. It carries no Maven or Aether
 * types.
 * </p>
 *
 * <h2>Transform Pipeline</h2>
 * <p>
 * The neutral model sits at the center of the SBOM generation pipeline:
 * {@code ArchiveAnalyzer.analyze} or event-driven provisioning builds an
 * {@code AssemblyComponents} instance (the neutral model), which is then
 * enriched with license data, passed to {@code BomRenderer} to produce a
 * CycloneDX BOM, and finally merged with discovered embedded SBOMs via
 * {@code EmbeddedSbomMergeTransform}. The confinement rule ensures this
 * model remains free of cyclonedx, maven-model, and aether types; only
 * the merge and render layers handle CycloneDX-specific structures.
 * </p>
 */
public final class AssemblyComponents {

    private final List<AssemblyComponent> components = new ArrayList<>();
    private final List<DependencyEdge> dependencyEdges = new ArrayList<>();
    private final List<DiscoveredSbom> discoveredSboms = new ArrayList<>();
    private AssemblyMetadata metadata = new AssemblyMetadata();

    /**
     * Adds a top-level component.
     *
     * @param component the component to add
     */
    public void addComponent(AssemblyComponent component) {
        components.add(component);
    }

    /**
     * Replaces all top-level components with the given list.
     *
     * @param replacement the new component list
     */
    void setComponents(List<AssemblyComponent> replacement) {
        components.clear();
        components.addAll(replacement);
    }

    /**
     * @return an unmodifiable view of the top-level components
     */
    public List<AssemblyComponent> components() {
        return Collections.unmodifiableList(components);
    }

    /**
     * Adds a dependency edge.
     *
     * @param edge the edge to add
     */
    public void addDependencyEdge(DependencyEdge edge) {
        dependencyEdges.add(edge);
    }

    /**
     * @return an unmodifiable view of the dependency edges
     */
    public List<DependencyEdge> dependencyEdges() {
        return Collections.unmodifiableList(dependencyEdges);
    }

    /**
     * Adds a discovered embedded SBOM to be merged.
     *
     * @param sbom the discovered SBOM
     */
    public void addDiscoveredSbom(DiscoveredSbom sbom) {
        discoveredSboms.add(sbom);
    }

    /**
     * @return an unmodifiable view of the discovered embedded SBOMs
     */
    public List<DiscoveredSbom> discoveredSboms() {
        return Collections.unmodifiableList(discoveredSboms);
    }

    /**
     * Returns the assembly-level metadata that feeds the BOM renderer.
     *
     * @return the metadata; never {@code null}
     */
    public AssemblyMetadata metadata() {
        return metadata;
    }

    /**
     * Replaces the assembly metadata.
     *
     * @param metadata the new metadata
     * @throws NullPointerException if {@code metadata} is {@code null}
     */
    public void setMetadata(AssemblyMetadata metadata) {
        if (metadata == null) {
            throw new NullPointerException("metadata cannot be null");
        }
        this.metadata = metadata;
    }

    /**
     * Sets the product metadata for the assembly's main component.
     * Delegates to the assembly metadata.
     *
     * @param product the product metadata, or {@code null}
     */
    public void setProduct(ProductInfo product) {
        metadata.setProduct(product);
    }

    /**
     * Returns the product metadata for the assembly's main component.
     * Delegates to the assembly metadata.
     *
     * @return the product metadata, or {@code null} if unset
     */
    public ProductInfo product() {
        return metadata.getProduct();
    }
}
