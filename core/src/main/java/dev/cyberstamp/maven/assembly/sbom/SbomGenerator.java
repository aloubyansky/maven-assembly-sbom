package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatcher;

/**
 * Reusable SBOM generation pipeline that analyzes file entries,
 * identifies Maven artifacts, builds a CycloneDX BOM, and merges
 * detected and external SBOMs.
 *
 * <p>
 * Used by both the {@code SbomContainerDescriptorHandler} (assembly plugin)
 * and the {@code generate} Maven goal (standalone directory scan).
 * </p>
 */
public class SbomGenerator {

    private static final Logger log = LoggerFactory.getLogger(SbomGenerator.class);

    private final MavenProject project;
    private final MavenSession session;
    private final RepositorySystem repoSystem;
    private final EffectiveModelResolver effectiveModelResolver;
    private final MessageDigest messageDigest;
    private final Hash.Algorithm bomHashAlgorithm;
    private final boolean failOnDuplicateHash;
    private final boolean failOnMissingLicense;
    private final String embeddedSboms;
    private final boolean librariesOnly;
    private final Version schemaVersion;

    private ProductInfo product;
    private boolean identityEvidence = true;
    private MavenArtifactMatcher mavenArtifactMatcher;
    private LicenseEnrichment licenseEnrichment;
    private List<org.eclipse.aether.graph.Dependency> cachedManagedDeps;
    private ArchiveAnalyzer lastAnalyzer;

    SbomGenerator(MavenProject project, MavenSession session,
            RepositorySystem repoSystem,
            EffectiveModelResolver effectiveModelResolver,
            MessageDigest messageDigest, Hash.Algorithm bomHashAlgorithm,
            boolean failOnDuplicateHash, boolean failOnMissingLicense,
            String embeddedSboms, boolean librariesOnly, String schemaVersion) {
        this.project = project;
        this.session = session;
        this.repoSystem = repoSystem;
        this.effectiveModelResolver = effectiveModelResolver;
        this.messageDigest = messageDigest;
        this.bomHashAlgorithm = bomHashAlgorithm;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.failOnMissingLicense = failOnMissingLicense;
        this.embeddedSboms = embeddedSboms;
        this.librariesOnly = librariesOnly;
        this.schemaVersion = SchemaVersions.resolve(schemaVersion);
    }

    /**
     * Returns the resolved CycloneDX schema version.
     */
    Version getSchemaVersion() {
        return schemaVersion;
    }

    /**
     * Sets user-configurable metadata for the main BOM component.
     */
    void setProduct(ProductInfo product) {
        this.product = product;
    }

    /**
     * Sets whether this tool emits identity evidence for the components it
     * identifies. Identity from external or embedded SBOMs is unaffected.
     */
    void setIdentityEvidence(boolean identityEvidence) {
        this.identityEvidence = identityEvidence;
    }

    /**
     * Sets the matcher used to identify otherwise-unmatched (e.g.
     * non-Maven-built) archive entries.
     *
     * @param mavenArtifactMatcher the matcher, or {@code null} to disable
     */
    void setMavenArtifactMatcher(MavenArtifactMatcher mavenArtifactMatcher) {
        this.mavenArtifactMatcher = mavenArtifactMatcher;
    }

    /**
     * Analyzes file entries, builds a CycloneDX BOM, and merges
     * detected and external SBOMs.
     *
     * @param entries the file entries to analyze
     * @param baseDirPrefix prefix to strip from entry paths, or {@code null}
     * @param externalBoms external SBOMs to merge as top-level components
     * @param classifier the Maven classifier, or {@code null}
     * @param archiveType the archive type for the main component PURL, or {@code null}
     * @return the assembled BOM
     */
    Bom generate(List<FileEntry> entries, String baseDirPrefix,
            List<Bom> externalBoms, String assemblyId, String classifier,
            String archiveType) {
        effectiveModelResolver.init(
                session.getRepositorySession(),
                project.getRemoteProjectRepositories(),
                session.getProjects());
        licenseEnrichment = new LicenseEnrichment(
                new EffectiveModelLicenseSource(effectiveModelResolver), failOnMissingLicense);
        cachedManagedDeps = null;

        AssemblyComponents model = analyzeEntries(entries, baseDirPrefix, externalBoms);

        // Populate AssemblyMetadata
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId(project.getGroupId());
        metadata.setProjectArtifactId(project.getArtifactId());
        metadata.setProjectVersion(project.getVersion());
        metadata.setAssemblyId(assemblyId);
        metadata.setTimestamp(SbomUtils.parseBuildTimestamp(getTimestamp()));
        metadata.setHashAlgorithmSpec(bomHashAlgorithm.getSpec());
        metadata.setClassifier(classifier);
        metadata.setArchiveType(archiveType);
        metadata.setProjectLicenses(licenseEnrichment.resolve(
                project.getGroupId(), project.getArtifactId(), project.getVersion()));
        metadata.setProduct(product);
        populateToolMetadata(metadata);
        model.setMetadata(metadata);

        // Build the dependency graph, then enrich + render through the shared
        // pipeline. No jar locator is supplied: the analyzer already performed
        // shaded detection, so only license enrichment runs here.
        buildDependencyGraph(model);
        SbomPipeline.forModel(model)
                .licenseSource(new EffectiveModelLicenseSource(effectiveModelResolver))
                .failOnMissingLicense(failOnMissingLicense)
                .identityEvidence(identityEvidence)
                .enrich();
        RenderedBom rendered = new BomRenderer().renderWithRefs(model);
        Bom bom = rendered.bom();

        // Post-processing (detected/external SBOMs, filtering, dedup)
        ArchiveIndex archiveIndex = ArchiveIndex.of(entries, baseDirPrefix, bomHashAlgorithm.getSpec());
        processDiscoveredSboms(rendered, model, archiveIndex);
        processExternalBoms(bom, externalBoms, archiveIndex);

        if (librariesOnly) {
            removeFileComponents(bom);
        }
        // Every copy got a unique bom-ref from the renderer or the merge.
        BomFinalizer.sortDependencies(bom);
        return bom;
    }

    private AssemblyComponents analyzeEntries(List<FileEntry> entries,
            String baseDirPrefix, List<Bom> externalBoms) {
        boolean detectEmbeddedSboms = !"ignore".equalsIgnoreCase(embeddedSboms);
        lastAnalyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem,
                project, session, messageDigest, failOnDuplicateHash,
                externalBoms, detectEmbeddedSboms, mavenArtifactMatcher);
        lastAnalyzer.setIdentityEvidence(identityEvidence);
        return lastAnalyzer.analyze(entries, baseDirPrefix);
    }

    /**
     * Merges or links the SBOMs found inside the scanned archives, each under
     * the component copy it describes.
     *
     * @param rendered the rendered BOM, with the bom-ref of every model copy
     * @param model the analyzed components, carrying the discovered SBOMs
     * @param archiveIndex the scanned layout the merged components are checked against
     */
    private void processDiscoveredSboms(RenderedBom rendered, AssemblyComponents model, ArchiveIndex archiveIndex) {
        EmbeddedSbomMergeTransform transform = new EmbeddedSbomMergeTransform(
                embeddedSboms, archiveIndex);
        transform.apply(rendered.bom(), model, owner -> resolveParentBomRef(owner, rendered));
    }

    /**
     * Merges the configured external SBOMs into the BOM as descriptions of
     * the whole distribution. Components the analyzer rejected are dropped,
     * and those it found in the layout are kept where it found them.
     *
     * @param bom the BOM to merge into
     * @param externalBomList the external SBOMs, possibly empty
     * @param archiveIndex the scanned layout the merged components are checked against
     */
    private void processExternalBoms(Bom bom, List<Bom> externalBomList, ArchiveIndex archiveIndex) {
        if (externalBomList.isEmpty()) {
            return;
        }
        Set<Component> rejected = lastAnalyzer.rejectedExternalComponents();
        Set<Component> matched = lastAnalyzer.matchedExternalComponents();
        AnchoredMerge.Scope scope = new AnchoredMerge.Scope(bom.getMetadata().getComponent(), archiveIndex,
                rejected, matched);
        for (Bom externalBom : externalBomList) {
            AnchoredMerge.merge(bom, externalBom, scope);
        }
    }

    /**
     * Removes all {@link Component.Type#FILE FILE} components from the BOM
     * (top-level, main component sub-components, and nested) and cleans up
     * any dependency references that point to removed components. The main
     * component itself is never removed, even if its type is FILE.
     *
     * @param bom the BOM to modify in place
     */
    static void removeFileComponents(Bom bom) {
        Set<String> removedRefs = new HashSet<>();
        bom.setComponents(filterOutFileComponents(bom.getComponents(), removedRefs));
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            bom.getMetadata().getComponent().setComponents(
                    filterOutFileComponents(bom.getMetadata().getComponent().getComponents(), removedRefs));
        }
        if (!removedRefs.isEmpty()) {
            DependencyList deps = DependencyList.of(bom);
            deps.removeIf(d -> removedRefs.contains(d.getRef()));
            for (Dependency dep : deps) {
                removeFileRefs(dep, removedRefs);
            }
        }
    }

    private static List<Component> filterOutFileComponents(List<Component> components,
            Set<String> removedRefs) {
        if (components == null) {
            return null;
        }
        List<Component> result = new ArrayList<>();
        for (Component comp : components) {
            if (comp.getType() == Component.Type.FILE) {
                if (comp.getBomRef() != null) {
                    removedRefs.add(comp.getBomRef());
                }
            } else {
                comp.setComponents(filterOutFileComponents(comp.getComponents(), removedRefs));
                result.add(comp);
            }
        }
        return result;
    }

    /**
     * Recursively removes child dependency references whose ref is contained
     * in {@code removedRefs}.
     *
     * @param dep the dependency whose children are filtered
     * @param removedRefs the set of bomRefs to remove
     */
    private static void removeFileRefs(Dependency dep, Set<String> removedRefs) {
        DependencyList children = DependencyList.ofChildren(dep);
        if (children.isEmpty()) {
            return;
        }
        children.removeByRefs(removedRefs);
        for (Dependency child : children) {
            removeFileRefs(child, removedRefs);
        }
    }

    /**
     * Resolves the bom-ref of the component a discovered SBOM is merged under:
     * the bom-ref the renderer gave the owner's copy, or the main component's
     * when the SBOM has no owner (it sits at the assembly root) or the owner
     * was not rendered.
     *
     * @param owner the id of the owner's copy, or {@code null}
     * @param rendered the rendered BOM and its bom-refs by component id
     * @return the parent bom-ref; never {@code null}
     */
    private static String resolveParentBomRef(ComponentId owner, RenderedBom rendered) {
        String ref = owner == null ? null : rendered.bomRefs().get(owner);
        return ref != null ? ref : rendered.bom().getMetadata().getComponent().getBomRef();
    }

    /**
     * Parses external SBOM files from a comma-separated path string,
     * resolving relative paths against the given base directory.
     *
     * @param externalSboms comma-separated SBOM file paths, or {@code null}
     * @param baseDir the base directory for relative path resolution, or {@code null}
     * @return the parsed BOMs (never {@code null})
     */
    public static List<Bom> parseExternalBoms(String externalSboms, Path baseDir) {
        if (externalSboms == null || externalSboms.isBlank()) {
            return List.of();
        }
        List<Bom> result = new ArrayList<>();
        for (String pathStr : externalSboms.split(",")) {
            pathStr = pathStr.trim();
            if (pathStr.isEmpty()) {
                continue;
            }
            Path bomPath = Path.of(pathStr);
            if (!bomPath.isAbsolute() && baseDir != null) {
                bomPath = baseDir.resolve(pathStr);
            }
            if (!Files.isRegularFile(bomPath)) {
                log.warn("External SBOM file not found: {}", bomPath);
                continue;
            }
            Bom bom = BomReader.readBom(bomPath.toFile());
            if (bom != null) {
                log.debug("Loaded external SBOM from {} ({} components)", bomPath,
                        bom.getComponents() != null ? bom.getComponents().size() : 0);
                result.add(bom);
            }
        }
        return result;
    }

    private String getTimestamp() {
        return project.getProperties() != null
                ? project.getProperties().getProperty("project.build.outputTimestamp")
                : null;
    }

    private void populateToolMetadata(AssemblyMetadata metadata) {
        metadata.setToolGroupId(ToolInfo.GROUP_ID);
        metadata.setToolArtifactId(ToolInfo.ARTIFACT_ID);
        metadata.setToolVersion(ToolInfo.VERSION);
        try {
            metadata.setToolLicenses(licenseEnrichment.resolve(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION));
        } catch (Exception e) {
            log.debug("Could not resolve tool licenses for {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
        resolveToolHash(metadata);
    }

    private void resolveToolHash(AssemblyMetadata metadata) {
        try {
            DefaultArtifact toolArtifact = new DefaultArtifact(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, "jar", ToolInfo.VERSION);
            ArtifactRequest request = new ArtifactRequest(
                    toolArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File jarFile = result.getArtifact().getFile();
            if (jarFile != null && jarFile.isFile()) {
                metadata.setToolHash(SbomUtils.computeHash(messageDigest, jarFile.toPath()));
            }
        } catch (Exception e) {
            log.debug("Could not resolve tool artifact {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
    }

    /**
     * Adds the module's dependency edges to the model.
     *
     * <p>
     * The module's own Maven resolution is the only one run: it uses the POM
     * of the build being run, so it reflects build time by definition.
     * Unpacked WARs and overlays are not resolved, since a published POM may
     * differ from the one their build used. Each collected artifact edge
     * {@code a -> b} is bound to the module's copies of {@code a} and
     * {@code b} (see {@link ArchiveAnalyzer#moduleCopies()}); an edge with an
     * end the module does not ship is dropped.
     * </p>
     *
     * <p>
     * When the resolution fails (e.g. offline, or a descriptor cannot be
     * read), a warning is logged, no edges are added, and the module's copies
     * are marked as having unknown dependencies, so they are not rendered as
     * having none.
     * </p>
     */
    private void buildDependencyGraph(AssemblyComponents model) {
        Map<ArtifactCoords, ComponentId> copies = lastAnalyzer.moduleCopies();
        if (copies.isEmpty()) {
            return;
        }
        Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges;
        try {
            collectedEdges = collectDependencyEdges();
        } catch (Exception e) {
            log.warn("Failed to build dependency graph,"
                    + " SBOM will omit dependency information", e);
            markDependenciesUnknown(model, copies.keySet());
            return;
        }
        for (Map.Entry<ArtifactCoords, Set<ArtifactCoords>> entry : collectedEdges.entrySet()) {
            ComponentId parent = copies.get(entry.getKey());
            if (parent == null) {
                continue;
            }
            for (ArtifactCoords childCoords : entry.getValue()) {
                ComponentId child = copies.get(childCoords);
                if (child != null && !child.equals(parent)) {
                    model.addDependencyEdge(new DependencyEdge(parent, child));
                }
            }
        }
    }

    /**
     * Marks every top-level copy of the given artifacts as having unknown
     * dependencies: the copy the module's edges would have been bound to and
     * any further top-level copy of the same artifact, which the renderer
     * merges with it.
     *
     * @param model the model whose top-level components to update
     * @param artifacts the coordinates of the module's artifacts
     */
    private static void markDependenciesUnknown(AssemblyComponents model, Set<ArtifactCoords> artifacts) {
        List<AssemblyComponent> components = new ArrayList<>(model.components());
        for (int i = 0; i < components.size(); i++) {
            if (components.get(i) instanceof PackageComponent pkg && pkg.dependenciesKnown()
                    && pkg.ref() instanceof ArtifactCoords coords && artifacts.contains(coords)) {
                components.set(i, pkg.withDependenciesKnown(false));
            }
        }
        model.setComponents(components);
    }

    /**
     * Collects the module's artifact-level dependency edges by running one
     * collect request over the project's dependencies, with its dependency
     * management, recording every parent-child pair the resolver visits.
     *
     * @return the collected edges, by parent coordinates
     * @throws Exception if the resolution fails
     */
    private Map<ArtifactCoords, Set<ArtifactCoords>> collectDependencyEdges() throws Exception {
        Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = new ConcurrentHashMap<>();

        DefaultRepositorySystemSession mutableSession = new DefaultRepositorySystemSession(session.getRepositorySession());
        mutableSession.setDependencySelector(new EdgeCollectorSelectorFactory(
                session.getRepositorySession().getDependencySelector(), collectedEdges));

        CollectRequest request = buildCollectRequest(
                toAetherDependencies(project.getDependencies()), collectManagedDependencies());
        repoSystem.collectDependencies(mutableSession, request);
        return collectedEdges;
    }

    private List<org.eclipse.aether.graph.Dependency> collectManagedDependencies() {
        if (cachedManagedDeps != null) {
            return cachedManagedDeps;
        }
        List<org.eclipse.aether.graph.Dependency> managedDeps;
        if (project.getDependencyManagement() != null
                && project.getDependencyManagement().getDependencies() != null) {
            managedDeps = toAetherDependencies(
                    project.getDependencyManagement().getDependencies());
        } else {
            managedDeps = List.of();
        }
        cachedManagedDeps = managedDeps;
        return managedDeps;
    }

    private List<org.eclipse.aether.graph.Dependency> toAetherDependencies(
            List<org.apache.maven.model.Dependency> deps) {
        List<org.eclipse.aether.graph.Dependency> result = new ArrayList<>(deps.size());
        for (org.apache.maven.model.Dependency dep : deps) {
            result.add(toAetherDependency(dep));
        }
        return result;
    }

    private static org.eclipse.aether.graph.Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        return new org.eclipse.aether.graph.Dependency(
                SbomUtils.toAetherArtifact(dep.getGroupId(), dep.getArtifactId(),
                        dep.getVersion(), dep.getType(), dep.getClassifier()),
                dep.getScope());
    }

    private CollectRequest buildCollectRequest(List<org.eclipse.aether.graph.Dependency> deps,
            List<org.eclipse.aether.graph.Dependency> managedDeps) {
        CollectRequest request = new CollectRequest();
        request.setDependencies(deps);
        request.setManagedDependencies(managedDeps);
        request.setRepositories(project.getRemoteProjectRepositories());
        return request;
    }
}
