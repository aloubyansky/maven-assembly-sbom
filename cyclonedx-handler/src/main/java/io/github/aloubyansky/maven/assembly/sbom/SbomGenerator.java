package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Hash;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reusable SBOM generation pipeline that analyzes file entries,
 * identifies Maven artifacts, builds a CycloneDX BOM, and merges
 * detected and external SBOMs.
 *
 * <p>
 * Used by both {@link SbomContainerDescriptorHandler} (assembly plugin)
 * and the {@code generate-sbom} Maven goal (standalone directory scan).
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
    private final String embeddedSbomHandling;

    private MavenLicenseResolver licenseResolver;
    private List<Dependency> cachedManagedDeps;

    SbomGenerator(MavenProject project, MavenSession session,
            RepositorySystem repoSystem,
            EffectiveModelResolver effectiveModelResolver,
            MessageDigest messageDigest, Hash.Algorithm bomHashAlgorithm,
            boolean failOnDuplicateHash, boolean failOnMissingLicense,
            String embeddedSbomHandling) {
        this.project = project;
        this.session = session;
        this.repoSystem = repoSystem;
        this.effectiveModelResolver = effectiveModelResolver;
        this.messageDigest = messageDigest;
        this.bomHashAlgorithm = bomHashAlgorithm;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.failOnMissingLicense = failOnMissingLicense;
        this.embeddedSbomHandling = embeddedSbomHandling;
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
    Bom generate(List<ArchiveContent.FileEntry> entries, String baseDirPrefix,
            List<Bom> externalBoms, String assemblyId, String classifier,
            String archiveType) {
        effectiveModelResolver.init(
                session.getRepositorySession(),
                project.getRemoteProjectRepositories(),
                session.getProjects());
        licenseResolver = new MavenLicenseResolver(
                effectiveModelResolver, failOnMissingLicense);
        cachedManagedDeps = null;

        ArchiveContent content = analyzeEntries(entries, baseDirPrefix, externalBoms);

        BomBuilder builder = new BomBuilder(
                project.getGroupId(), project.getArtifactId(),
                project.getVersion(), assemblyId,
                SbomUtils.parseBuildTimestamp(getTimestamp()), bomHashAlgorithm);
        builder.setProjectLicenses(licenseResolver.resolveLicenses(
                project.getGroupId(), project.getArtifactId(),
                project.getVersion()));
        builder.setClassifier(classifier);
        builder.setArchiveType(archiveType);
        populateToolMetadata(builder);

        addToBom(content, builder);

        Bom bom = builder.build();
        String normalizedAlg = normalizeAlgorithm(bomHashAlgorithm.getSpec());
        Set<String> archivePaths = collectArchivePaths(entries, baseDirPrefix);
        Set<String> archiveHashes = collectArchiveHashes(entries);
        processDetectedSboms(bom, content, builder,
                archivePaths, archiveHashes, normalizedAlg);
        processExternalBoms(bom, externalBoms,
                archivePaths, archiveHashes, normalizedAlg);

        replaceFileComponentsWithLibraries(bom, normalizedAlg);
        deduplicateBomRefs(bom);
        return bom;
    }

    private ArchiveContent analyzeEntries(List<ArchiveContent.FileEntry> entries,
            String baseDirPrefix, List<Bom> externalBoms) {
        boolean detectEmbeddedSboms = !"ignore".equalsIgnoreCase(embeddedSbomHandling);
        ArchiveAnalyzer analyzer = new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem,
                project, session, messageDigest, failOnDuplicateHash,
                externalBoms, detectEmbeddedSboms);
        return analyzer.analyze(entries, baseDirPrefix);
    }

    private void addToBom(ArchiveContent content, BomBuilder builder) {
        for (var e : content.mavenEntries()) {
            ArtifactCoords id = e.artifactId();
            builder.addMavenArtifact(id, e.archivePath(), e.hash(),
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        for (var e : content.nestedEntries()) {
            ArtifactCoords id = e.artifactId();
            builder.addNestedMavenArtifact(e.parentId(), id, e.archivePath(), e.hash(),
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        for (var edge : content.explicitDependencies()) {
            builder.addExplicitDependency(edge.parent(), edge.child());
        }
        for (var e : content.unmatchedFiles()) {
            builder.addFile(e.path(), e.hash());
        }
        for (var e : content.fileNestedArtifacts()) {
            ArtifactCoords id = e.artifactId();
            builder.addNestedArtifactUnderFile(e.filePath(), id,
                    licenseResolver.resolveLicenses(
                            id.groupId(), id.artifactId(), id.version()));
        }
        buildDependencyGraph(builder, content);
    }

    private void processDetectedSboms(Bom bom, ArchiveContent content,
            BomBuilder builder, Set<String> archivePaths,
            Set<String> archiveHashes, String normalizedAlg) {
        if ("ignore".equalsIgnoreCase(embeddedSbomHandling)) {
            return;
        }
        for (ArchiveContent.DetectedSbom detected : content.detectedSboms()) {
            String parentRef = resolveParentBomRef(detected.parentArtifact(),
                    bom, builder);
            if ("link".equalsIgnoreCase(embeddedSbomHandling)) {
                BomMerger.addBomReference(bom, parentRef, detected.archivePath());
            } else {
                org.cyclonedx.model.Component parent = BomMerger.findComponentByBomRef(
                        bom, parentRef);
                String parentPrefix = parent != null
                        ? BomMerger.getParentPathPrefix(parent)
                        : null;
                Bom filtered = filterSbomByArchive(detected.parsedBom(),
                        archivePaths, archiveHashes, normalizedAlg, parentPrefix);
                if (parent != null) {
                    BomMerger.mergeUnder(bom, parentRef, filtered);
                } else {
                    BomMerger.mergeFlat(bom, filtered);
                }
            }
        }
    }

    private static Set<String> collectArchivePaths(
            List<ArchiveContent.FileEntry> entries, String baseDirPrefix) {
        Set<String> paths = new HashSet<>(entries.size());
        for (var e : entries) {
            String path = e.path();
            if (baseDirPrefix != null && path.startsWith(baseDirPrefix)) {
                path = path.substring(baseDirPrefix.length());
            }
            paths.add(path);
        }
        return paths;
    }

    private static Set<String> collectArchiveHashes(
            List<ArchiveContent.FileEntry> entries) {
        Set<String> hashes = new HashSet<>(entries.size());
        for (var e : entries) {
            if (e.hash() != null) {
                hashes.add(e.hash());
            }
        }
        return hashes;
    }

    private static Bom filterSbomByArchive(Bom sbom, Set<String> archivePaths,
            Set<String> archiveHashes, String normalizedAlg,
            String parentPathPrefix) {
        if (sbom.getComponents() == null) {
            return sbom;
        }
        Set<String> survivingRefs = new HashSet<>();
        List<org.cyclonedx.model.Component> filtered = new ArrayList<>();
        for (org.cyclonedx.model.Component comp : sbom.getComponents()) {
            if (matchesArchive(comp, archivePaths, archiveHashes,
                    normalizedAlg, parentPathPrefix)) {
                filtered.add(comp);
                collectBomRefs(comp, survivingRefs);
            } else {
                log.debug("Filtering out component {} from SBOM:"
                        + " no matching file in archive", comp.getPurl());
            }
        }
        Bom result = new Bom();
        result.setComponents(filtered);
        if (sbom.getDependencies() != null) {
            List<org.cyclonedx.model.Dependency> filteredDeps = new ArrayList<>();
            for (org.cyclonedx.model.Dependency dep : sbom.getDependencies()) {
                if (survivingRefs.contains(dep.getRef())) {
                    org.cyclonedx.model.Dependency pruned = filterDependencyChildren(
                            dep, survivingRefs);
                    filteredDeps.add(pruned);
                }
            }
            if (!filteredDeps.isEmpty()) {
                result.setDependencies(filteredDeps);
            }
        }
        return result;
    }

    private static org.cyclonedx.model.Dependency filterDependencyChildren(
            org.cyclonedx.model.Dependency dep, Set<String> survivingRefs) {
        if (dep.getDependencies() == null || dep.getDependencies().isEmpty()) {
            return dep;
        }
        org.cyclonedx.model.Dependency result = new org.cyclonedx.model.Dependency(
                dep.getRef());
        for (org.cyclonedx.model.Dependency child : dep.getDependencies()) {
            if (survivingRefs.contains(child.getRef())) {
                result.addDependency(new org.cyclonedx.model.Dependency(child.getRef()));
            }
        }
        return result;
    }

    private static void collectBomRefs(org.cyclonedx.model.Component comp,
            Set<String> refs) {
        if (comp.getBomRef() != null) {
            refs.add(comp.getBomRef());
        }
        if (comp.getComponents() != null) {
            for (org.cyclonedx.model.Component child : comp.getComponents()) {
                collectBomRefs(child, refs);
            }
        }
    }

    /**
     * Checks whether a component from an external/embedded SBOM corresponds
     * to a file actually present in the archive. A component matches if:
     * <ul>
     * <li>It has an occurrence whose path (prefixed with the parent's
     * archive path when applicable) exists as an archive entry, OR</li>
     * <li>It has no occurrences and its hash matches an archive file
     * (hash-only fallback), OR</li>
     * <li>It has no hash with a comparable algorithm (can't verify).</li>
     * </ul>
     */
    private static boolean matchesArchive(org.cyclonedx.model.Component comp,
            Set<String> archivePaths, Set<String> archiveHashes,
            String normalizedAlg, String parentPathPrefix) {
        if (hasMatchingOccurrence(comp, archivePaths, parentPathPrefix)) {
            return true;
        }
        if (hasEmptyOccurrence(comp, parentPathPrefix)) {
            return true;
        }
        if (BomMerger.hasOccurrences(comp)) {
            if (isNpmComponent(comp)) {
                return true;
            }
            return false;
        }
        // no occurrences — fall back to hash check
        if (comp.getHashes() == null || comp.getHashes().isEmpty()) {
            return true;
        }
        return hasMatchingHash(comp, archiveHashes, normalizedAlg)
                || !hasVerifiableHash(comp, normalizedAlg);
    }

    private static boolean hasMatchingHash(org.cyclonedx.model.Component comp,
            Set<String> archiveHashes, String normalizedAlg) {
        if (comp.getHashes() == null) {
            return false;
        }
        for (org.cyclonedx.model.Hash h : comp.getHashes()) {
            if (normalizedAlg.equals(normalizeAlgorithm(h.getAlgorithm()))
                    && archiveHashes.contains(h.getValue())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasVerifiableHash(org.cyclonedx.model.Component comp,
            String normalizedAlg) {
        if (comp.getHashes() == null) {
            return false;
        }
        for (org.cyclonedx.model.Hash h : comp.getHashes()) {
            if (normalizedAlg.equals(normalizeAlgorithm(h.getAlgorithm()))) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMatchingOccurrence(org.cyclonedx.model.Component comp,
            Set<String> archivePaths, String parentPathPrefix) {
        org.cyclonedx.model.Evidence evidence = comp.getEvidence();
        if (evidence == null || evidence.getOccurrences() == null) {
            return false;
        }
        for (org.cyclonedx.model.component.evidence.Occurrence occ : evidence.getOccurrences()) {
            String location = occ.getLocation();
            if (location == null || location.isEmpty()) {
                continue;
            }
            String fullPath = parentPathPrefix != null
                    ? parentPathPrefix + location
                    : location;
            if (archivePaths.contains(fullPath)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasEmptyOccurrence(org.cyclonedx.model.Component comp,
            String parentPathPrefix) {
        if (parentPathPrefix == null
                || comp.getType() == org.cyclonedx.model.Component.Type.FILE) {
            return false;
        }
        org.cyclonedx.model.Evidence evidence = comp.getEvidence();
        if (evidence == null || evidence.getOccurrences() == null) {
            return false;
        }
        for (org.cyclonedx.model.component.evidence.Occurrence occ : evidence.getOccurrences()) {
            if ("".equals(occ.getLocation())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNpmComponent(org.cyclonedx.model.Component comp) {
        String purl = comp.getPurl();
        return purl != null && purl.startsWith("pkg:npm/");
    }

    private static String normalizeAlgorithm(String algorithm) {
        return algorithm.replace("-", "").toLowerCase();
    }

    private void processExternalBoms(Bom bom, List<Bom> externalBomList,
            Set<String> archivePaths, Set<String> archiveHashes,
            String normalizedAlg) {
        if (externalBomList.isEmpty()) {
            return;
        }
        for (Bom externalBom : externalBomList) {
            Bom filtered = filterSbomByArchive(externalBom,
                    archivePaths, archiveHashes, normalizedAlg, null);
            BomMerger.mergeFlat(bom, filtered);
        }
    }

    static void replaceFileComponentsWithLibraries(Bom bom, String normalizedAlg) {
        if (bom.getComponents() == null) {
            return;
        }
        Map<String, List<org.cyclonedx.model.Component>> filesByHash = new HashMap<>();
        for (org.cyclonedx.model.Component comp : bom.getComponents()) {
            if (comp.getBomRef() != null
                    && comp.getBomRef().startsWith("file:")
                    && comp.getHashes() != null) {
                for (Hash h : comp.getHashes()) {
                    if (normalizedAlg.equals(normalizeAlgorithm(h.getAlgorithm()))) {
                        filesByHash.computeIfAbsent(h.getValue(),
                                k -> new ArrayList<>()).add(comp);
                    }
                }
            }
        }
        if (filesByHash.isEmpty()) {
            return;
        }
        Map<String, String> fileToLibRef = new HashMap<>();
        for (org.cyclonedx.model.Component comp : bom.getComponents()) {
            if (comp.getType() != org.cyclonedx.model.Component.Type.LIBRARY
                    || comp.getHashes() == null) {
                continue;
            }
            for (Hash h : comp.getHashes()) {
                if (!normalizedAlg.equals(normalizeAlgorithm(h.getAlgorithm()))) {
                    continue;
                }
                List<org.cyclonedx.model.Component> fileComps = filesByHash.get(h.getValue());
                if (fileComps != null) {
                    for (org.cyclonedx.model.Component fileComp : fileComps) {
                        fileToLibRef.put(fileComp.getBomRef(), comp.getBomRef());
                    }
                }
            }
        }
        if (fileToLibRef.isEmpty()) {
            return;
        }
        bom.getComponents().removeIf(
                c -> fileToLibRef.containsKey(c.getBomRef()));
        if (bom.getDependencies() != null) {
            List<org.cyclonedx.model.Dependency> toRemove = new ArrayList<>();
            for (org.cyclonedx.model.Dependency dep : bom.getDependencies()) {
                String replacement = fileToLibRef.get(dep.getRef());
                if (replacement != null) {
                    toRemove.add(dep);
                } else {
                    replaceDependsOnRefs(dep, fileToLibRef);
                }
            }
            bom.getDependencies().removeAll(toRemove);
        }
    }

    private static void replaceDependsOnRefs(
            org.cyclonedx.model.Dependency dep,
            Map<String, String> refMap) {
        if (dep.getDependencies() == null) {
            return;
        }
        List<org.cyclonedx.model.Dependency> toAdd = new ArrayList<>();
        List<org.cyclonedx.model.Dependency> toRemove = new ArrayList<>();
        for (org.cyclonedx.model.Dependency child : dep.getDependencies()) {
            String replacement = refMap.get(child.getRef());
            if (replacement != null) {
                toRemove.add(child);
                boolean alreadyPresent = dep.getDependencies().stream()
                        .anyMatch(d -> replacement.equals(d.getRef()));
                if (!alreadyPresent) {
                    toAdd.add(new org.cyclonedx.model.Dependency(replacement));
                }
            }
            replaceDependsOnRefs(child, refMap);
        }
        dep.getDependencies().removeAll(toRemove);
        for (org.cyclonedx.model.Dependency d : toAdd) {
            dep.addDependency(d);
        }
    }

    private static void deduplicateBomRefs(Bom bom) {
        Map<String, org.cyclonedx.model.Component> seen = new HashMap<>();
        Map<String, String> renames = new HashMap<>();
        if (bom.getComponents() != null) {
            deduplicateBomRefs(bom.getComponents(), seen, renames);
        }
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null
                && bom.getMetadata().getComponent().getComponents() != null) {
            deduplicateBomRefs(
                    bom.getMetadata().getComponent().getComponents(), seen, renames);
        }
        if (!renames.isEmpty() && bom.getDependencies() != null) {
            Map<String, List<String>> originalToNew = new HashMap<>();
            for (Map.Entry<String, String> e : renames.entrySet()) {
                originalToNew.computeIfAbsent(e.getValue(),
                        k -> new ArrayList<>()).add(e.getKey());
            }
            List<org.cyclonedx.model.Dependency> toAdd = new ArrayList<>();
            for (org.cyclonedx.model.Dependency dep : bom.getDependencies()) {
                List<String> newRefs = originalToNew.get(dep.getRef());
                if (newRefs != null) {
                    for (String newRef : newRefs) {
                        org.cyclonedx.model.Dependency clone = new org.cyclonedx.model.Dependency(newRef);
                        if (dep.getDependencies() != null) {
                            for (org.cyclonedx.model.Dependency child : dep.getDependencies()) {
                                clone.addDependency(
                                        new org.cyclonedx.model.Dependency(
                                                child.getRef()));
                            }
                        }
                        toAdd.add(clone);
                    }
                }
            }
            bom.getDependencies().addAll(toAdd);
        }
    }

    private static void deduplicateBomRefs(
            List<org.cyclonedx.model.Component> components,
            Map<String, org.cyclonedx.model.Component> seen,
            Map<String, String> renames) {
        for (org.cyclonedx.model.Component comp : components) {
            String ref = comp.getBomRef();
            if (ref != null && seen.putIfAbsent(ref, comp) != null) {
                int suffix = 2;
                String unique = ref + "#" + suffix;
                while (seen.containsKey(unique)) {
                    unique = ref + "#" + ++suffix;
                }
                renames.put(unique, ref);
                comp.setBomRef(unique);
                seen.put(unique, comp);
            }
            if (comp.getComponents() != null) {
                deduplicateBomRefs(comp.getComponents(), seen, renames);
            }
        }
    }

    private String resolveParentBomRef(ArtifactCoords parentArtifact,
            Bom bom, BomBuilder builder) {
        if (parentArtifact != null) {
            String ref = builder.bomRefOf(parentArtifact);
            if (ref != null) {
                return ref;
            }
        }
        return bom.getMetadata().getComponent().getBomRef();
    }

    /**
     * Parses external SBOM files from a comma-separated path string,
     * resolving relative paths against the given base directory.
     *
     * @param mergeBoms comma-separated SBOM file paths, or {@code null}
     * @param baseDir the base directory for relative path resolution, or {@code null}
     * @return the parsed BOMs (never {@code null})
     */
    public static List<Bom> parseExternalBoms(String mergeBoms, Path baseDir) {
        if (mergeBoms == null || mergeBoms.isBlank()) {
            return List.of();
        }
        List<Bom> result = new ArrayList<>();
        for (String pathStr : mergeBoms.split(",")) {
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

    private void populateToolMetadata(BomBuilder builder) {
        try {
            builder.setToolLicenses(licenseResolver.resolveLicenses(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION));
        } catch (Exception e) {
            log.debug("Could not resolve tool licenses for {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
        resolveToolHash(builder);
    }

    private void resolveToolHash(BomBuilder builder) {
        try {
            org.eclipse.aether.artifact.DefaultArtifact toolArtifact = new org.eclipse.aether.artifact.DefaultArtifact(
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, "jar", ToolInfo.VERSION);
            ArtifactRequest request = new ArtifactRequest(
                    toolArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File jarFile = result.getArtifact().getFile();
            if (jarFile != null && jarFile.isFile()) {
                builder.setToolHash(SbomUtils.computeHash(messageDigest, jarFile.toPath()));
            }
        } catch (Exception e) {
            log.debug("Could not resolve tool artifact {}:{}:{}",
                    ToolInfo.GROUP_ID, ToolInfo.ARTIFACT_ID, ToolInfo.VERSION, e);
        }
    }

    private void buildDependencyGraph(BomBuilder builder, ArchiveContent content) {
        try {
            Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = collectDependencyEdges(content.nestedDepsByParent());
            Set<ArtifactCoords> knownIds = content.collectKnownArtifactCoords();
            Map<ArtifactCoords, List<ArtifactCoords>> graph = filterEdges(collectedEdges, knownIds);
            builder.setDependencyGraph(graph);
        } catch (Exception e) {
            log.warn("Failed to build dependency graph,"
                    + " SBOM will omit dependency information", e);
        }
    }

    private Map<ArtifactCoords, Set<ArtifactCoords>> collectDependencyEdges(
            Map<ArtifactCoords, List<Dependency>> nestedDepsByParent) throws Exception {
        Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges = new ConcurrentHashMap<>();

        DefaultRepositorySystemSession mutableSession = new DefaultRepositorySystemSession(session.getRepositorySession());
        mutableSession.setDependencySelector(new EdgeCollectorSelectorFactory(
                session.getRepositorySession().getDependencySelector(), collectedEdges));

        List<Dependency> projectManagedDeps = collectManagedDependencies();
        CollectRequest request = buildCollectRequest(
                toAetherDependencies(project.getDependencies()), projectManagedDeps);
        repoSystem.collectDependencies(mutableSession, request);

        for (Map.Entry<ArtifactCoords, List<Dependency>> entry : nestedDepsByParent.entrySet()) {
            List<Dependency> parentManagedDeps = resolveManagedDependencies(entry.getKey());
            CollectRequest nestedRequest = buildCollectRequest(entry.getValue(), parentManagedDeps);
            repoSystem.collectDependencies(mutableSession, nestedRequest);
        }

        return collectedEdges;
    }

    private List<Dependency> resolveManagedDependencies(ArtifactCoords coords) {
        Model model = effectiveModelResolver.resolveEffectiveModel(
                coords.groupId(), coords.artifactId(), coords.version());
        if (model == null || model.getDependencyManagement() == null
                || model.getDependencyManagement().getDependencies() == null) {
            return List.of();
        }
        return toAetherDependencies(model.getDependencyManagement().getDependencies());
    }

    private List<Dependency> collectManagedDependencies() {
        if (cachedManagedDeps != null) {
            return cachedManagedDeps;
        }
        List<Dependency> managedDeps;
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

    private List<Dependency> toAetherDependencies(
            List<org.apache.maven.model.Dependency> deps) {
        List<Dependency> result = new ArrayList<>(deps.size());
        for (org.apache.maven.model.Dependency dep : deps) {
            result.add(toAetherDependency(dep));
        }
        return result;
    }

    private static Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        return new Dependency(
                SbomUtils.toAetherArtifact(dep.getGroupId(), dep.getArtifactId(),
                        dep.getVersion(), dep.getType(), dep.getClassifier()),
                dep.getScope());
    }

    private CollectRequest buildCollectRequest(List<Dependency> deps,
            List<Dependency> managedDeps) {
        CollectRequest request = new CollectRequest();
        request.setDependencies(deps);
        request.setManagedDependencies(managedDeps);
        request.setRepositories(project.getRemoteProjectRepositories());
        return request;
    }

    private Map<ArtifactCoords, List<ArtifactCoords>> filterEdges(
            Map<ArtifactCoords, Set<ArtifactCoords>> collectedEdges,
            Set<ArtifactCoords> knownIds) {
        Map<ArtifactCoords, List<ArtifactCoords>> graph = new HashMap<>();
        for (ArtifactCoords id : knownIds) {
            Set<ArtifactCoords> children = collectedEdges.get(id);
            if (children == null) {
                continue;
            }
            List<ArtifactCoords> filtered = new ArrayList<>(children.size());
            for (ArtifactCoords childId : children) {
                if (knownIds.contains(childId)) {
                    filtered.add(childId);
                }
            }
            graph.put(id, filtered);
        }
        return graph;
    }
}
