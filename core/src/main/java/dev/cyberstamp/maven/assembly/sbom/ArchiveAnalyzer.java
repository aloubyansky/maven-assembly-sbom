package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches archive entries to Maven artifacts by content hash and
 * detects unpacked (exploded) archives within the assembly.
 *
 * <p>
 * This class encapsulates the artifact identification pipeline:
 * hash-based matching, unpacked artifact detection via ZIP content
 * scanning, and nested JAR identification via dependency resolution
 * or embedded {@code pom.properties}.
 * </p>
 */
class ArchiveAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ArchiveAnalyzer.class);
    public static final String JAR = "jar";
    private static final Set<String> ZIP_BASED_EXTENSIONS = Set.of(
            ".jar", ".war", ".ear", ".rar", ".par");

    private static final Comparator<String> JSON_FIRST_SBOM_ORDER = Comparator
            .<String, Boolean> comparing(p -> !p.endsWith(".cdx.json"))
            .thenComparing(Comparator.naturalOrder());

    private final EffectiveModelResolver effectiveModelResolver;
    private final RepositorySystem repoSystem;
    private final MavenProject project;
    private final MavenSession session;
    // not thread-safe — safe here because the matcher runs on a single thread
    private final MessageDigest messageDigest;
    private final boolean failOnDuplicateHash;
    private final Map<ArtifactCoords, MavenProject> reactorModuleIndex;
    private final List<Bom> externalBoms;
    private final boolean detectEmbeddedSboms;
    private List<Artifact> allArtifacts;
    private ArtifactHashIndex hashIndex;
    private Map<ArtifactCoords, List<Dependency>> lastNestedDepsByParent;

    /**
     * Result of scanning a ZIP file's contents against unmatched
     * archive entries.
     *
     * @param matchedArchiveEntries archive entries matched by hash
     * @param hashToZipEntryNames content hash to ZIP entry name mapping
     */
    record ZipScanResult(Set<FileEntry> matchedArchiveEntries,
            Map<String, List<String>> hashToZipEntryNames) {

        /** Returns {@code true} if at least one entry matched. */
        boolean hasMatchedEntries() {
            return !matchedArchiveEntries.isEmpty();
        }

        /**
         * Derives the common unpack prefix from matched entries.
         *
         * @return the prefix (with trailing slash), or {@code null}
         */
        String computeUnpackPrefix() {
            String prefix = null;
            for (FileEntry entry : matchedArchiveEntries) {
                List<String> zipNames = hashToZipEntryNames.get(entry.hash());
                if (zipNames == null) {
                    continue;
                }
                String entryPrefix = null;
                for (String zipName : zipNames) {
                    if (entry.archivePath().endsWith(zipName)) {
                        entryPrefix = entry.archivePath().substring(
                                0, entry.archivePath().length() - zipName.length());
                        break;
                    }
                }
                if (entryPrefix == null) {
                    continue;
                }
                if (prefix == null) {
                    prefix = entryPrefix;
                } else if (!prefix.equals(entryPrefix)) {
                    return null;
                }
            }
            return prefix;
        }
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash) {
        this(effectiveModelResolver, repoSystem, project, session,
                messageDigest, failOnDuplicateHash, List.of(), true);
    }

    ArchiveAnalyzer(EffectiveModelResolver effectiveModelResolver,
            RepositorySystem repoSystem,
            MavenProject project,
            MavenSession session,
            MessageDigest messageDigest,
            boolean failOnDuplicateHash,
            List<Bom> externalBoms,
            boolean detectEmbeddedSboms) {
        this.effectiveModelResolver = effectiveModelResolver;
        this.repoSystem = repoSystem;
        this.project = project;
        this.session = session;
        this.messageDigest = messageDigest;
        this.failOnDuplicateHash = failOnDuplicateHash;
        this.reactorModuleIndex = indexReactorModules(session.getProjects());
        this.externalBoms = externalBoms;
        this.detectEmbeddedSboms = detectEmbeddedSboms;
    }

    /**
     * Indexes reactor projects by artifact id for O(1) lookup.
     */
    private static Map<ArtifactCoords, MavenProject> indexReactorModules(List<MavenProject> projects) {
        Map<ArtifactCoords, MavenProject> index = new HashMap<>(projects.size());
        for (MavenProject p : projects) {
            index.put(MavenArtifactCoords.of(p), p);
        }
        return index;
    }

    /**
     * Returns the project's resolved dependencies plus its own artifact,
     * collecting them on first access.
     */
    private List<Artifact> allArtifacts() {
        if (allArtifacts == null) {
            allArtifacts = new ArrayList<>();
            if (project.getArtifacts() != null) {
                allArtifacts.addAll(project.getArtifacts());
            }
            Artifact projectArtifact = project.getArtifact();
            if (projectArtifact != null && projectArtifact.getFile() != null) {
                allArtifacts.add(projectArtifact);
            }
        }
        return allArtifacts;
    }

    /**
     * Returns the Aether-typed nested dependencies collected during the last
     * {@link #analyze} call. This is analysis side-data that must NOT be stored
     * on the neutral model.
     *
     * <p>
     * Exposed as a package-private getter so {@link SbomGenerator} can read it
     * for {@code buildDependencyGraph} without polluting the neutral model.
     * </p>
     *
     * @return the nested dependencies map from the last analysis, or {@code null}
     *         if {@code analyze} has not been called
     */
    Map<ArtifactCoords, List<Dependency>> nestedDepsByParent() {
        return lastNestedDepsByParent;
    }

    /**
     * Analyzes archive entries against Maven artifacts and returns
     * the neutral component model.
     *
     * @param entries the archive file entries with content hashes
     * @param baseDirPrefix the base directory prefix to strip, or {@code null}
     * @return the assembled neutral component model
     * @throws IllegalStateException if duplicate hashes are detected
     *         and the matcher is configured to fail on duplicates
     */
    AssemblyComponents analyze(List<FileEntry> entries, String baseDirPrefix) {
        ArchiveContent content = new ArchiveContent();
        Set<Artifact> matchedArtifacts = new HashSet<>();
        Map<String, FileEntry> unmatchedByPath = new HashMap<>();

        classifyArchiveEntries(entries, baseDirPrefix, content, matchedArtifacts, unmatchedByPath);
        if (!unmatchedByPath.isEmpty()) {
            detectUnpackedArtifacts(matchedArtifacts, unmatchedByPath, content);
            reclassifyEntriesUnderUnpackedArtifacts(content);
        }
        if (!unmatchedByPath.isEmpty()) {
            detectMavenMetadataInUnmatchedJars(unmatchedByPath, content);
        }
        if (!unmatchedByPath.isEmpty()) {
            matchAgainstExternalSboms(unmatchedByPath, content);
        }
        if (detectEmbeddedSboms) {
            Set<String> detectedSbomPaths = new HashSet<>();
            detectSbomsInArtifactJars(content, detectedSbomPaths);
            detectedSbomPaths.forEach(unmatchedByPath::remove);
        }

        for (FileEntry entry : unmatchedByPath.values()) {
            content.addUnmatchedFile(entry);
        }

        // Translate ArchiveContent → AssemblyComponents
        return translateToModel(content);
    }

    /**
     * Translates the internal {@link ArchiveContent} scratch structure into
     * the neutral {@link AssemblyComponents} model. This method preserves order
     * and nesting, so the {@link BomRenderer} produces byte-identical output.
     *
     * <p>
     * Translation rules (per Task C2 brief):
     * <ul>
     * <li>{@code MavenEntry} → top-level {@link PackageComponent}</li>
     * <li>{@code NestedMavenEntry} → {@link PackageComponent} nested under parent,
     * plus a {@link DependencyEdge} with {@code explicit=true}</li>
     * <li>{@code FileNestedArtifact} → {@link PackageComponent} (no hash) nested
     * under the {@link FileComponent} at that path</li>
     * <li>Unmatched files → top-level {@link FileComponent}</li>
     * <li>{@code detectedSboms} → {@link DiscoveredSbom}</li>
     * </ul>
     * </p>
     *
     * <p>
     * The Aether-typed {@code nestedDepsByParent} is NOT stored on the model;
     * instead it is exposed via {@link #nestedDepsByParent()} for {@link SbomGenerator}
     * to consume.
     * </p>
     */
    private AssemblyComponents translateToModel(ArchiveContent content) {
        // Store Aether side-data for the getter
        lastNestedDepsByParent = content.nestedDepsByParent();

        // 1. Build top-level PackageComponents (no licenses yet) into a plain list
        Map<ArtifactCoords, PackageComponent> topLevelByCoords = new HashMap<>();
        List<AssemblyComponent> topLevel = new ArrayList<>();
        for (ArchiveContent.MavenEntry entry : content.mavenEntries()) {
            PackageComponent pkg = PackageComponent.of(
                    entry.artifactId(), entry.archivePath(), entry.hash());
            topLevel.add(pkg);
            topLevelByCoords.put(entry.artifactId(), pkg);
        }

        // 2. Attach nested children to top-level PackageComponents where present
        Map<ArtifactCoords, List<ArchiveContent.NestedMavenEntry>> childrenByParent = new HashMap<>();
        for (ArchiveContent.NestedMavenEntry nested : content.nestedEntries()) {
            childrenByParent.computeIfAbsent(nested.parentId(), k -> new ArrayList<>())
                    .add(nested);
        }

        if (!childrenByParent.isEmpty()) {
            Map<ArtifactCoords, PackageComponent> builtNestedComponents = new HashMap<>();
            for (int i = 0; i < topLevel.size(); i++) {
                if (topLevel.get(i) instanceof PackageComponent pkg) {
                    ArtifactCoords coords = (ArtifactCoords) pkg.ref();
                    List<AssemblyComponent> nestedList = buildNestedComponentsRecursively(
                            coords, childrenByParent, builtNestedComponents);
                    if (!nestedList.isEmpty()) {
                        PackageComponent withNested = new PackageComponent(
                                pkg.ref(), pkg.archivePath(), pkg.hash(),
                                pkg.licenses(), nestedList);
                        topLevel.set(i, withNested);
                        topLevelByCoords.put(coords, withNested);
                    }
                }
            }
        }

        // 3. File components — group FileNestedArtifacts by archive path first
        Map<String, List<PackageComponent>> nestedByFilePath = new HashMap<>();
        for (ArchiveContent.FileNestedArtifact fna : content.fileNestedArtifacts()) {
            nestedByFilePath.computeIfAbsent(fna.archivePath(), k -> new ArrayList<>())
                    .add(PackageComponent.of(fna.artifactId(), null, null));
        }
        for (FileEntry fileEntry : content.unmatchedFiles()) {
            List<PackageComponent> nestedPkgs = nestedByFilePath.getOrDefault(
                    fileEntry.archivePath(), List.of());
            topLevel.add(new FileComponent(
                    fileEntry.archivePath(), fileEntry.hash(), new ArrayList<>(nestedPkgs)));
        }

        // Assemble the model from the fully-built component list
        AssemblyComponents model = new AssemblyComponents();
        for (AssemblyComponent comp : topLevel) {
            model.addComponent(comp);
        }

        // 4. Dependency edges — only for explicitly-identified nested entries
        for (ArchiveContent.NestedMavenEntry nested : content.nestedEntries()) {
            if (nested.explicit()) {
                model.addDependencyEdge(new DependencyEdge(nested.parentId(), nested.artifactId(), true));
            }
        }

        // 5. Detected embedded SBOMs
        for (ArchiveContent.DetectedSbom detected : content.detectedSboms()) {
            model.addDiscoveredSbom(new DiscoveredSbom(
                    detected.archivePath(), detected.parsedBom(), detected.parentArtifact()));
        }

        return model;
    }

    /**
     * Recursively builds nested PackageComponents for the given parent,
     * handling multi-level nesting (e.g., bundled deps within shaded JARs
     * that are themselves nested within WARs).
     *
     * <p>
     * Assumes an acyclic parent-child relationship: the detection pipeline
     * derives {@code childrenByParent} from filesystem artifacts, which cannot
     * form cycles. The {@code builtComponents} cache also ensures each parent's
     * subtree is built once and shared. A circular relationship would recurse
     * without terminating; the no-cycle contract is guaranteed by the
     * filesystem-based source rather than an explicit guard.
     * </p>
     */
    private List<AssemblyComponent> buildNestedComponentsRecursively(
            ArtifactCoords parentCoords,
            Map<ArtifactCoords, List<ArchiveContent.NestedMavenEntry>> childrenByParent,
            Map<ArtifactCoords, PackageComponent> builtComponents) {
        List<AssemblyComponent> result = new ArrayList<>();
        List<ArchiveContent.NestedMavenEntry> directChildren = childrenByParent.get(parentCoords);
        if (directChildren == null) {
            return result;
        }

        for (ArchiveContent.NestedMavenEntry child : directChildren) {
            // Check if we've already built this component (to handle shared children)
            PackageComponent built = builtComponents.get(child.artifactId());
            if (built != null) {
                result.add(built);
                continue;
            }

            // Recursively build this child's nested components
            List<AssemblyComponent> grandchildren = buildNestedComponentsRecursively(
                    child.artifactId(), childrenByParent, builtComponents);

            // Build the child component with its nested components
            PackageComponent childComponent = new PackageComponent(
                    child.artifactId(), child.archivePath(), child.hash(),
                    List.of(), grandchildren);
            builtComponents.put(child.artifactId(), childComponent);
            result.add(childComponent);
        }

        return result;
    }

    /**
     * Classifies archive entries as matched or unmatched by hash lookup.
     */
    private void classifyArchiveEntries(List<FileEntry> entries,
            String baseDirPrefix,
            ArchiveContent content,
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath) {
        hashIndex = new ArtifactHashIndex(allArtifacts(), messageDigest, failOnDuplicateHash);
        for (FileEntry entry : entries) {
            String relativePath = stripBaseDir(entry.archivePath(), baseDirPrefix);
            if (relativePath.isEmpty()) {
                continue;
            }
            List<Artifact> artifacts = hashIndex.lookup(entry.hash());
            if (artifacts != null) {
                for (Artifact artifact : artifacts) {
                    matchedArtifacts.add(artifact);
                    content.addMavenEntry(new ArchiveContent.MavenEntry(
                            MavenArtifactCoords.of(artifact), relativePath, entry.hash()));
                    detectBundledDepsInArtifactFile(artifact, content);
                }
            } else {
                unmatchedByPath.put(relativePath,
                        new FileEntry(relativePath, entry.hash(), entry.sourceFile()));
            }
        }
    }

    /**
     * Detects artifacts that were unpacked into the assembly.
     * Matched entries are removed from {@code unmatchedByPath}.
     */
    private void detectUnpackedArtifacts(
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath,
            ArchiveContent content) {

        Path buildDir = Path.of(project.getBuild().getDirectory()).toAbsolutePath().normalize();
        Map<String, List<FileEntry>> entriesByHash = indexEntriesByHash(
                unmatchedByPath.values(), buildDir);

        for (Artifact artifact : allArtifacts()) {
            if (entriesByHash.isEmpty()) {
                break;
            }
            if (matchedArtifacts.contains(artifact)) {
                continue;
            }
            if (artifact.getFile() == null || !artifact.getFile().isFile()) {
                continue;
            }
            tryMatchUnpackedArtifact(artifact, entriesByHash,
                    matchedArtifacts, unmatchedByPath, content);
        }
    }

    /**
     * Reclassifies top-level {@link ArchiveContent.MavenEntry} records
     * whose paths fall inside a detected unpacked artifact. An unpacked
     * artifact is recognized by its {@code archivePath} ending with
     * {@code '/'}. Root-level overlays (empty archivePath) are skipped
     * to avoid reclassifying independent top-level entries. When
     * multiple prefixes match, the longest prefix wins to correctly
     * handle nested unpacked archives.
     *
     * <p>
     * Entries that belong to an unpacked artifact are removed from the
     * top-level list and added as {@link ArchiveContent.NestedMavenEntry}
     * records under the unpacked parent.
     * </p>
     */
    private static void reclassifyEntriesUnderUnpackedArtifacts(ArchiveContent content) {
        // collect unpacked artifact prefixes → parent coords
        Map<String, ArtifactCoords> prefixToParent = null;
        for (ArchiveContent.MavenEntry entry : content.mavenEntries()) {
            String path = entry.archivePath();
            if (path != null && path.endsWith("/")) {
                if (prefixToParent == null) {
                    prefixToParent = new HashMap<>();
                }
                prefixToParent.put(path, entry.artifactId());
            }
        }
        if (prefixToParent == null) {
            return;
        }

        var it = content.mavenEntries().iterator();
        while (it.hasNext()) {
            ArchiveContent.MavenEntry entry = it.next();
            String path = entry.archivePath();
            if (path == null || path.endsWith("/") || path.isEmpty()) {
                continue;
            }
            // match the longest prefix to handle nested unpacked archives
            String longestPrefix = null;
            for (String pfx : prefixToParent.keySet()) {
                if (path.startsWith(pfx)
                        && (longestPrefix == null || pfx.length() > longestPrefix.length())) {
                    longestPrefix = pfx;
                }
            }
            if (longestPrefix != null) {
                ArtifactCoords parentId = prefixToParent.get(longestPrefix);
                if (!parentId.equals(entry.artifactId())) {
                    it.remove();
                    content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                            parentId, entry.artifactId(),
                            entry.archivePath(), entry.hash(), true));
                }
            }
        }
    }

    /**
     * Indexes entries by content hash, excluding project source files.
     *
     * <p>
     * Entries whose {@link FileEntry#sourceFile() sourceFile}
     * resolves outside the project's build output directory are considered
     * project source files (e.g. {@code LICENSE.txt} included via a
     * {@code <fileSet>}) and are excluded from the index. This prevents
     * false-positive unpack detection when a dependency jar happens to
     * contain a file with the same hash as a project source file.
     * </p>
     */
    private static Map<String, List<FileEntry>> indexEntriesByHash(
            Iterable<FileEntry> entries, Path buildDir) {
        Map<String, List<FileEntry>> index = new HashMap<>();
        for (FileEntry e : entries) {
            if (e.hash() != null && !isProjectSourceFile(e, buildDir)) {
                index.computeIfAbsent(e.hash(), k -> new ArrayList<>(1)).add(e);
            }
        }
        return index;
    }

    /**
     * Returns {@code true} if the entry originates from a project source
     * file rather than a build output. An entry is considered a project
     * source file when its {@code sourceFile} is known and does not
     * reside under the project's build directory.
     */
    private static boolean isProjectSourceFile(FileEntry entry, Path buildDir) {
        if (entry.sourceFile() == null) {
            return false;
        }
        return !entry.sourceFile().toPath().startsWith(buildDir);
    }

    /**
     * Scans unmatched JAR entries for embedded {@code pom.properties}
     * to identify non-dependency JARs as Maven components.
     * Identified entries are removed from {@code unmatchedByPath}.
     */
    private static void detectMavenMetadataInUnmatchedJars(
            Map<String, FileEntry> unmatchedByPath,
            ArchiveContent content) {
        List<ArchiveContent.FileNestedArtifact> fileNestedArtifacts = content.fileNestedArtifacts();
        Set<String> alreadyProcessed = new HashSet<>(fileNestedArtifacts.size());
        for (ArchiveContent.FileNestedArtifact fna : fileNestedArtifacts) {
            alreadyProcessed.add(fna.archivePath());
        }
        var it = unmatchedByPath.values().iterator();
        while (it.hasNext()) {
            FileEntry fileEntry = it.next();
            if (fileEntry.sourceFile() == null
                    || !fileEntry.sourceFile().isFile()
                    || !hasZipBasedExtension(fileEntry.archivePath())
                    || alreadyProcessed.contains(fileEntry.archivePath())) {
                continue;
            }
            try (ZipFile zf = new ZipFile(fileEntry.sourceFile())) {
                List<Properties> allProps = readPomPropertiesFromZip(zf);
                if (allProps.isEmpty()) {
                    continue;
                }
                boolean identified = allProps.size() == 1
                        ? registerFromStandaloneProps(allProps.get(0), fileEntry, content) != null
                        : registerStandaloneShadedJar(allProps, fileEntry, content);
                if (identified) {
                    it.remove();
                }
            } catch (IOException e) {
                log.debug("Could not read {} for Maven metadata", fileEntry.sourceFile(), e);
            }
        }
    }

    /**
     * Registers a standalone JAR as a Maven entry from pom.properties.
     *
     * @return the registered artifact coordinates, or {@code null} if
     *         required properties are missing
     */
    private static ArtifactCoords registerFromStandaloneProps(Properties props,
            FileEntry fileEntry, ArchiveContent content) {
        String gId = props.getProperty("groupId");
        String aId = props.getProperty("artifactId");
        String ver = props.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        ArtifactCoords coords = ArtifactCoords.of(gId, aId, ver);
        content.addMavenEntry(new ArchiveContent.MavenEntry(
                coords, fileEntry.archivePath(), fileEntry.hash()));
        return coords;
    }

    /**
     * Handles a standalone shaded JAR (multiple pom.properties, not a
     * known project dependency). Uses filename matching to determine
     * the owner, same logic as nested shaded JARs.
     *
     * @return {@code true} if the owner was identified and registered
     */
    private static boolean registerStandaloneShadedJar(List<Properties> allProps,
            FileEntry fileEntry, ArchiveContent content) {
        return resolveAndRegisterShadedOwner(allProps, fileEntry, content,
                fileEntry.archivePath(),
                props -> registerFromStandaloneProps(props, fileEntry, content));
    }

    /**
     * Shared resolve/register/fallback flow for shaded JARs with multiple
     * pom.properties. Resolves the owner by filename, delegates registration
     * to the caller-provided function, and falls back to file-nested
     * recording on failure.
     *
     * @param registerOwner registers the owner and returns its coords, or null on failure
     * @return {@code true} if the owner was identified and registered
     */
    private static boolean resolveAndRegisterShadedOwner(
            List<Properties> allProps, FileEntry archiveEntry,
            ArchiveContent content, String pathForFilename,
            Function<Properties, ArtifactCoords> registerOwner) {
        Properties owner = resolveOwnerByFilename(allProps,
                SbomUtils.extractFileName(pathForFilename));
        if (owner == null) {
            log.debug("Could not determine owner of shaded JAR {},"
                    + " nesting all under file", pathForFilename);
            recordAllAsFileNested(archiveEntry, allProps, content);
            return false;
        }
        ArtifactCoords ownerCoords = registerOwner.apply(owner);
        if (ownerCoords == null) {
            recordAllAsFileNested(archiveEntry, allProps, content);
            return false;
        }
        registerBundledDependencies(ownerCoords, allProps, content);
        return true;
    }

    /**
     * Strips the base directory prefix from an archive path.
     */
    private static String stripBaseDir(String archivePath, String baseDirPrefix) {
        if (baseDirPrefix != null && archivePath.startsWith(baseDirPrefix)) {
            return archivePath.substring(baseDirPrefix.length());
        }
        return archivePath;
    }

    private static boolean hasZipBasedExtension(String path) {
        int dot = path.lastIndexOf('.');
        return dot >= 0 && ZIP_BASED_EXTENSIONS.contains(path.substring(dot));
    }

    /**
     * Attempts to match a single artifact as an unpacked archive.
     * Entries that match the archive content but cannot be positively
     * identified are preserved in {@code unmatchedByPath} so they
     * appear as file components in the final BOM. When pom.properties
     * are found inside an unidentified entry, the discovered artifacts
     * are recorded as file-nested entries.
     */
    private void tryMatchUnpackedArtifact(Artifact artifact,
            Map<String, List<FileEntry>> entriesByHash,
            Set<Artifact> matchedArtifacts,
            Map<String, FileEntry> unmatchedByPath,
            ArchiveContent content) {
        try (ZipFile zf = new ZipFile(artifact.getFile())) {
            ZipScanResult scan = scanZipForMatches(zf, entriesByHash);
            if (!scan.hasMatchedEntries()) {
                return;
            }

            matchedArtifacts.add(artifact);
            String occurrence = scan.computeUnpackPrefix();
            if (occurrence == null) {
                log.debug("Could not determine unpack prefix for {}", artifact);
            }
            content.addMavenEntry(new ArchiveContent.MavenEntry(
                    MavenArtifactCoords.of(artifact), occurrence, hashIndex.hashOf(artifact)));

            Map<String, Artifact> nestedArtifactsByHash = buildNestedArtifactHashMap(artifact);
            ArtifactCoords parentCoords = MavenArtifactCoords.of(artifact);

            for (FileEntry archiveEntry : scan.matchedArchiveEntries) {
                boolean identified = identifyNestedArtifact(archiveEntry, zf,
                        scan.hashToZipEntryNames, nestedArtifactsByHash,
                        parentCoords, matchedArtifacts, content);
                if (identified) {
                    unmatchedByPath.remove(archiveEntry.archivePath());
                }
                entriesByHash.remove(archiveEntry.hash());
            }
        } catch (IOException e) {
            log.debug("Could not read {} as ZIP, skipping unpacked detection",
                    artifact.getFile(), e);
        }
    }

    /**
     * Scans ZIP entries and matches hashes against unmatched archive entries.
     */
    private ZipScanResult scanZipForMatches(ZipFile zf,
            Map<String, List<FileEntry>> entriesByHash)
            throws IOException {
        Set<FileEntry> matchedArchiveEntries = new HashSet<>();
        Map<String, List<String>> hashToZipEntryNames = new HashMap<>();

        Enumeration<? extends ZipEntry> zipEntries = zf.entries();
        while (zipEntries.hasMoreElements()) {
            ZipEntry ze = zipEntries.nextElement();
            if (ze.isDirectory()) {
                continue;
            }
            String hash;
            try (InputStream entryStream = zf.getInputStream(ze)) {
                hash = SbomUtils.computeHash(messageDigest, entryStream);
            }
            hashToZipEntryNames.computeIfAbsent(hash, k -> new ArrayList<>(1))
                    .add(ze.getName());
            List<FileEntry> matching = entriesByHash.get(hash);
            if (matching != null) {
                matchedArchiveEntries.addAll(matching);
            }
        }
        return new ZipScanResult(matchedArchiveEntries, hashToZipEntryNames);
    }

    /**
     * Identifies a nested artifact via hash lookup or pom.properties fallback.
     *
     * @return {@code true} if the artifact was positively identified
     */
    private boolean identifyNestedArtifact(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            Map<String, Artifact> nestedArtifactsByHash,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        if (archiveEntry.hash() != null) {
            Artifact nestedArtifact = nestedArtifactsByHash.get(archiveEntry.hash());
            if (nestedArtifact != null) {
                registerNestedArtifact(nestedArtifact, archiveEntry, parentId, matchedArtifacts, content);
                detectBundledDependencies(archiveEntry, parentZip, hashToZipEntryNames,
                        MavenArtifactCoords.of(nestedArtifact), content);
                return true;
            }
        }
        return tryIdentifyFromPomProperties(archiveEntry, parentZip,
                hashToZipEntryNames, parentId, matchedArtifacts, content);
    }

    /**
     * Scans an artifact's JAR file directly for bundled (shaded) dependencies.
     */
    private void detectBundledDepsInArtifactFile(Artifact artifact, ArchiveContent content) {
        File file = artifact.getFile();
        if (file == null || !file.isFile()) {
            return;
        }
        try (ZipFile zf = new ZipFile(file)) {
            List<Properties> allProps = readPomPropertiesFromZip(zf);
            registerBundledDependencies(MavenArtifactCoords.of(artifact), allProps, content);
        } catch (IOException e) {
            log.debug("Could not scan {} for bundled dependencies", file, e);
        }
    }

    /**
     * Scans a hash-identified nested JAR for bundled (shaded) dependencies
     * by reading its pom.properties via the parent ZIP.
     */
    private void detectBundledDependencies(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords ownerCoords, ArchiveContent content) {
        if (archiveEntry.hash() == null) {
            return;
        }
        List<String> zipEntryNames = hashToZipEntryNames.get(archiveEntry.hash());
        if (zipEntryNames == null) {
            return;
        }
        List<Properties> allProps = readAllPomProperties(parentZip, zipEntryNames.get(0));
        registerBundledDependencies(ownerCoords, allProps, content);
    }

    /**
     * Registers non-owner pom.properties entries as bundled nested components.
     */
    private static void registerBundledDependencies(ArtifactCoords ownerCoords, List<Properties> allProps,
            ArchiveContent content) {
        if (allProps.size() <= 1) {
            return;
        }
        for (Properties bp : allProps) {
            String gId = bp.getProperty("groupId");
            String aId = bp.getProperty("artifactId");
            String ver = bp.getProperty("version");
            if (gId != null && aId != null && ver != null
                    && !(gId.equals(ownerCoords.groupId())
                            && aId.equals(ownerCoords.artifactId())
                            && ver.equals(ownerCoords.version()))) {
                content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                        ownerCoords, ArtifactCoords.of(gId, aId, ver), null, null, false));
            }
        }
    }

    /**
     * Matches artifactIds from pom.properties entries against a JAR
     * filename to find the owner. Returns the single best match, or
     * {@code null} if the result is ambiguous (zero or multiple
     * equally-long matches).
     */
    private static Properties resolveOwnerByFilename(List<Properties> allProps,
            String fileName) {
        List<Properties> matching = new ArrayList<>();
        for (Properties p : allProps) {
            String aId = p.getProperty("artifactId");
            if (aId != null && fileName.contains(aId)) {
                matching.add(p);
            }
        }
        if (matching.size() > 1) {
            Properties best = null;
            int maxLen = 0;
            boolean unique = true;
            for (Properties p : matching) {
                int len = p.getProperty("artifactId").length();
                if (len > maxLen) {
                    maxLen = len;
                    best = p;
                    unique = true;
                } else if (len == maxLen) {
                    unique = false;
                }
            }
            return unique ? best : null;
        }
        return matching.size() == 1 ? matching.get(0) : null;
    }

    /**
     * Records all pom.properties entries as file-nested artifacts.
     */
    private static void recordAllAsFileNested(FileEntry archiveEntry, List<Properties> allProps,
            ArchiveContent content) {
        for (Properties p : allProps) {
            String gId = p.getProperty("groupId");
            String aId = p.getProperty("artifactId");
            String ver = p.getProperty("version");
            if (gId != null && aId != null && ver != null) {
                content.addFileNestedArtifact(archiveEntry.archivePath(),
                        ArtifactCoords.of(gId, aId, ver));
            }
        }
    }

    /**
     * Reads all pom.properties entries directly from a ZIP file.
     */
    private static List<Properties> readPomPropertiesFromZip(ZipFile zf) throws IOException {
        List<Properties> result = new ArrayList<>();
        Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (ze.getName().startsWith("META-INF/maven/")
                    && ze.getName().endsWith("/pom.properties")) {
                Properties props = new Properties();
                try (InputStream is = zf.getInputStream(ze)) {
                    props.load(is);
                }
                result.add(props);
            }
        }
        return result;
    }

    /**
     * Attempts to identify a nested JAR by reading embedded pom.properties.
     *
     * <p>
     * When a JAR contains multiple pom.properties (shaded/fat JAR), the
     * method attempts to match the JAR filename against the artifactIds.
     * If exactly one artifactId matches, that entry is used as the owner
     * and the remaining entries are registered as bundled nested components.
     * </p>
     *
     * @return {@code true} if the artifact was positively identified
     */
    private boolean tryIdentifyFromPomProperties(FileEntry archiveEntry, ZipFile parentZip,
            Map<String, List<String>> hashToZipEntryNames,
            ArtifactCoords parentId,
            Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        if (archiveEntry.hash() == null) {
            return false;
        }
        List<String> zipEntryNames = hashToZipEntryNames.get(archiveEntry.hash());
        if (zipEntryNames == null) {
            return false;
        }
        for (String zipEntryName : zipEntryNames) {
            List<Properties> allProps = readAllPomProperties(parentZip, zipEntryName);
            if (allProps.isEmpty()) {
                continue;
            }
            if (allProps.size() == 1) {
                return tryRegisterFromProps(allProps.get(0), archiveEntry,
                        parentId, matchedArtifacts, content) != null;
            }
            // Shaded JAR: match the filename against artifactIds
            return resolveAndRegisterShadedOwner(allProps, archiveEntry, content,
                    zipEntryName,
                    props -> tryRegisterFromProps(props, archiveEntry,
                            parentId, matchedArtifacts, content));
        }
        return false;
    }

    /**
     * Tries to register a nested artifact from the given pom.properties.
     *
     * @return the registered artifact's coordinates, or {@code null} if
     *         required properties are missing
     */
    private ArtifactCoords tryRegisterFromProps(Properties pomProps,
            FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        String gId = pomProps.getProperty("groupId");
        String aId = pomProps.getProperty("artifactId");
        String ver = pomProps.getProperty("version");
        if (gId == null || aId == null || ver == null) {
            return null;
        }
        Artifact nested = new org.apache.maven.artifact.DefaultArtifact(
                gId, aId, ver, "compile", JAR, null,
                new org.apache.maven.artifact.handler.DefaultArtifactHandler(JAR));
        registerNestedArtifact(nested, archiveEntry, parentId, matchedArtifacts, content);
        return MavenArtifactCoords.of(nested);
    }

    /**
     * Records a nested artifact and its dependency relationship.
     */
    private void registerNestedArtifact(Artifact artifact, FileEntry archiveEntry,
            ArtifactCoords parentId, Set<Artifact> matchedArtifacts,
            ArchiveContent content) {
        matchedArtifacts.add(artifact);
        ArtifactCoords nestedId = MavenArtifactCoords.of(artifact);
        content.addNestedEntry(new ArchiveContent.NestedMavenEntry(
                parentId, nestedId, archiveEntry.archivePath(), archiveEntry.hash(), true));
        content.addNestedDependency(parentId, new Dependency(
                SbomUtils.toAetherArtifact(artifact.getGroupId(), artifact.getArtifactId(),
                        artifact.getVersion(), artifact.getType(), artifact.getClassifier()),
                "compile"));
    }

    /**
     * Reads all pom.properties entries from a nested JAR entry.
     */
    private static List<Properties> readAllPomProperties(ZipFile outerZip, String entryName) {
        ZipEntry entry = outerZip.getEntry(entryName);
        if (entry == null) {
            return List.of();
        }
        List<Properties> result = new ArrayList<>();
        try (InputStream is = outerZip.getInputStream(entry);
                ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                if (ze.getName().startsWith("META-INF/maven/")
                        && ze.getName().endsWith("/pom.properties")) {
                    Properties props = new Properties();
                    props.load(zis);
                    result.add(props);
                }
            }
        } catch (IOException e) {
            log.debug("Failed to parse pom.properties from nested JAR {}", entryName, e);
        }
        return result;
    }

    /**
     * Builds a hash-to-artifact map for the given artifact's dependencies.
     */
    private Map<String, Artifact> buildNestedArtifactHashMap(Artifact artifact) {
        ArtifactCoords coords = MavenArtifactCoords.of(artifact);
        MavenProject module = reactorModuleIndex.get(coords);
        if (module != null && module.getArtifacts() != null) {
            return buildHashMapFromArtifacts(module.getArtifacts());
        }
        return buildHashMapFromEffectiveModel(artifact);
    }

    /**
     * Builds a hash-to-artifact map from pre-resolved Maven artifacts.
     */
    private Map<String, Artifact> buildHashMapFromArtifacts(Set<Artifact> artifacts) {
        Map<String, Artifact> map = new HashMap<>(artifacts.size());
        for (Artifact a : artifacts) {
            String hash = hashIndex.hashOf(a);
            if (hash != null) {
                map.put(hash, a);
            }
        }
        return map;
    }

    private static final Set<String> EXCLUDED_SCOPES = Set.of("test", "provided", "system");

    /**
     * Resolves dependencies from an artifact's effective POM and builds
     * a hash-to-artifact map. Only compile and runtime scoped dependencies
     * are included; test, provided, and system scopes are excluded.
     */
    private Map<String, Artifact> buildHashMapFromEffectiveModel(Artifact artifact) {
        Model model = effectiveModelResolver.resolveEffectiveModel(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
        if (model == null || model.getDependencies() == null) {
            return Map.of();
        }

        Map<String, Artifact> map = new HashMap<>();
        for (org.apache.maven.model.Dependency dep : model.getDependencies()) {
            String scope = dep.getScope();
            if (scope == null || !EXCLUDED_SCOPES.contains(scope)) {
                resolveAndHashDependency(dep, map);
            }
        }
        return map;
    }

    /**
     * Resolves a single dependency's artifact and adds it to the hash map.
     */
    private void resolveAndHashDependency(org.apache.maven.model.Dependency dep,
            Map<String, Artifact> map) {
        try {
            org.eclipse.aether.artifact.DefaultArtifact aetherArtifact = SbomUtils.toAetherArtifact(
                    dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                    dep.getType(), dep.getClassifier());
            ArtifactRequest request = new ArtifactRequest(
                    aetherArtifact, project.getRemoteProjectRepositories(), null);
            ArtifactResult result = repoSystem.resolveArtifact(
                    session.getRepositorySession(), request);
            File file = result.getArtifact().getFile();
            if (file != null && file.isFile()) {
                Artifact mavenArtifact = new org.apache.maven.artifact.DefaultArtifact(
                        dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                        dep.getScope() != null ? dep.getScope() : "compile",
                        dep.getType() != null ? dep.getType() : JAR,
                        dep.getClassifier(),
                        new org.apache.maven.artifact.handler.DefaultArtifactHandler(
                                dep.getType() != null ? dep.getType() : JAR));
                mavenArtifact.setFile(file);
                String hash = hashIndex.hashOf(mavenArtifact);
                if (hash != null) {
                    map.put(hash, mavenArtifact);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to resolve dependency {}:{}:{}",
                    dep.getGroupId(), dep.getArtifactId(), dep.getVersion(), e);
        }
    }

    // ---- External SBOM matching ----

    /**
     * Matches unmatched archive entries against components from external
     * SBOMs by content hash. Matched entries are removed from
     * {@code unmatchedByPath} and their archive path is recorded as
     * an {@link Occurrence} on the external component so the file
     * remains traceable in the final BOM.
     *
     * <p>
     * This enables non-Maven artifacts (e.g. npm packages) to be
     * identified when an external SBOM with matching hashes is provided.
     * Maven-identified artifacts take precedence — this method only
     * processes entries that were not matched by the Maven hash index.
     * </p>
     */
    private void matchAgainstExternalSboms(
            Map<String, FileEntry> unmatchedByPath,
            ArchiveContent content) {
        if (externalBoms.isEmpty()) {
            return;
        }
        Map<String, ExternalComponentRef> externalHashIndex = buildExternalHashIndex();
        if (externalHashIndex.isEmpty()) {
            return;
        }
        // Collect all archive paths per matched component before mutating
        Map<Component, List<String>> matchedPaths = new HashMap<>();
        var it = unmatchedByPath.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            ExternalComponentRef ref = externalHashIndex.get(entry.getValue().hash());
            if (ref != null) {
                matchedPaths.computeIfAbsent(ref.component(), k -> new ArrayList<>())
                        .add(entry.getKey());
                it.remove();
            }
        }
        // Replace stale occurrences with the collected archive paths
        for (var matched : matchedPaths.entrySet()) {
            setOccurrences(matched.getKey(), matched.getValue());
        }
    }

    private static void setOccurrences(Component component, List<String> archivePaths) {
        Evidence evidence = component.getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            component.setEvidence(evidence);
        }
        List<Occurrence> occurrences = new ArrayList<>(archivePaths.size());
        for (String path : archivePaths) {
            Occurrence occ = new Occurrence();
            occ.setLocation(path);
            occurrences.add(occ);
        }
        evidence.setOccurrences(occurrences);
    }

    /**
     * A component from an external SBOM paired with its source BOM.
     */
    private record ExternalComponentRef(Component component, Bom sourceBom) {
    }

    /**
     * Builds a hash-to-component index from all external SBOM components.
     *
     * <p>
     * Only components that declare content hashes using the configured
     * hash algorithm are indexed. Components without hashes are skipped.
     * </p>
     */
    private Map<String, ExternalComponentRef> buildExternalHashIndex() {
        Map<String, ExternalComponentRef> index = new HashMap<>();
        String normalizedAlg = SbomUtils.normalizeAlgorithm(
                messageDigest.getAlgorithm());
        for (Bom bom : externalBoms) {
            if (bom.getComponents() == null) {
                continue;
            }
            indexComponentTree(bom.getComponents(), bom, normalizedAlg, index);
        }
        return index;
    }

    private static void indexComponentTree(List<Component> components, Bom bom,
            String normalizedAlg, Map<String, ExternalComponentRef> index) {
        for (Component comp : components) {
            String hash = SbomUtils.extractHash(comp, normalizedAlg);
            if (hash != null) {
                index.putIfAbsent(hash, new ExternalComponentRef(comp, bom));
            }
            if (comp.getComponents() != null) {
                indexComponentTree(comp.getComponents(), bom,
                        normalizedAlg, index);
            }
        }
    }

    /**
     * Scans matched JAR/WAR artifacts for embedded CycloneDX SBOM files.
     *
     * <p>
     * For each Maven artifact that is a ZIP-based archive, scans its
     * entries for {@code .cdx.json} or {@code .cdx.xml} files. Detected
     * SBOMs are parsed and recorded in the content, with the artifact
     * as the parent.
     * </p>
     */
    private void detectSbomsInArtifactJars(ArchiveContent content,
            Set<String> detectedSbomPaths) {
        Map<ArtifactCoords, String> coordsToPath = new HashMap<>();
        for (ArchiveContent.MavenEntry entry : content.mavenEntries()) {
            coordsToPath.put(entry.artifactId(), entry.archivePath());
        }
        Set<ArtifactCoords> knownCoords = content.collectKnownArtifactCoords();
        Set<File> scannedFiles = new HashSet<>();
        for (Artifact artifact : allArtifacts()) {
            ArtifactCoords coords = MavenArtifactCoords.of(artifact);
            if (!knownCoords.contains(coords)) {
                continue;
            }
            File file = artifact.getFile();
            if (file == null || !file.isFile() || !hasZipBasedExtension(file.getName())) {
                continue;
            }
            if (!scannedFiles.add(file)) {
                continue;
            }
            String parentArchivePath = coordsToPath.get(coords);
            if (parentArchivePath == null) {
                parentArchivePath = "";
            }
            scanJarForSboms(file, coords, content,
                    parentArchivePath, detectedSbomPaths);
        }
    }

    /**
     * Scans a single JAR/WAR file for embedded SBOM entries.
     */
    private static void scanJarForSboms(File jarFile, ArtifactCoords artifactId,
            ArchiveContent content, String parentArchivePath,
            Set<String> detectedSbomPaths) {
        Set<String> processedStems = new HashSet<>();
        try (ZipFile zf = new ZipFile(jarFile)) {
            List<String> sbomEntryNames = new ArrayList<>();
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                if (!ze.isDirectory() && BomReader.isSbomFile(ze.getName())) {
                    sbomEntryNames.add(ze.getName());
                }
            }
            sbomEntryNames.sort(JSON_FIRST_SBOM_ORDER);
            for (String entryName : sbomEntryNames) {
                String stem = BomReader.sbomStem(entryName);
                if (!processedStems.add(stem)) {
                    continue;
                }
                try (InputStream is = zf.getInputStream(zf.getEntry(entryName))) {
                    Bom parsedBom = BomReader.readBom(is);
                    if (parsedBom != null) {
                        content.addDetectedSbom(new ArchiveContent.DetectedSbom(
                                entryName, parsedBom, artifactId));
                        detectedSbomPaths.add(
                                parentArchivePath + entryName);
                    }
                }
            }
        } catch (IOException e) {
            log.debug("Could not scan {} for embedded SBOMs", jarFile, e);
        }
    }

    /**
     * Private mutable detection accumulator for {@link ArchiveAnalyzer}.
     * Contains classified entries (matched Maven artifacts, nested artifacts
     * inside unpacked archives, and unmatched files) plus dependency
     * relationship data.
     *
     * <p>
     * Instances are built incrementally by the analyzer's detection pipeline
     * and translated into the neutral {@link AssemblyComponents} model by
     * {@link #translateToModel(ArchiveContent)}.
     * </p>
     */
    private static class ArchiveContent {

        /**
         * An archive entry matched to a Maven artifact by content hash.
         */
        record MavenEntry(ArtifactCoords artifactId, String archivePath, String hash) {
        }

        /**
         * A Maven artifact found nested inside an unpacked parent archive
         * (e.g., a JAR inside an unpacked WAR).
         *
         * @param explicit {@code true} if this entry was positively identified
         *        by hash and should produce a {@link DependencyEdge};
         *        {@code false} for bundled (shaded) deps discovered only via
         *        pom.properties, where nesting is sufficient
         */
        record NestedMavenEntry(ArtifactCoords parentId, ArtifactCoords artifactId,
                String archivePath, String hash, boolean explicit) {
        }

        /**
         * A Maven artifact discovered inside a file (e.g. via pom.properties
         * in a shaded JAR) that should be nested under the file's component.
         *
         * <p>
         * The file at {@code archivePath} is most likely a Maven artifact itself
         * (e.g. a shaded or fat JAR) that could not be positively identified
         * because its filename matched zero or multiple embedded artifactIds.
         * </p>
         */
        record FileNestedArtifact(String archivePath, ArtifactCoords artifactId) {
        }

        /**
         * A CycloneDX SBOM file detected within the archive or inside a
         * bundled JAR artifact.
         *
         * @param archivePath the path of the SBOM file relative to the archive root
         * @param parsedBom the eagerly-parsed BOM content
         * @param parentArtifact the Maven artifact whose content contains this SBOM,
         *        or {@code null} if at the archive root or unresolved
         */
        record DetectedSbom(String archivePath, Bom parsedBom, ArtifactCoords parentArtifact) {
        }

        private final List<MavenEntry> mavenEntries = new ArrayList<>();
        private final List<NestedMavenEntry> nestedEntries = new ArrayList<>();
        private final List<FileEntry> unmatchedFiles = new ArrayList<>();
        private final Map<ArtifactCoords, List<Dependency>> nestedDepsByParent = new HashMap<>();
        private final List<FileNestedArtifact> fileNestedArtifacts = new ArrayList<>();
        private final List<DetectedSbom> detectedSboms = new ArrayList<>();

        List<MavenEntry> mavenEntries() {
            return mavenEntries;
        }

        List<NestedMavenEntry> nestedEntries() {
            return nestedEntries;
        }

        List<FileEntry> unmatchedFiles() {
            return unmatchedFiles;
        }

        Map<ArtifactCoords, List<Dependency>> nestedDepsByParent() {
            return nestedDepsByParent;
        }

        List<FileNestedArtifact> fileNestedArtifacts() {
            return fileNestedArtifacts;
        }

        void addMavenEntry(MavenEntry entry) {
            mavenEntries.add(entry);
        }

        void addNestedEntry(NestedMavenEntry entry) {
            nestedEntries.add(entry);
        }

        void addUnmatchedFile(FileEntry entry) {
            unmatchedFiles.add(entry);
        }

        void addFileNestedArtifact(String archivePath, ArtifactCoords artifactId) {
            fileNestedArtifacts.add(new FileNestedArtifact(archivePath, artifactId));
        }

        List<DetectedSbom> detectedSboms() {
            return detectedSboms;
        }

        void addDetectedSbom(DetectedSbom sbom) {
            detectedSboms.add(sbom);
        }

        void addNestedDependency(ArtifactCoords parentId, Dependency dependency) {
            nestedDepsByParent.computeIfAbsent(parentId, k -> new ArrayList<>())
                    .add(dependency);
        }

        /**
         * Collects all known artifact ids from both top-level and nested
         * entries, for use in dependency graph filtering.
         */
        Set<ArtifactCoords> collectKnownArtifactCoords() {
            Set<ArtifactCoords> ids = new HashSet<>(mavenEntries.size() + nestedEntries.size() + fileNestedArtifacts.size());
            for (MavenEntry e : mavenEntries) {
                ids.add(e.artifactId());
            }
            for (NestedMavenEntry e : nestedEntries) {
                ids.add(e.artifactId());
            }
            for (FileNestedArtifact e : fileNestedArtifacts) {
                ids.add(e.artifactId());
            }
            return ids;
        }
    }
}
