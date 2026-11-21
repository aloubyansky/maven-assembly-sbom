package dev.cyberstamp.maven.assembly.sbom;

import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Merges an SBOM into a BOM by recognizing which of its components are copies
 * already there.
 *
 * <p>
 * An SBOM to merge describes some part of the target: a jar it was found in,
 * an unpacked WAR, the whole distribution. Merging it means
 * <em>anchoring</em> each of its components to the copy it describes,
 * enriching that copy with what the SBOM adds, and deciding by explicit rules
 * what to do with the components that describe no copy. Nothing is
 * reconciled by purl across the whole target, and nothing is renamed
 * afterwards: every source bom-ref is mapped, at the time it is merged, to
 * the target bom-ref of its copy ({@link Result#refMap()}), and the source's
 * own dependency edges are translated through that map.
 * </p>
 *
 * <h2>Anchoring</h2>
 * <p>
 * A source component anchors to a target copy:
 * </p>
 * <ol>
 * <li>by occurrence location, prefixed with the SBOM's {@link #rootOffset root
 * offset}, unless the two carry differing hashes of a common algorithm (the
 * SBOM then describes another build of that file);</li>
 * <li>else by content hash, at any depth of the target;</li>
 * <li>else, for a component without a location whose source parent anchored
 * to a binary (a jar or native binary, not an unpacked directory), by purl
 * among that binary's nested components: inside one binary, a purl names one
 * artifact;</li>
 * <li>else by purl among the direct children of its anchored source parent,
 * or of the merge parent (the top level, for a flat merge): a component never
 * holds two copies of one artifact side by side. Differing hashes then mean
 * another build of the same artifact, and the copy keeps its own;</li>
 * <li>else, when that parent is an unpacked archive, by purl among the
 * target's components with a location under the archive's directory (a file
 * of the archive the target lists elsewhere); such a copy is then placed
 * inside the archive's component.</li>
 * </ol>
 * <p>
 * The source's own main component stands for the {@link Scope#parent() merge
 * parent}. Dependency edges are never used to recognize components: they
 * describe artifacts as another tool resolved them, not copies.
 * </p>
 *
 * <h2>Components that do not anchor</h2>
 * <ul>
 * <li>a component without a location whose source parent anchored to a binary
 * is attributed to that binary and kept nested under its copy;</li>
 * <li>a component the {@link Scope#layout() layout} would show if it shipped
 * (a Maven package, a file, anything hashed in the layout's algorithm) but
 * does not show is dropped: the distribution does not ship it. One the
 * layout shows (at its location after the offset, or by hash) is kept: it
 * ships, the target just has no component for it;</li>
 * <li>anything else — a package that cannot be found as a file (e.g. an npm
 * package compiled into a JS bundle), or any component when there is no
 * layout (the target simply did not list it) — is kept under its anchored
 * source parent, or under the merge parent.</li>
 * </ul>
 * <p>
 * A kept component's occurrence locations and {@code file:} bom-ref are
 * prefixed with the root offset, and its bom-ref is made unique with
 * {@code #n} if taken.
 * </p>
 */
final class AnchoredMerge {

    private static final Logger log = LoggerFactory.getLogger(AnchoredMerge.class);
    private static final String FILE_REF_PREFIX = "file:";
    private static final String MAVEN_PURL_PREFIX = "pkg:maven/";

    /**
     * Where and how an SBOM is merged.
     *
     * @param parent the target copy the SBOM describes: the copy it was found
     *        in, or the target's main component for an SBOM of the whole
     *        assembly; never {@code null}
     * @param layout the distribution's files, which make "not anchored" mean
     *        "not shipped"; {@code null} when merging finished SBOMs with no
     *        distribution at hand
     * @param excluded source components that must not anchor, compared by
     *        identity (e.g. an external SBOM's claims the analyzer rejected)
     * @param shipped source components already known to ship, compared by
     *        identity: the analyzer matched them to archive files it then left
     *        out of the model and set their occurrences to those files'
     *        distribution paths, so they are kept as they are, with no root
     *        offset applied
     * @param nestUnderMain {@code true} to nest components kept under the
     *        target's main component in it (an explicit nested merge under
     *        it), {@code false} to make them top-level components
     */
    record Scope(Component parent, ArchiveIndex layout, Set<Component> excluded, Set<Component> shipped,
            boolean nestUnderMain) {

        /**
         * A scope that keeps the source's top-level components at the top
         * level when the parent is the target's main component (a flat merge).
         *
         * @param parent the target copy the SBOM describes, or the main
         *        component
         * @param layout the distribution's files, or {@code null}
         * @param excluded source components that must not anchor
         * @param shipped source components already known to ship
         */
        Scope(Component parent, ArchiveIndex layout, Set<Component> excluded, Set<Component> shipped) {
            this(parent, layout, excluded, shipped, false);
        }

        /**
         * A scope with nothing excluded and nothing known to ship.
         *
         * @param parent the target copy the SBOM describes
         * @param layout the distribution's files, or {@code null}
         * @return the scope
         */
        static Scope of(Component parent, ArchiveIndex layout) {
            return new Scope(parent, layout, Set.of(), Set.of());
        }
    }

    /**
     * The outcome of a merge.
     *
     * @param refMap the target bom-ref of every source component's anchored
     *        or kept copy, by its source bom-ref; dropped components are absent
     * @param anchored the number of source components anchored to a copy
     * @param kept the number of source components added to the target
     * @param dropped the number of source components dropped
     */
    record Result(Map<String, String> refMap, int anchored, int kept, int dropped) {
    }

    private final MergeTarget target;
    private final Scope scope;
    private final String offset;
    // the layout's view for hash checks: the merge parent's directory when it
    // is unpacked, so the same file shipped elsewhere does not count
    private final ArchiveIndex hashLayout;
    private final Map<String, String> refMap = new HashMap<>();
    // the target copy of every mapped target ref
    private final Map<String, Component> copiesByRef = new HashMap<>();
    // target refs a FILE copy gave up when it took a library's identity
    private final Map<String, String> renamedTargetRefs = new HashMap<>();
    private int anchored;
    private int kept;
    private int dropped;

    private AnchoredMerge(MergeTarget target, Scope scope, String offset) {
        this.target = target;
        this.scope = scope;
        this.offset = offset;
        String directory = directoryOf(scope.parent());
        this.hashLayout = scope.layout() == null || directory == null || directory.isEmpty() ? scope.layout()
                : scope.layout().scopedTo(directory);
    }

    /**
     * Merges {@code source} into {@code target}.
     *
     * <p>
     * The source BOM's components are consumed: kept ones are moved into the
     * target. Pass a copy if the source is used afterwards.
     * </p>
     *
     * @param target the BOM to merge into
     * @param source the SBOM to merge
     * @param scope where it is merged
     * @return the ref map and counts
     */
    static Result merge(Bom target, Bom source, Scope scope) {
        MergeTarget index = MergeTarget.of(target);
        String offset = rootOffset(source, index);
        if (offset.isEmpty()) {
            String directory = directoryOf(scope.parent());
            offset = directory == null ? "" : directory;
        }
        AnchoredMerge merge = new AnchoredMerge(index, scope, offset);
        merge.mergeComponents(source);
        merge.mergeSourceMain(source);
        merge.renameTargetRefs(target);
        merge.mergeDependencies(target, source);
        return new Result(merge.refMap, merge.anchored, merge.kept, merge.dropped);
    }

    /**
     * Derives where the SBOM's root sits in the target.
     *
     * <p>
     * An SBOM may manifest part of the target with locations relative to its
     * own root (e.g. a Quarkus application whose {@code lib/main/x.jar} is
     * the distribution's {@code lib/lib/main/x.jar}). The SBOM's main
     * component is anchored by hash, or failing that its first hashed and
     * located component; when that copy's location ends with the component's
     * own, the rest of it is the offset.
     * </p>
     *
     * @param source the SBOM to merge
     * @param target the indexed target
     * @return the prefix to put before the SBOM's locations, possibly empty
     */
    static String rootOffset(Bom source, MergeTarget target) {
        Component main = source.getMetadata() == null ? null : source.getMetadata().getComponent();
        String offset = offsetOf(main, target);
        if (offset != null) {
            return offset;
        }
        if (source.getComponents() != null) {
            for (Component c : source.getComponents()) {
                offset = offsetOf(c, target);
                if (offset != null) {
                    return offset;
                }
            }
        }
        return "";
    }

    /** The offset implied by one component anchored by hash, or {@code null}. */
    private static String offsetOf(Component c, MergeTarget target) {
        if (c == null || c.getHashes() == null) {
            return null;
        }
        String location = firstLocation(c);
        if (location == null) {
            return null;
        }
        for (Hash h : c.getHashes()) {
            Component copy = target.byHash(h);
            if (copy == null) {
                continue;
            }
            Evidence evidence = copy.getEvidence();
            if (evidence == null || evidence.getOccurrences() == null) {
                continue;
            }
            for (Occurrence o : evidence.getOccurrences()) {
                String loc = o.getLocation();
                if (loc != null && loc.endsWith(location)
                        && (loc.length() == location.length() || loc.charAt(loc.length() - location.length() - 1) == '/')) {
                    return loc.substring(0, loc.length() - location.length());
                }
            }
        }
        return null;
    }

    /** Walks the source's components, top level first. */
    private void mergeComponents(Bom source) {
        if (source.getComponents() == null) {
            return;
        }
        Component topParent = scope.parent() == target.main() ? null : scope.parent();
        boolean topParentIsBinary = topParent != null && isBinary(topParent);
        List<Component> ordered = new java.util.ArrayList<>(source.getComponents());
        ordered.sort(BomRenderer.COMPONENT_ORDER);
        for (Component c : ordered) {
            BomMerger.normalizePurls(c);
            walk(c, topParent, topParentIsBinary);
        }
    }

    /**
     * Maps the source's main component, after its components were merged:
     * an SBOM may list its main component among its components too (the
     * Quarkus SBOM does), in which case it maps to that component's copy.
     */
    private void mergeSourceMain(Bom source) {
        Component sourceMain = source.getMetadata() == null ? null : source.getMetadata().getComponent();
        if (sourceMain == null || sourceMain.getBomRef() == null) {
            return;
        }
        String listed = mapped(sourceMain.getBomRef());
        if (listed != null) {
            Component copy = copiesByRef.get(listed);
            if (copy != null && copy != target.main()) {
                enrich(copy, sourceMain);
            }
            return;
        }
        // The source's main component is the copy it describes: the merge
        // parent, or, in a flat merge, the copy it anchors to if it ships
        // in the target (e.g. a Quarkus application's quarkus-run.jar).
        Component copy = scope.parent();
        if (copy == target.main()) {
            Component anchoredMain = anchor(sourceMain, null, false);
            if (anchoredMain != null && anchoredMain != target.main()) {
                copy = anchoredMain;
            }
        }
        refMap.put(sourceMain.getBomRef(), copy.getBomRef());
        copiesByRef.put(copy.getBomRef(), copy);
        if (copy != target.main()) {
            enrich(copy, sourceMain);
        }
    }

    /**
     * Merges one source component and, recursively, its children.
     *
     * @param c the source component
     * @param anchoredParent the target copy of {@code c}'s source parent, or
     *        {@code null} at the source's top level of a flat merge
     * @param parentIsBinary whether {@code anchoredParent} is a binary whose
     *        nested components are shaded in it
     */
    private void walk(Component c, Component anchoredParent, boolean parentIsBinary) {
        List<Component> children = c.getComponents() == null ? List.of() : List.copyOf(c.getComponents());
        Component copy = anchor(c, anchoredParent, parentIsBinary);
        Component placedIn = anchoredParent != null ? anchoredParent : scope.parent();
        if (copy != null && copy != placedIn && placedIn != target.main() && !target.isWithin(copy, placedIn)) {
            copy = claimForParent(copy, c, placedIn);
            if (directoryOf(placedIn) != null && !target.isWithin(copy, placedIn)) {
                // an unpacked archive's content is its files: another copy of
                // the same artifact outside it (e.g. the same jar at the top
                // level, while the archive's own copy was excluded) is not this
                // one. A binary's SBOM may well name such a copy: identical
                // bytes elsewhere are that artifact.
                copy = null;
            }
        }
        if (copy != null) {
            enrich(copy, c);
            map(c, copy, copy.getBomRef());
            anchored++;
            boolean binary = isBinary(copy);
            for (Component child : children) {
                walk(child, copy, binary);
            }
            return;
        }
        Component keepUnder = placeOf(c, anchoredParent, parentIsBinary);
        if (keepUnder == null) {
            dropped++;
            log.debug("Not merging {}: the distribution has no matching file", c.getPurl());
            // its children are judged on their own, as children of its parent
            for (Component child : children) {
                walk(child, anchoredParent, parentIsBinary);
            }
            return;
        }
        c.setComponents(null);
        if (!scope.shipped().contains(c)) {
            prefixOccurrences(c);
        }
        String base = c.getBomRef() != null ? prefixFileRef(c.getBomRef())
                : c.getPurl() != null ? c.getPurl() : FILE_REF_PREFIX + offset + c.getName();
        String ref = target.claimRef(base);
        map(c, c, ref);
        c.setBomRef(ref);
        target.add(c, keepUnder, !scope.nestUnderMain());
        kept++;
        boolean binary = isBinary(c);
        for (Component child : children) {
            walk(child, c, binary);
        }
    }

    /**
     * Places a copy the SBOM puts inside {@code parent} but the target lists
     * elsewhere (e.g. a file of an unpacked WAR the analyzer could not
     * identify, listed at the top level). Only a copy whose location is under
     * the parent's directory is placed: the whole copy moves under the parent
     * when that is its only location; when it also stands for copies
     * elsewhere (a top-level component merged from several locations), the
     * source component becomes the parent's own copy at that location, with
     * the copy's identity evidence, and the location leaves the other copy.
     *
     * @return the copy to enrich, now within {@code parent}; or the original
     *         copy when it is not under the parent's directory
     */
    private Component claimForParent(Component copy, Component c, Component parent) {
        String directory = directoryOf(parent);
        if (directory == null || copy.getEvidence() == null || copy.getEvidence().getOccurrences() == null) {
            return copy;
        }
        List<Occurrence> occurrences = copy.getEvidence().getOccurrences();
        Occurrence inside = null;
        for (Occurrence o : occurrences) {
            if (o.getLocation() != null && o.getLocation().startsWith(directory)) {
                inside = o;
                break;
            }
        }
        if (inside == null) {
            return copy;
        }
        if (occurrences.size() == 1 || target.parentOf(copy) == parent) {
            if (target.parentOf(copy) != parent) {
                target.move(copy, parent);
            }
            return copy;
        }
        List<Occurrence> remaining = new java.util.ArrayList<>(occurrences.size() - 1);
        for (Occurrence o : occurrences) {
            if (o != inside) {
                remaining.add(o);
            }
        }
        copy.getEvidence().setOccurrences(remaining);
        List<Component> children = c.getComponents();
        c.setComponents(null);
        Evidence evidence = new Evidence();
        evidence.setOccurrences(new java.util.ArrayList<>(List.of(inside)));
        if (copy.getEvidence().getIdentities() != null) {
            evidence.setIdentities(copy.getEvidence().getIdentities());
        }
        c.setEvidence(evidence);
        if (c.getHashes() == null && copy.getHashes() != null) {
            c.setHashes(copy.getHashes());
        }
        if (c.getLicenses() == null) {
            c.setLicenses(copy.getLicenses());
        }
        c.setBomRef(target.claimRef(copy.getBomRef()));
        target.add(c, parent);
        c.setComponents(children);
        return c;
    }

    /** Finds the copy {@code c} describes, or {@code null} (see "Anchoring"). */
    private Component anchor(Component c, Component anchoredParent, boolean parentIsBinary) {
        if (scope.excluded().contains(c)) {
            return null;
        }
        boolean located = false;
        Evidence evidence = c.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                String loc = o.getLocation();
                if (loc == null || loc.isEmpty()) {
                    continue;
                }
                located = true;
                // locations are relative to the SBOM's root, which sits at the offset
                Component copy = target.byLocation(offset + loc);
                if (copy != null && !hashesConflict(copy, c)) {
                    return copy;
                }
            }
        }
        if (c.getHashes() != null) {
            for (Hash h : c.getHashes()) {
                Component copy = target.byHash(h);
                if (copy != null) {
                    return copy;
                }
            }
        }
        if (c.getPurl() == null) {
            return null;
        }
        if (!located && parentIsBinary && anchoredParent != null) {
            Component copy = target.byPurlWithin(anchoredParent, c.getPurl());
            if (copy != null) {
                return copy;
            }
        }
        Component sibling = target.byPurlAmongChildren(anchoredParent != null ? anchoredParent : scope.parent(),
                c.getPurl());
        // a hash conflict here means the source describes another build of
        // the same artifact; mergeHashes then keeps the copy's own hashes
        if (sibling != null) {
            return sibling;
        }
        String directory = directoryOf(anchoredParent != null ? anchoredParent : scope.parent());
        return directory == null ? null : target.byPurlUnderDirectory(c.getPurl(), directory);
    }

    /**
     * Decides where an unanchored component is kept (see "Components that do
     * not anchor").
     *
     * @return the component to nest it in (the target's main component for
     *         the top level), or {@code null} to drop it
     */
    private Component placeOf(Component c, Component anchoredParent, boolean parentIsBinary) {
        Component fallback = anchoredParent != null ? anchoredParent : scope.parent();
        if (scope.shipped().contains(c)) {
            return fallback;
        }
        if (firstLocation(c) == null && parentIsBinary && anchoredParent != null) {
            return anchoredParent;
        }
        ArchiveIndex layout = scope.layout();
        return layout != null && couldBeFound(c, layout) && !inLayout(c, layout) ? null : fallback;
    }

    /**
     * Whether the layout ships the component. An archive unpacked into the
     * distribution (a directory location, or the empty location marking the
     * SBOM's root) ships as its directory, never as the packed file its hash
     * describes. Otherwise its hash decides, when it has one in the layout's
     * algorithm (a file at its path with other content is another build);
     * else a file at one of its locations (after the offset).
     */
    private boolean inLayout(Component c, ArchiveIndex layout) {
        Evidence evidence = c.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                String loc = o.getLocation();
                if (loc != null && (loc.isEmpty() || loc.endsWith("/"))) {
                    String path = offset + loc;
                    return path.isEmpty() || layout.containsDirectory(path);
                }
            }
        }
        String hash = SbomUtils.extractHash(c, layout.normalizedAlg());
        if (hash != null) {
            return hashLayout.containsHash(hash);
        }
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                String loc = o.getLocation();
                if (loc != null && layout.containsPath(offset + loc)) {
                    return true;
                }
            }
        }
        String refPath = fileRefPath(c);
        return refPath != null && layout.containsPath(offset + refPath);
    }

    /**
     * Whether the layout would show a component if the distribution shipped
     * it: one carrying a hash in the layout's algorithm, or a Maven package or
     * a file with a location (an occurrence, or the path of a {@code file:}
     * bom-ref). Other packages (e.g. npm packages compiled into a JS bundle,
     * whose locations, if any, point into the source tree) cannot be found as
     * files, and a component with no location or hash cannot be looked up,
     * so not finding them proves nothing.
     */
    private static boolean couldBeFound(Component c, ArchiveIndex layout) {
        if (SbomUtils.extractHash(c, layout.normalizedAlg()) != null) {
            return true;
        }
        boolean fileOrMaven = c.getType() == Component.Type.FILE
                || (c.getPurl() != null && c.getPurl().startsWith(MAVEN_PURL_PREFIX));
        return fileOrMaven && (hasOccurrence(c) || fileRefPath(c) != null);
    }

    private static boolean hasOccurrence(Component c) {
        return c.getEvidence() != null && c.getEvidence().getOccurrences() != null
                && !c.getEvidence().getOccurrences().isEmpty();
    }

    /** The path a {@code file:} bom-ref names, or {@code null}. */
    private static String fileRefPath(Component c) {
        String ref = c.getBomRef();
        return ref != null && ref.startsWith(FILE_REF_PREFIX) ? ref.substring(FILE_REF_PREFIX.length()) : null;
    }

    /**
     * Adds what the source says about a copy: hashes it lacks (unless they
     * conflict), licenses if it has none, properties, external references and
     * identity evidence if it has none, and a description, publisher,
     * supplier or copyright it lacks. A file copy described by a package
     * takes the package's identity and keeps its location. The copy's
     * occurrences are its own and stay as they are.
     */
    private void enrich(Component copy, Component c) {
        BomMerger.mergeHashes(copy, c);
        if (copy.getLicenses() == null && c.getLicenses() != null) {
            copy.setLicenses(c.getLicenses());
        }
        if (copy.getDescription() == null) {
            copy.setDescription(c.getDescription());
        }
        if (copy.getPublisher() == null) {
            copy.setPublisher(c.getPublisher());
        }
        if (copy.getSupplier() == null) {
            copy.setSupplier(c.getSupplier());
        }
        if (copy.getCopyright() == null) {
            copy.setCopyright(c.getCopyright());
        }
        BomMerger.mergeProperties(copy, c);
        BomMerger.mergeExternalReferences(copy, c);
        Evidence sourceEvidence = c.getEvidence();
        if (sourceEvidence != null && sourceEvidence.getIdentities() != null
                && !sourceEvidence.getIdentities().isEmpty()) {
            Evidence evidence = copy.getEvidence();
            if (evidence == null) {
                evidence = new Evidence();
                copy.setEvidence(evidence);
            }
            if (evidence.getIdentities() == null || evidence.getIdentities().isEmpty()) {
                evidence.setIdentities(sourceEvidence.getIdentities());
            }
        }
        if (copy.getType() == Component.Type.FILE && c.getType() != Component.Type.FILE && c.getPurl() != null) {
            copy.setType(c.getType());
            copy.setGroup(c.getGroup());
            copy.setName(c.getName());
            copy.setVersion(c.getVersion());
            copy.setPurl(c.getPurl());
            String oldRef = copy.getBomRef();
            String newRef = target.claimRef(c.getPurl());
            copy.setBomRef(newRef);
            if (oldRef != null) {
                renamedTargetRefs.put(oldRef, newRef);
            }
        }
    }

    /**
     * Translates the source's dependency entries through the ref map: the
     * target entry of each mapped source component (created if absent, so a
     * copy whose dependencies were unknown learns them from the source) gains
     * every mapped child it does not list yet. A child that was dropped is
     * left out, and so is a self-reference two source components anchoring
     * to one copy would create, and a child whose copy is nested in the
     * parent's copy: containment is not a dependency.
     */
    private void mergeDependencies(Bom bom, Bom source) {
        if (source.getDependencies() == null || source.getDependencies().isEmpty()) {
            return;
        }
        Map<String, Dependency> entries = new HashMap<>();
        if (bom.getDependencies() != null) {
            for (Dependency d : bom.getDependencies()) {
                entries.putIfAbsent(d.getRef(), d);
            }
        }
        Map<Dependency, Set<String>> listed = new IdentityHashMap<>();
        for (Dependency d : source.getDependencies()) {
            String parent = mapped(d.getRef());
            if (parent == null) {
                continue;
            }
            Dependency entry = entries.get(parent);
            if (entry == null) {
                entry = new Dependency(parent);
                bom.addDependency(entry);
                entries.put(parent, entry);
            }
            if (d.getDependencies() == null) {
                continue;
            }
            Set<String> children = listed.computeIfAbsent(entry, AnchoredMerge::childRefs);
            Component parentCopy = copiesByRef.get(parent);
            for (Dependency child : d.getDependencies()) {
                String ref = mapped(child.getRef());
                if (ref == null || ref.equals(parent)) {
                    continue;
                }
                // containment is not a dependency: e.g. an SBOM listing what its
                // main component ships as its dependencies
                Component childCopy = copiesByRef.get(ref);
                if (parentCopy != null && childCopy != null && target.isWithin(childCopy, parentCopy)) {
                    continue;
                }
                if (children.add(ref)) {
                    entry.addDependency(new Dependency(ref));
                }
            }
        }
    }

    /** The target ref a source ref maps to, also trying its normalized Maven purl form. */
    private String mapped(String sourceRef) {
        if (sourceRef == null) {
            return null;
        }
        String ref = refMap.get(sourceRef);
        return ref != null ? ref : refMap.get(BomMerger.normalizeMavenPurl(sourceRef));
    }

    private static Set<String> childRefs(Dependency entry) {
        Set<String> refs = new HashSet<>();
        if (entry.getDependencies() != null) {
            for (Dependency child : entry.getDependencies()) {
                refs.add(child.getRef());
            }
        }
        return refs;
    }

    /**
     * Records the target copy of a source component, under the copy's ref
     * ({@code targetRef}; for a kept component, the ref it is about to get);
     * a source ref seen twice keeps its first copy.
     */
    private void map(Component c, Component copy, String targetRef) {
        copiesByRef.putIfAbsent(targetRef, copy);
        if (c.getBomRef() != null) {
            refMap.putIfAbsent(c.getBomRef(), targetRef);
        }
        if (c.getPurl() != null && !c.getPurl().equals(c.getBomRef())) {
            refMap.putIfAbsent(c.getPurl(), targetRef);
        }
    }

    /** Applies the refs file copies gave up to the target's dependency entries. */
    private void renameTargetRefs(Bom bom) {
        if (renamedTargetRefs.isEmpty() || bom.getDependencies() == null) {
            return;
        }
        List<Dependency> deps = bom.getDependencies();
        for (int i = 0; i < deps.size(); i++) {
            deps.set(i, renamed(deps.get(i)));
        }
    }

    /** The dependency with renamed refs ({@link Dependency} refs are immutable), or itself if none changes. */
    private Dependency renamed(Dependency dep) {
        String ref = renamedTargetRefs.getOrDefault(dep.getRef(), dep.getRef());
        List<Dependency> children = dep.getDependencies();
        boolean childRenamed = false;
        if (children != null) {
            for (Dependency child : children) {
                if (renamedTargetRefs.containsKey(child.getRef())) {
                    childRenamed = true;
                    break;
                }
            }
        }
        if (ref.equals(dep.getRef()) && !childRenamed) {
            return dep;
        }
        Dependency result = new Dependency(ref);
        if (children != null) {
            for (Dependency child : children) {
                result.addDependency(renamed(child));
            }
        }
        return result;
    }

    /** Whether two components carry different values for a common hash algorithm. */
    private static boolean hashesConflict(Component a, Component b) {
        if (a.getHashes() == null || b.getHashes() == null) {
            return false;
        }
        for (Hash ha : a.getHashes()) {
            if (ha.getAlgorithm() == null || ha.getValue() == null) {
                continue;
            }
            String alg = SbomUtils.normalizeAlgorithm(ha.getAlgorithm());
            for (Hash hb : b.getHashes()) {
                if (hb.getAlgorithm() != null && hb.getValue() != null
                        && alg.equals(SbomUtils.normalizeAlgorithm(hb.getAlgorithm()))
                        && !ha.getValue().equalsIgnoreCase(hb.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Whether a copy is a binary whose nested components are inside it (a jar,
     * a native binary), as opposed to an unpacked directory whose nested
     * components are files of their own.
     */
    private static boolean isBinary(Component copy) {
        return directoryOf(copy) == null && copy.getType() != Component.Type.APPLICATION;
    }

    /**
     * The directory an unpacked parent occupies: its directory occurrence, or
     * {@code ""} for an archive unpacked at the assembly root (marked by an
     * empty occurrence); {@code null} when the parent is not unpacked.
     */
    private static String directoryOf(Component parent) {
        Evidence evidence = parent.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                String loc = o.getLocation();
                if (loc != null && (loc.isEmpty() || loc.endsWith("/"))) {
                    return loc;
                }
            }
        }
        return null;
    }

    private void prefixOccurrences(Component c) {
        if (offset.isEmpty() || c.getEvidence() == null || c.getEvidence().getOccurrences() == null) {
            return;
        }
        // an empty location marks the SBOM's root (an archive unpacked
        // there), which sits at the offset
        for (Occurrence o : c.getEvidence().getOccurrences()) {
            if (o.getLocation() != null) {
                o.setLocation(offset + o.getLocation());
            }
        }
    }

    private String prefixFileRef(String ref) {
        if (offset.isEmpty() || !ref.startsWith(FILE_REF_PREFIX)) {
            return ref;
        }
        return FILE_REF_PREFIX + offset + ref.substring(FILE_REF_PREFIX.length());
    }

    private static String firstLocation(Component c) {
        Evidence evidence = c.getEvidence();
        if (evidence == null || evidence.getOccurrences() == null) {
            return null;
        }
        for (Occurrence o : evidence.getOccurrences()) {
            if (o.getLocation() != null && !o.getLocation().isEmpty()) {
                return o.getLocation();
            }
        }
        return null;
    }
}
