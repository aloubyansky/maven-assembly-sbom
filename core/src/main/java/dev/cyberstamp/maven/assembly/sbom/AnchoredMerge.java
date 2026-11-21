package dev.cyberstamp.maven.assembly.sbom;

import java.util.HashMap;
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
 * artifact.</li>
 * </ol>
 * <p>
 * The source's own main component stands for the {@link Scope#parent() merge
 * parent}. Dependency edges are never used to recognize components: they
 * describe artifacts as another tool resolved them, not copies.
 * </p>
 *
 * <h2>Components that do not anchor</h2>
 * <ul>
 * <li>a package that cannot exist as a file (not {@code pkg:maven}, no
 * location — e.g. an npm package compiled into a JS bundle) is kept under its
 * anchored source parent, or under the merge parent;</li>
 * <li>a component without a location whose source parent anchored to a binary
 * is attributed to that binary and kept nested under its copy;</li>
 * <li>anything else is dropped when a {@link Scope#layout() layout} is given
 * (the distribution does not ship it), and kept under its anchored source
 * parent or the merge parent when not (the target simply did not list
 * it).</li>
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
     */
    record Scope(Component parent, ArchiveIndex layout, Set<Component> excluded) {
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
    private final Map<String, String> refMap = new HashMap<>();
    // target refs a FILE copy gave up when it took a library's identity
    private final Map<String, String> renamedTargetRefs = new HashMap<>();
    private int anchored;
    private int kept;
    private int dropped;

    private AnchoredMerge(MergeTarget target, Scope scope, String offset) {
        this.target = target;
        this.scope = scope;
        this.offset = offset;
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
            offset = directoryOf(scope.parent());
        }
        AnchoredMerge merge = new AnchoredMerge(index, scope, offset);
        merge.mergeComponents(source);
        merge.renameTargetRefs(target);
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
        Component sourceMain = source.getMetadata() == null ? null : source.getMetadata().getComponent();
        if (sourceMain != null && sourceMain.getBomRef() != null) {
            refMap.put(sourceMain.getBomRef(), scope.parent().getBomRef());
            if (scope.parent() != target.main()) {
                enrich(scope.parent(), sourceMain);
            }
        }
        if (source.getComponents() == null) {
            return;
        }
        Component topParent = scope.parent() == target.main() ? null : scope.parent();
        boolean topParentIsBinary = topParent != null && isBinary(topParent);
        for (Component c : List.copyOf(source.getComponents())) {
            BomMerger.normalizePurls(c);
            walk(c, topParent, topParentIsBinary);
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
        if (copy != null) {
            enrich(copy, c);
            map(c, copy.getBomRef());
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
        prefixOccurrences(c);
        String base = c.getBomRef() != null ? prefixFileRef(c.getBomRef())
                : c.getPurl() != null ? c.getPurl() : FILE_REF_PREFIX + offset + c.getName();
        String ref = target.claimRef(base);
        map(c, ref);
        c.setBomRef(ref);
        target.add(c, keepUnder);
        kept++;
        boolean binary = isBinary(c);
        for (Component child : children) {
            walk(child, c, binary);
        }
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
        if (!located && parentIsBinary && anchoredParent != null && c.getPurl() != null) {
            return target.byPurlWithin(anchoredParent, c.getPurl());
        }
        return null;
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
        boolean located = firstLocation(c) != null;
        boolean maven = c.getPurl() != null && c.getPurl().startsWith(MAVEN_PURL_PREFIX);
        if (!located && c.getType() != Component.Type.FILE && !maven) {
            return fallback;
        }
        if (!located && parentIsBinary && anchoredParent != null) {
            return anchoredParent;
        }
        return scope.layout() != null ? null : fallback;
    }

    /**
     * Adds what the source says about a copy: hashes it lacks (unless they
     * conflict), licenses if it has none, properties, external references and
     * identity evidence if it has none. A file copy described by a package
     * takes the package's identity and keeps its location. The copy's
     * occurrences are its own and stay as they are.
     */
    private void enrich(Component copy, Component c) {
        BomMerger.mergeHashes(copy, c);
        if (copy.getLicenses() == null && c.getLicenses() != null) {
            copy.setLicenses(c.getLicenses());
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

    /** Records the target ref of a source component; a ref seen twice keeps its first copy. */
    private void map(Component c, String targetRef) {
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
        Evidence evidence = copy.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                if (o.getLocation() != null && o.getLocation().endsWith("/")) {
                    return false;
                }
            }
        }
        return copy.getType() != Component.Type.APPLICATION;
    }

    /** The directory occurrence of an unpacked parent, or "". */
    private static String directoryOf(Component parent) {
        Evidence evidence = parent.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                if (o.getLocation() != null && o.getLocation().endsWith("/")) {
                    return o.getLocation();
                }
            }
        }
        return "";
    }

    private void prefixOccurrences(Component c) {
        if (offset.isEmpty() || c.getEvidence() == null || c.getEvidence().getOccurrences() == null) {
            return;
        }
        for (Occurrence o : c.getEvidence().getOccurrences()) {
            String loc = o.getLocation();
            if (loc != null && !loc.isEmpty()) {
                o.setLocation(offset + loc);
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
