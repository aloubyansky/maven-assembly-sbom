package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * The BOM an SBOM is merged into, indexed for anchoring.
 *
 * <p>
 * Merging recognizes which of an incoming SBOM's components are copies
 * already in the target, so it looks components up by content hash, by
 * occurrence location and, inside a binary, by purl. This index answers those
 * lookups and is built once per merge, in one breadth-first
 * pass over the target (the main component, then the top-level components,
 * then nested ones level by level). Hash and location lookups are hash-map
 * reads; purl lookups among a parent's children use an index built on first
 * use per parent, and canonical purls are computed once per component. Where several components share a hash or
 * a location, the first one in that order wins, so a top-level copy is
 * preferred over a nested one.
 * </p>
 *
 * <p>
 * It also tracks the bom-refs in use, so components the merge adds get
 * unique ones ({@link #claimRef}), and it keeps the index current as
 * components are {@link #add added}. Components are tracked by identity:
 * CycloneDX components compare by value, and two copies of an artifact may
 * be equal.
 * </p>
 */
final class MergeTarget {

    private final Bom bom;
    private final Component main;
    private final Map<String, Component> byHash = new HashMap<>();
    // further components with a hash already in byHash, in index order (rare:
    // the same file shipped in several places)
    private final Map<String, List<Component>> moreByHash = new HashMap<>();
    // canonical purl of each component, computed once
    private final Map<Component, String> canonicalPurls = new IdentityHashMap<>();
    // children by canonical purl, per parent (TOP for the top level), built on first use
    private final Map<Object, Map<String, Component>> childrenByPurl = new IdentityHashMap<>();
    private static final Object TOP = new Object();
    private final Map<String, Component> byLocation = new HashMap<>();
    private final Map<Component, Component> parents = new IdentityHashMap<>();
    private final Set<String> takenRefs = new HashSet<>();
    // canonical purl -> components, built on first use
    private Map<String, List<Component>> byPurl;

    private MergeTarget(Bom bom) {
        this.bom = bom;
        this.main = bom.getMetadata() == null ? null : bom.getMetadata().getComponent();
    }

    /**
     * Indexes the given BOM: its main component, its top-level components and
     * every nested component, at any depth.
     *
     * @param target the BOM to merge into; it is updated by {@link #add}
     * @return the index
     */
    static MergeTarget of(Bom target) {
        MergeTarget index = new MergeTarget(target);
        List<Component> level = new ArrayList<>();
        if (index.main != null) {
            index.register(index.main, null);
            if (index.main.getComponents() != null) {
                for (Component c : index.main.getComponents()) {
                    index.parents.put(c, index.main);
                    level.add(c);
                }
            }
        }
        if (target.getComponents() != null) {
            level.addAll(target.getComponents());
        }
        index.indexLevels(level);
        return index;
    }

    /**
     * Returns the component carrying the given hash.
     *
     * @param hash a hash of an incoming component
     * @return the first component in index order with a hash of the same
     *         algorithm (compared normalized, e.g. {@code SHA-256} and
     *         {@code sha256}) and value (case-insensitive), or {@code null}
     */
    Component byHash(Hash hash) {
        String key = hashKey(hash);
        return key == null ? null : byHash.get(key);
    }

    /**
     * Returns the component carrying the given hash, preferring one within
     * the given context (e.g. the unpacked WAR an SBOM describes): the same
     * file may ship in several places, and each archive's own copy belongs
     * to it.
     *
     * @param hash a hash of an incoming component
     * @param context the component whose subtree to prefer, or {@code null}
     * @return the first such component within {@code context}, else the
     *         first in index order, or {@code null}
     */
    Component byHash(Hash hash, Component context) {
        String key = hashKey(hash);
        if (key == null) {
            return null;
        }
        Component first = byHash.get(key);
        if (first == null || context == null || isWithin(first, context)) {
            return first;
        }
        for (Component c : moreByHash.getOrDefault(key, List.of())) {
            if (isWithin(c, context)) {
                return c;
            }
        }
        return first;
    }

    /**
     * Returns the component with the given occurrence location.
     *
     * @param location a location relative to the target's root
     * @return the first component in index order with that exact
     *         occurrence location, or {@code null}
     */
    Component byLocation(String location) {
        return location == null ? null : byLocation.get(location);
    }

    /**
     * Returns the component with the given purl among a parent's descendants.
     *
     * <p>
     * Used for a component inside a binary (a dependency shaded in a jar),
     * which has no file of its own to match by: inside one binary, a purl
     * names one artifact. Purls are compared in canonical form
     * ({@link BomMerger#canonicalPurl}), so a redundant {@code ?type=jar} does
     * not prevent a match. The search covers the parent's subtree only, never
     * a copy nested elsewhere.
     * </p>
     *
     * @param parent the component whose descendants to search
     * @param purl the purl to look for
     * @return the first matching descendant, breadth-first, or {@code null}
     */
    Component byPurlWithin(Component parent, String purl) {
        String wanted = BomMerger.canonicalPurl(purl);
        if (wanted == null || parent.getComponents() == null) {
            return null;
        }
        List<Component> level = parent.getComponents();
        while (!level.isEmpty()) {
            List<Component> next = null;
            for (Component c : level) {
                if (wanted.equals(canonicalPurl(c))) {
                    return c;
                }
                if (c.getComponents() != null && !c.getComponents().isEmpty()) {
                    if (next == null) {
                        next = new ArrayList<>();
                    }
                    next.addAll(c.getComponents());
                }
            }
            level = next == null ? List.of() : next;
        }
        return null;
    }

    /**
     * Returns the component with the given purl among a parent's direct
     * children.
     *
     * <p>
     * A component never holds two copies of one artifact side by side (the
     * renderer merges top-level copies with one purl into one component), so
     * among one parent's children a purl names one copy. For the main
     * component, its children are the BOM's top-level components.
     * </p>
     *
     * @param parent the parent whose children to search; {@code null} or the
     *        main component for the top level
     * @param purl the purl to look for
     * @return the matching child, or {@code null}
     */
    Component byPurlAmongChildren(Component parent, String purl) {
        String wanted = BomMerger.canonicalPurl(purl);
        if (wanted == null) {
            return null;
        }
        Object key = parent == null || parent == main ? TOP : parent;
        Map<String, Component> index = childrenByPurl.get(key);
        if (index == null) {
            List<Component> children = key == TOP ? bom.getComponents() : parent.getComponents();
            index = new HashMap<>();
            if (children != null) {
                for (Component c : children) {
                    String p = canonicalPurl(c);
                    if (p != null) {
                        index.putIfAbsent(p, c);
                    }
                }
            }
            childrenByPurl.put(key, index);
        }
        return index.get(wanted);
    }

    /** The canonical purl of a component, computed once per component. */
    private String canonicalPurl(Component c) {
        if (c.getPurl() == null) {
            return null;
        }
        return canonicalPurls.computeIfAbsent(c, k -> BomMerger.canonicalPurl(k.getPurl()));
    }

    /** Keeps a parent's child purl index current when a child is attached to it. */
    private void indexChild(Component child, Component parent) {
        Map<String, Component> index = childrenByPurl.get(parent == null || parent == main ? TOP : parent);
        String p = canonicalPurl(child);
        if (index != null && p != null) {
            index.putIfAbsent(p, child);
        }
    }

    /** Removes a child from its parent's child purl index when it is moved away. */
    private void unindexChild(Component child, Component parent) {
        Map<String, Component> index = childrenByPurl.get(parent == null || parent == main ? TOP : parent);
        String p = canonicalPurl(child);
        if (index != null && p != null && index.get(p) == child) {
            index.remove(p);
        }
    }

    /**
     * Returns a component with the given purl that has an occurrence under a
     * directory, wherever the target lists it.
     *
     * <p>
     * Used when an SBOM of an unpacked archive describes a component the
     * target lists outside the archive's component, e.g. a file of an
     * unpacked WAR the analyzer could not identify: the purl and the location
     * under the archive's directory together name the copy.
     * </p>
     *
     * @param purl the purl to look for
     * @param directory a directory location ending with {@code /}
     * @return the first such component in index order, or {@code null}
     */
    Component byPurlUnderDirectory(String purl, String directory) {
        String wanted = BomMerger.canonicalPurl(purl);
        if (wanted == null) {
            return null;
        }
        if (byPurl == null) {
            byPurl = new HashMap<>();
            for (Component c : parents.keySet()) {
                indexPurl(c);
            }
            if (bom.getComponents() != null) {
                for (Component c : bom.getComponents()) {
                    indexPurl(c);
                }
            }
        }
        for (Component c : byPurl.getOrDefault(wanted, List.of())) {
            Evidence evidence = c.getEvidence();
            if (evidence != null && evidence.getOccurrences() != null) {
                for (Occurrence o : evidence.getOccurrences()) {
                    if (o.getLocation() != null && o.getLocation().startsWith(directory)) {
                        return c;
                    }
                }
            }
        }
        return null;
    }

    private void indexPurl(Component c) {
        String key = canonicalPurl(c);
        if (key != null) {
            List<Component> list = byPurl.computeIfAbsent(key, k -> new ArrayList<>(1));
            for (Component existing : list) {
                if (existing == c) {
                    return;
                }
            }
            list.add(c);
        }
    }

    /**
     * Returns the component a component is nested in.
     *
     * @param component an indexed component
     * @return its parent, the main component for a component nested in it,
     *         or {@code null} for a top-level component or the main one
     */
    Component parentOf(Component component) {
        return parents.get(component);
    }

    /**
     * Returns the target's main component.
     *
     * @return {@code metadata.component}, or {@code null} if there is none
     */
    Component main() {
        return main;
    }

    /**
     * Reserves a unique bom-ref for a component the merge adds.
     *
     * @param base the bom-ref the component would naturally have (its purl,
     *        or a {@code file:} ref)
     * @return {@code base} if no component uses it yet, otherwise
     *         {@code base#n} with the smallest free {@code n} from 2; the
     *         returned ref is marked as taken
     */
    String claimRef(String base) {
        if (takenRefs.add(base)) {
            return base;
        }
        int n = 2;
        String ref = base + '#' + n;
        while (!takenRefs.add(ref)) {
            ref = base + '#' + ++n;
        }
        return ref;
    }

    /**
     * Attaches a component the merge keeps and indexes it with its subtree.
     *
     * <p>
     * A component kept under the main component becomes a top-level
     * component of the BOM, the way the renderer lays a module's components
     * out. The component's bom-ref (and those of its descendants) should
     * already have been {@link #claimRef claimed}; it is marked as taken
     * either way.
     * </p>
     *
     * @param component the component to attach
     * @param parent the component to nest it in, or {@code null} or the main
     *        component for the top level
     */
    void add(Component component, Component parent) {
        add(component, parent, true);
    }

    /**
     * Like {@link #add(Component, Component)}, choosing what a component kept
     * under the main component becomes.
     *
     * @param mainChildrenAtTopLevel {@code true} to make a child of the main
     *        component a top-level component, {@code false} to nest it in the
     *        main component (an explicit nested merge under it)
     */
    void add(Component component, Component parent, boolean mainChildrenAtTopLevel) {
        indexChild(component, parent == null || (parent == main && mainChildrenAtTopLevel) ? null : parent);
        if (parent == null || (parent == main && mainChildrenAtTopLevel)) {
            if (bom.getComponents() == null) {
                bom.setComponents(new ArrayList<>());
            } else if (!(bom.getComponents() instanceof ArrayList)) {
                bom.setComponents(new ArrayList<>(bom.getComponents()));
            }
            bom.getComponents().add(component);
        } else {
            if (parent.getComponents() != null && !(parent.getComponents() instanceof ArrayList)) {
                parent.setComponents(new ArrayList<>(parent.getComponents()));
            }
            parent.addComponent(component);
            parents.put(component, parent);
        }
        List<Component> level = new ArrayList<>(1);
        level.add(component);
        indexLevels(level);
        if (byPurl != null) {
            indexSubtreePurls(component);
        }
    }

    private void indexSubtreePurls(Component c) {
        indexPurl(c);
        if (c.getComponents() != null) {
            for (Component child : c.getComponents()) {
                indexSubtreePurls(child);
            }
        }
    }

    /**
     * Moves a component, with its subtree, under another parent.
     *
     * @param component an indexed component
     * @param newParent the component to nest it in
     */
    void move(Component component, Component newParent) {
        Component oldParent = parents.get(component);
        unindexChild(component, oldParent);
        indexChild(component, newParent);
        if (newParent.getComponents() != null && !(newParent.getComponents() instanceof ArrayList)) {
            newParent.setComponents(new ArrayList<>(newParent.getComponents()));
        }
        List<Component> siblings = oldParent == null ? bom.getComponents() : oldParent.getComponents();
        if (siblings != null) {
            for (int i = 0; i < siblings.size(); i++) {
                if (siblings.get(i) == component) {
                    if (oldParent == null) {
                        bom.setComponents(withoutIndex(siblings, i));
                    } else {
                        oldParent.setComponents(withoutIndex(siblings, i));
                    }
                    break;
                }
            }
        }
        newParent.addComponent(component);
        parents.put(component, newParent);
    }

    /**
     * Makes {@code owner} the copy found at {@code location}, after the
     * occurrence moved to it from another copy (the index otherwise keeps
     * the first copy registered at a location).
     *
     * @param location an occurrence location of {@code owner}
     * @param owner an indexed component
     */
    void relocate(String location, Component owner) {
        if (location != null && !location.isEmpty()) {
            byLocation.put(location, owner);
        }
    }

    /** Whether {@code component} is {@code ancestor} or nested in it at any depth. */
    boolean isWithin(Component component, Component ancestor) {
        for (Component c = component; c != null; c = parents.get(c)) {
            if (c == ancestor) {
                return true;
            }
        }
        return false;
    }

    /** A modifiable copy of {@code list} without the element at {@code index} (lists may be unmodifiable). */
    private static List<Component> withoutIndex(List<Component> list, int index) {
        List<Component> result = new ArrayList<>(list.size() - 1);
        for (int i = 0; i < list.size(); i++) {
            if (i != index) {
                result.add(list.get(i));
            }
        }
        return result;
    }

    /** Indexes components level by level, starting with {@code level}. */
    private void indexLevels(List<Component> level) {
        while (!level.isEmpty()) {
            List<Component> next = null;
            for (Component c : level) {
                register(c, parents.get(c));
                List<Component> children = c.getComponents();
                if (children != null && !children.isEmpty()) {
                    if (next == null) {
                        next = new ArrayList<>();
                    }
                    for (Component child : children) {
                        parents.put(child, c);
                        next.add(child);
                    }
                }
            }
            level = next == null ? List.of() : next;
        }
    }

    /** Records one component's bom-ref, hashes and locations. */
    private void register(Component c, Component parent) {
        if (parent != null) {
            parents.put(c, parent);
        }
        if (c.getBomRef() != null) {
            takenRefs.add(c.getBomRef());
        }
        if (c.getHashes() != null) {
            for (Hash h : c.getHashes()) {
                String key = hashKey(h);
                if (key != null) {
                    Component existing = byHash.putIfAbsent(key, c);
                    if (existing != null && existing != c) {
                        moreByHash.computeIfAbsent(key, k -> new ArrayList<>(1)).add(c);
                    }
                }
            }
        }
        Evidence evidence = c.getEvidence();
        if (evidence != null && evidence.getOccurrences() != null) {
            for (Occurrence o : evidence.getOccurrences()) {
                if (o.getLocation() != null && !o.getLocation().isEmpty()) {
                    byLocation.putIfAbsent(o.getLocation(), c);
                }
            }
        }
    }

    /**
     * Returns the index key of a hash: its normalized algorithm and its
     * lower-cased value, or {@code null} if either is missing.
     */
    static String hashKey(Hash hash) {
        if (hash == null || hash.getAlgorithm() == null || hash.getValue() == null) {
            return null;
        }
        return SbomUtils.normalizeAlgorithm(hash.getAlgorithm()) + ':' + hash.getValue().toLowerCase();
    }
}
