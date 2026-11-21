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
 * lookups in constant time and is built once per merge, in one breadth-first
 * pass over the target (the main component, then the top-level components,
 * then nested ones level by level). Where several components share a hash or
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
    private final Map<String, Component> byLocation = new HashMap<>();
    private final Map<Component, Component> parents = new IdentityHashMap<>();
    private final Set<String> takenRefs = new HashSet<>();

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
                if (wanted.equals(BomMerger.canonicalPurl(c.getPurl()))) {
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
        if (parent == null || parent == main) {
            if (bom.getComponents() == null) {
                bom.setComponents(new ArrayList<>());
            }
            bom.getComponents().add(component);
        } else {
            parent.addComponent(component);
            parents.put(component, parent);
        }
        List<Component> level = new ArrayList<>(1);
        level.add(component);
        indexLevels(level);
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
                    byHash.putIfAbsent(key, c);
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
