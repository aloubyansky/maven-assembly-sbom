package io.github.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;

/**
 * Mutable, indexed wrapper around a CycloneDX dependency list.
 *
 * <p>
 * On construction the wrapper ensures the underlying list is mutable.
 * For {@link Bom}, {@code setDependencies()} copies into an internal
 * {@code DependencyList} (CycloneDX's own, extends {@link ArrayList}),
 * so after setting we re-read via {@code getDependencies()} to hold
 * the actual internal reference. For {@link Dependency} children,
 * the setter is a direct assignment.
 * </p>
 */
final class DependencyList implements Iterable<Dependency> {

    private final List<Dependency> list;
    private Map<String, Dependency> refIndex;

    private DependencyList(List<Dependency> list) {
        this.list = list;
    }

    static DependencyList of(Bom bom) {
        List<Dependency> raw = bom.getDependencies();
        if (raw == null) {
            bom.setDependencies(new ArrayList<>());
            return new DependencyList(bom.getDependencies());
        }
        if (!(raw instanceof ArrayList)) {
            bom.setDependencies(new ArrayList<>(raw));
            return new DependencyList(bom.getDependencies());
        }
        return new DependencyList(raw);
    }

    static DependencyList ofChildren(Dependency dep) {
        List<Dependency> raw = dep.getDependencies();
        if (raw == null) {
            List<Dependency> mutable = new ArrayList<>();
            dep.setDependencies(mutable);
            return new DependencyList(mutable);
        }
        if (!(raw instanceof ArrayList)) {
            List<Dependency> mutable = new ArrayList<>(raw);
            dep.setDependencies(mutable);
            return new DependencyList(mutable);
        }
        return new DependencyList(raw);
    }

    Dependency findByRef(String ref) {
        if (ref == null) {
            return null;
        }
        return refIndex().get(BomMerger.normalizeMavenPurl(ref));
    }

    boolean containsRef(String ref) {
        return findByRef(ref) != null;
    }

    void add(Dependency dep) {
        list.add(dep);
        if (refIndex != null) {
            indexRef(dep);
        }
    }

    boolean remove(Dependency dep) {
        boolean removed = list.remove(dep);
        if (removed && refIndex != null) {
            removeRef(dep);
        }
        return removed;
    }

    void removeIf(Predicate<Dependency> filter) {
        boolean changed = false;
        Iterator<Dependency> it = list.iterator();
        while (it.hasNext()) {
            if (filter.test(it.next())) {
                it.remove();
                changed = true;
            }
        }
        if (changed) {
            refIndex = null;
        }
    }

    void removeByRefs(Set<String> refs) {
        removeIf(d -> refs.contains(d.getRef()));
    }

    boolean isEmpty() {
        return list.isEmpty();
    }

    int size() {
        return list.size();
    }

    Stream<Dependency> stream() {
        return list.stream();
    }

    @Override
    public Iterator<Dependency> iterator() {
        return list.iterator();
    }

    private Map<String, Dependency> refIndex() {
        if (refIndex == null) {
            refIndex = new HashMap<>(list.size());
            for (Dependency dep : list) {
                indexRef(dep);
            }
        }
        return refIndex;
    }

    private void indexRef(Dependency dep) {
        String ref = dep.getRef();
        if (ref != null) {
            refIndex.put(BomMerger.normalizeMavenPurl(ref), dep);
        }
    }

    private void removeRef(Dependency dep) {
        String ref = dep.getRef();
        if (ref != null) {
            refIndex.remove(BomMerger.normalizeMavenPurl(ref));
        }
    }
}
