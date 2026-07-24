package io.github.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;

/**
 * Mutable, indexed wrapper around a CycloneDX component list.
 *
 * <p>
 * On construction the wrapper ensures the underlying list is a mutable
 * {@link ArrayList} and writes it back to the owner ({@link Bom} or
 * {@link Component}) so that all subsequent mutations are visible
 * without further syncing. Null lists from the owner are treated as
 * empty.
 * </p>
 *
 * <p>
 * Indexed lookups by PURL and bom-ref are lazy-built on first access
 * and kept in sync by mutations through this wrapper.
 * </p>
 */
final class ComponentList implements Iterable<Component> {

    private final List<Component> list;
    private Map<String, Component> purlIndex;
    private Map<String, Component> bomRefIndex;

    private ComponentList(List<Component> list) {
        this.list = list;
    }

    static ComponentList of(Bom bom) {
        List<Component> raw = bom.getComponents();
        List<Component> mutable = ensureMutable(raw);
        if (mutable != raw) {
            bom.setComponents(mutable);
        }
        return new ComponentList(mutable);
    }

    static ComponentList ofNested(Component component) {
        List<Component> raw = component.getComponents();
        List<Component> mutable = ensureMutable(raw);
        if (mutable != raw) {
            component.setComponents(mutable);
        }
        return new ComponentList(mutable);
    }

    Component findByPurl(String purl) {
        if (purl == null) {
            return null;
        }
        return purlIndex().get(BomMerger.normalizeMavenPurl(purl));
    }

    Component findByBomRef(String bomRef) {
        if (bomRef == null) {
            return null;
        }
        return bomRefIndex().get(BomMerger.normalizeMavenPurl(bomRef));
    }

    boolean containsPurl(String purl) {
        return findByPurl(purl) != null;
    }

    boolean containsBomRef(String bomRef) {
        return findByBomRef(bomRef) != null;
    }

    void add(Component comp) {
        list.add(comp);
        if (purlIndex != null) {
            indexPurl(comp);
        }
        if (bomRefIndex != null) {
            indexBomRef(comp);
        }
    }

    boolean remove(Component comp) {
        boolean removed = list.remove(comp);
        if (removed) {
            if (purlIndex != null) {
                removePurl(comp);
            }
            if (bomRefIndex != null) {
                removeBomRef(comp);
            }
        }
        return removed;
    }

    List<Component> removeIf(Predicate<Component> filter) {
        List<Component> removed = new ArrayList<>();
        Iterator<Component> it = list.iterator();
        while (it.hasNext()) {
            Component comp = it.next();
            if (filter.test(comp)) {
                it.remove();
                removed.add(comp);
            }
        }
        if (!removed.isEmpty()) {
            invalidateIndices();
        }
        return removed;
    }

    boolean isEmpty() {
        return list.isEmpty();
    }

    int size() {
        return list.size();
    }

    Stream<Component> stream() {
        return list.stream();
    }

    @Override
    public Iterator<Component> iterator() {
        return list.iterator();
    }

    List<Component> sorted(Comparator<Component> comparator) {
        List<Component> copy = new ArrayList<>(list);
        copy.sort(comparator);
        return copy;
    }

    private Map<String, Component> purlIndex() {
        if (purlIndex == null) {
            purlIndex = new HashMap<>(list.size());
            for (Component comp : list) {
                indexPurl(comp);
            }
        }
        return purlIndex;
    }

    private Map<String, Component> bomRefIndex() {
        if (bomRefIndex == null) {
            bomRefIndex = new HashMap<>(list.size());
            for (Component comp : list) {
                indexBomRef(comp);
            }
        }
        return bomRefIndex;
    }

    private void indexPurl(Component comp) {
        String purl = comp.getPurl();
        if (purl != null) {
            purlIndex.put(BomMerger.normalizeMavenPurl(purl), comp);
        }
    }

    private void indexBomRef(Component comp) {
        String ref = comp.getBomRef();
        if (ref != null) {
            bomRefIndex.put(BomMerger.normalizeMavenPurl(ref), comp);
        }
    }

    private void removePurl(Component comp) {
        String purl = comp.getPurl();
        if (purl != null) {
            purlIndex.remove(BomMerger.normalizeMavenPurl(purl));
        }
    }

    private void removeBomRef(Component comp) {
        String ref = comp.getBomRef();
        if (ref != null) {
            bomRefIndex.remove(BomMerger.normalizeMavenPurl(ref));
        }
    }

    private void invalidateIndices() {
        purlIndex = null;
        bomRefIndex = null;
    }

    private static List<Component> ensureMutable(List<Component> list) {
        if (list == null) {
            return new ArrayList<>();
        }
        if (list instanceof ArrayList) {
            return list;
        }
        return new ArrayList<>(list);
    }
}
