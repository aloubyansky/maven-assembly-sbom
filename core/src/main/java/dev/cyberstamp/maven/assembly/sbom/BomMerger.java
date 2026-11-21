package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Property;

/**
 * Merges or links external CycloneDX SBOMs into a target SBOM.
 *
 * <p>
 * This utility supports three integration modes:
 * </p>
 * <ul>
 * <li><b>Merge nested</b> ({@link #mergeUnder}) — merges the source BOM
 * as a description of one component of the target (e.g. the jar it was
 * found in).</li>
 * <li><b>Merge flat</b> ({@link #mergeFlat}) — merges the source BOM as a
 * description of the target as a whole.</li>
 * </ul>
 * <p>
 * Both merge by {@link AnchoredMerge anchoring}: each source component that
 * describes a component already in the target (same hash, same location
 * relative to the source's root, or, inside a binary, same purl) enriches
 * that component instead of being added; the others are added under the
 * merge parent with unique bom-refs, and the source's dependency edges are
 * carried across between the matching components. With no distribution at
 * hand, nothing is dropped: a component the target does not list may still
 * be part of it.
 * </p>
 * <ul>
 * <li><b>Link</b> ({@link #addBomReference}) — adds a CycloneDX
 * {@code externalReference} of type {@code bom} to a parent
 * component, pointing to the SBOM file's location within the
 * archive.</li>
 * </ul>
 */
public final class BomMerger {

    private static final Comparator<Component> COMPONENT_ORDER = BomRenderer.COMPONENT_ORDER;

    private BomMerger() {
    }

    /**
     * Merges the source BOM's components as nested sub-components
     * under the specified parent component in the target BOM.
     *
     * <p>
     * Source components are sorted by group/name/version and appended
     * to the parent's existing nested component list (if any).
     * Dependency entries from the source BOM are imported into the
     * target BOM's top-level dependency section. When the parent is
     * an unpacked archive (has a directory-style occurrence ending
     * with {@code '/'}), {@code file:} bom-refs on source components
     * and imported dependency refs are prefixed with the parent's
     * archive path to produce distribution-relative references.
     * </p>
     *
     * @param targetBom the distribution BOM to merge into
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param sourceBom the external BOM whose components to import
     */
    public static void mergeUnder(Bom targetBom, String parentBomRef, Bom sourceBom) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            throw new IllegalArgumentException(
                    "Cannot merge SBOM: parent component with bom-ref '"
                            + parentBomRef + "' not found");
        }
        AnchoredMerge.merge(targetBom, sourceBom,
                new AnchoredMerge.Scope(parent, null, java.util.Set.of(), java.util.Set.of(), true));
    }

    /**
     * Merges the source BOM's components into the target BOM's
     * top-level component list, and imports its dependency entries.
     *
     * @param targetBom the BOM to merge into
     * @param sourceBom the external BOM whose components to import
     */
    public static void mergeFlat(Bom targetBom, Bom sourceBom) {
        Component main = targetBom.getMetadata() == null ? null : targetBom.getMetadata().getComponent();
        if (main == null) {
            throw new IllegalArgumentException("Cannot merge SBOM: the target has no main component");
        }
        AnchoredMerge.merge(targetBom, sourceBom, AnchoredMerge.Scope.of(main, null));
    }

    /**
     * Adds a CycloneDX external reference of type {@code bom} to the
     * specified parent component, pointing to the given archive path.
     *
     * <p>
     * If the parent component cannot be found, a warning is logged
     * and no changes are made.
     * </p>
     *
     * @param targetBom the distribution BOM
     * @param parentBomRef the {@code bom-ref} of the parent component
     * @param bomPath the archive-internal path to the SBOM file
     */
    public static void addBomReference(Bom targetBom, String parentBomRef, String bomPath) {
        Component parent = findComponentByBomRef(targetBom, parentBomRef);
        if (parent == null) {
            throw new IllegalArgumentException(
                    "Cannot add BOM reference: parent component with bom-ref '"
                            + parentBomRef + "' not found");
        }
        ExternalReference ref = new ExternalReference();
        ref.setType(ExternalReference.Type.BOM);
        ref.setUrl(bomPath);
        parent.addExternalReference(ref);
    }

    private static final String FILE_BOMREF_PREFIX = "file:";

    /**
     * Normalizes a component's PURL and bom-ref in place by stripping
     * the redundant {@code ?type=jar} qualifier (jar is the PURL-spec
     * default for Maven). Recurses into sub-components.
     */
    static void normalizePurls(Component comp) {
        String purl = comp.getPurl();
        if (purl != null) {
            String normalized = normalizeMavenPurl(purl);
            if (!normalized.equals(purl)) {
                comp.setPurl(normalized);
                if (purl.equals(comp.getBomRef())) {
                    comp.setBomRef(normalized);
                }
            }
        }
        if (comp.getComponents() != null) {
            for (Component child : comp.getComponents()) {
                normalizePurls(child);
            }
        }
    }

    /**
     * Canonical dedup/index key for a purl or bom-ref string.
     *
     * <p>
     * Composes the existing Maven {@code type=jar} stripping with full
     * purl canonicalization (sorted qualifiers, lowercased npm name/type,
     * canonical percent-encoding) so semantically-equal npm/generic purls
     * that differ only in qualifier order or encoding dedup to one entry.
     * Maven behavior is unchanged: {@link #normalizeMavenPurl} strips
     * {@code type=jar} first, and {@link Purl#parse} is idempotent on the
     * canonical purls this codebase emits (see {@code ArtifactCoords.toPurl},
     * which omits {@code type=jar}). Unparseable strings fall back to the
     * Maven-normalized raw value, matching prior use-as-is behavior.
     * </p>
     */
    static String canonicalPurl(String purlOrRef) {
        if (purlOrRef == null) {
            return null;
        }
        String normalized = normalizeMavenPurl(purlOrRef);
        try {
            return Purl.parse(normalized).toString();
        } catch (IllegalArgumentException | NullPointerException e) {
            return normalized;
        }
    }

    /**
     * Strips the redundant {@code type=jar} qualifier from a Maven PURL
     * since {@code jar} is the default type per the PURL spec. Handles
     * the qualifier in any position ({@code ?type=jar}, {@code ?type=jar&…},
     * or {@code …&type=jar}). Non-Maven PURLs and PURLs with a non-jar
     * type are returned unchanged.
     */
    static String normalizeMavenPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:maven/")) {
            return purl;
        }
        int idx = purl.indexOf("type=jar");
        if (idx <= 0) {
            return purl;
        }
        char before = purl.charAt(idx - 1);
        if (before != '?' && before != '&') {
            return purl;
        }
        int end = idx + "type=jar".length();
        if (end < purl.length() && purl.charAt(end) != '&') {
            return purl;
        }
        if (end == purl.length()) {
            return purl.substring(0, idx - 1);
        }
        return purl.substring(0, idx) + purl.substring(end + 1);
    }

    /**
     * Merges hashes from the source component into the target,
     * adding any hash algorithms that the target does not already
     * have.
     *
     * <p>
     * When both components share a hash algorithm, the values are
     * compared. If any shared algorithm has a different value, all
     * source hashes are discarded — the mismatch indicates the
     * source may describe a different version of the artifact (e.g.
     * before shading or repackaging), so its hashes cannot be
     * trusted.
     * </p>
     */
    static void mergeHashes(Component target, Component source) {
        if (source.getHashes() == null || source.getHashes().isEmpty()) {
            return;
        }
        Map<String, String> existingByAlg = new HashMap<>();
        if (target.getHashes() != null) {
            for (Hash h : target.getHashes()) {
                existingByAlg.put(h.getAlgorithm(), h.getValue());
            }
        }
        for (Hash h : source.getHashes()) {
            String existingValue = existingByAlg.get(h.getAlgorithm());
            if (existingValue != null && !existingValue.equals(h.getValue())) {
                return;
            }
        }
        for (Hash h : source.getHashes()) {
            if (existingByAlg.putIfAbsent(h.getAlgorithm(), h.getValue()) == null) {
                target.addHash(h);
            }
        }
    }

    /**
     * Copies properties from the source component into the target,
     * skipping any property whose name already exists on the target.
     *
     * <p>
     * Deduplication uses the property name alone because CycloneDX
     * properties are key-value pairs where the name serves as the
     * unique key. When the same property name appears on both sides,
     * the target's value is preserved.
     * </p>
     *
     * @param target the component to merge properties into
     * @param source the component to copy properties from
     */
    static void mergeProperties(Component target, Component source) {
        if (source.getProperties() == null || source.getProperties().isEmpty()) {
            return;
        }
        if (target.getProperties() == null || target.getProperties().isEmpty()) {
            target.setProperties(new ArrayList<>(source.getProperties()));
            return;
        }
        Set<String> existing = new HashSet<>();
        for (Property p : target.getProperties()) {
            existing.add(p.getName());
        }
        for (Property p : source.getProperties()) {
            if (existing.add(p.getName())) {
                target.addProperty(p);
            }
        }
    }

    /**
     * Copies external references from the source component into the
     * target, skipping any reference that already exists on the target.
     *
     * <p>
     * Deduplication uses the combination of reference type and URL
     * because a component can legitimately have multiple references
     * of the same type (e.g. several {@code mailing-list} entries
     * pointing to different lists). The type alone is therefore not
     * sufficient as a dedup key; type plus URL uniquely identifies
     * a reference.
     * </p>
     *
     * @param target the component to merge external references into
     * @param source the component to copy external references from
     */
    static void mergeExternalReferences(Component target, Component source) {
        if (source.getExternalReferences() == null
                || source.getExternalReferences().isEmpty()) {
            return;
        }
        if (target.getExternalReferences() == null
                || target.getExternalReferences().isEmpty()) {
            target.setExternalReferences(
                    new ArrayList<>(source.getExternalReferences()));
            return;
        }
        Set<String> existing = new HashSet<>();
        for (ExternalReference ref : target.getExternalReferences()) {
            existing.add(ref.getType() + " " + ref.getUrl());
        }
        for (ExternalReference ref : source.getExternalReferences()) {
            if (existing.add(ref.getType() + " " + ref.getUrl())) {
                target.addExternalReference(ref);
            }
        }
    }

    static boolean hasOccurrences(Component component) {
        Evidence evidence = component.getEvidence();
        return evidence != null && evidence.getOccurrences() != null
                && !evidence.getOccurrences().isEmpty();
    }

    /**
     * Searches for a component by {@code bom-ref} in the target BOM.
     *
     * <p>
     * Checks the metadata component first, then top-level components,
     * then recursively searches nested component trees.
     * </p>
     *
     * @param bom the BOM to search
     * @param bomRef the {@code bom-ref} to match
     * @return the matching component, or {@code null} if not found
     */
    public static Component findComponentByBomRef(Bom bom, String bomRef) {
        if (bomRef == null) {
            return null;
        }
        String normalized = canonicalPurl(bomRef);
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component main = bom.getMetadata().getComponent();
            if (normalized.equals(canonicalPurl(main.getBomRef()))) {
                return main;
            }
        }
        return searchComponentTree(bom.getComponents(), normalized);
    }

    /**
     * Recursively searches a list of components and their children
     * for a matching {@code bom-ref}.
     */
    private static Component searchComponentTree(List<Component> components, String bomRef) {
        if (components == null) {
            return null;
        }
        for (Component comp : components) {
            if (bomRef.equals(canonicalPurl(comp.getBomRef()))) {
                return comp;
            }
            Component nested = searchComponentTree(comp.getComponents(), bomRef);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }
}
