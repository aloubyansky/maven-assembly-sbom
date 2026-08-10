package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Read-only view of a {@link Component} that pre-extracts the hash
 * value for a target algorithm and the occurrence locations. This
 * avoids repeated iteration over the component's hash and evidence
 * lists during archive matching and occurrence correction.
 *
 * <p>
 * Created once per component in
 * {@link SbomGenerator#filterSbomByArchive} and passed to
 * {@code matchesArchive} / {@code correctOccurrences} so that each
 * component's hashes and occurrences are walked exactly once.
 * </p>
 */
class ComponentView {

    private final Component component;
    private final String hash;
    private final List<String> locations;

    /**
     * @param component the CycloneDX component to wrap
     * @param normalizedAlg the normalized hash algorithm name
     *        (e.g. {@code "sha256"}) used to select which hash
     *        value to extract
     */
    ComponentView(Component component, String normalizedAlg) {
        this.component = component;
        this.hash = SbomUtils.extractHash(component, normalizedAlg);
        this.locations = extractLocations(component);
    }

    /** Returns the underlying CycloneDX component. */
    Component component() {
        return component;
    }

    /**
     * Returns the hash value for the target algorithm, or
     * {@code null} if the component has no hash of that algorithm.
     * The value is lowercased for consistent comparison.
     */
    String hash() {
        return hash;
    }

    /**
     * Returns {@code true} if the component declares a hash of the
     * target algorithm (whether or not it matches an archive entry).
     */
    boolean hasVerifiableHash() {
        return hash != null;
    }

    /**
     * Returns the pre-extracted occurrence location strings.
     * Never {@code null}; empty if the component has no occurrences.
     * May contain empty strings (used for empty-occurrence matching).
     */
    List<String> locations() {
        return locations;
    }

    /**
     * Returns {@code true} if the component has at least one
     * occurrence (including empty-string occurrences).
     */
    boolean hasOccurrences() {
        return !locations.isEmpty();
    }

    private static List<String> extractLocations(Component comp) {
        Evidence evidence = comp.getEvidence();
        if (evidence == null || evidence.getOccurrences() == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Occurrence occ : evidence.getOccurrences()) {
            String loc = occ.getLocation();
            if (loc != null) {
                result.add(loc);
            }
        }
        return result;
    }
}
