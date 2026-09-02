package dev.cyberstamp.maven.assembly.sbom;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A model transform that detects shaded (bundled) Maven artifacts inside a
 * {@link PackageComponent}'s own JAR and surfaces them as nested components.
 *
 * <p>
 * A shaded JAR (for example {@code angus-mail}, which bundles
 * {@code angus-core}) carries more than one {@code META-INF/maven/&#42;/
 * pom.properties}. For each top-level Maven {@link PackageComponent} whose
 * artifact can be located, this transform reads those descriptors (via
 * {@link BundledArtifactScanner}) and nests every non-owner artifact under the
 * component (with no dependency edge — containment is expressed by nesting).
 * Components already carrying that nested artifact are left untouched.
 * </p>
 *
 * <p>
 * The artifact for a component is obtained through a pluggable
 * {@link JarLocator}, so producers with different artifact-access mechanisms
 * (the assembly plugin's resolved artifacts, Galleon's stashed resolution
 * paths) can share this one detector.
 * </p>
 */
public final class ShadedJarDetection {

    /**
     * Locates the local artifact file (a JAR, or an exploded directory) for a
     * package, so its contents can be scanned for bundled artifacts.
     */
    @FunctionalInterface
    public interface JarLocator {
        /**
         * Locates the local artifact for the given coordinates.
         *
         * @param coords the Maven coordinates of the component
         * @return the local artifact path, or {@code null} if it cannot be located
         */
        Path locate(ArtifactCoords coords);
    }

    private final JarLocator locator;

    /**
     * Creates a detector that locates artifacts via the given locator.
     *
     * @param locator locates the artifact file for a component's coordinates
     */
    public ShadedJarDetection(JarLocator locator) {
        this.locator = locator;
    }

    /**
     * Detects shaded artifacts in every top-level Maven package component and
     * nests them, rebuilding the immutable component records in place.
     *
     * @param model the model to transform; its component list is replaced
     */
    public void apply(AssemblyComponents model) {
        List<AssemblyComponent> result = new ArrayList<>(model.components().size());
        for (AssemblyComponent comp : model.components()) {
            result.add(detect(comp));
        }
        model.setComponents(result);
    }

    private AssemblyComponent detect(AssemblyComponent comp) {
        if (!(comp instanceof PackageComponent pkg)
                || !(pkg.ref() instanceof ArtifactCoords owner)) {
            return comp;
        }
        Path jar = locator.locate(owner);
        if (jar == null) {
            return comp;
        }
        List<ArtifactCoords> bundled = BundledArtifactScanner.bundledNonOwner(jar, owner);
        if (bundled.isEmpty()) {
            return comp;
        }
        Set<String> existing = new HashSet<>();
        for (AssemblyComponent nested : pkg.nested()) {
            if (nested instanceof PackageComponent nestedPkg) {
                existing.add(nestedPkg.ref().toPurl().toString());
            }
        }
        List<AssemblyComponent> nested = new ArrayList<>(pkg.nested());
        for (ArtifactCoords coords : bundled) {
            if (existing.add(coords.toPurl().toString())) {
                // Bundled artifacts are discovered from embedded pom.properties;
                // their transitive dependencies are not resolved, so they are
                // marked as having unknown dependencies (not an empty leaf).
                nested.add(PackageComponent.of(coords, null, null, false));
            }
        }
        return pkg.withNested(nested);
    }
}
