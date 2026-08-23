package dev.cyberstamp.maven.assembly.sbom;

/**
 * An ecosystem-neutral package identity whose canonical form is a
 * Package URL (purl).
 *
 * <p>
 * The {@link Purl} returned by {@link #toPurl()} is the single identity used
 * throughout the SBOM pipeline for deduplication, component indexing, and —
 * via its canonical {@link Purl#toString()} — CycloneDX {@code bom-ref}/
 * {@code purl} values. {@code Purl} has value-based {@code equals}/
 * {@code hashCode}, so it can be used directly as a map key. Every ecosystem
 * (Maven, npm, generic assembled artifacts, ...) is represented by an
 * implementation of this interface rather than by a distinct component type,
 * so structural code never switches on ecosystem.
 * </p>
 */
public interface PackageRef {

    /**
     * Returns the canonical Package URL for this reference, for example
     * {@code pkg:maven/org.example/foo@1.0?type=war}.
     *
     * @return the canonical purl; never {@code null}
     */
    Purl toPurl();
}
