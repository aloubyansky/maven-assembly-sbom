package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;
import java.util.Objects;

/**
 * A component identified by a {@link PackageRef} (Maven, npm, generic, ...).
 *
 * @param ref the package identity; never {@code null}
 * @param archivePath the path of this component within the assembly, or
 *        {@code null} if not located in an archive
 * @param hash the content hash, or {@code null}
 * @param licenses the attached licenses (defensively copied; {@code null}
 *        becomes empty)
 * @param nested the nested components (defensively copied; {@code null}
 *        becomes empty)
 * @param dependenciesKnown whether this component's dependencies are known
 *        (see {@link AssemblyComponent#dependenciesKnown()})
 */
public record PackageComponent(PackageRef ref, String archivePath, String hash,
        List<LicenseInfo> licenses, List<AssemblyComponent> nested, boolean dependenciesKnown)
        implements
            AssemblyComponent {

    /**
     * Requires a non-null {@code ref} and defensively copies the license and
     * nested lists (a {@code null} list becomes empty).
     */
    public PackageComponent {
        Objects.requireNonNull(ref, "ref");
        licenses = licenses == null ? List.of() : List.copyOf(licenses);
        nested = nested == null ? List.of() : List.copyOf(nested);
    }

    /**
     * Backward-compatible constructor that assumes the component's dependencies
     * are known.
     *
     * @param ref the package identity; never {@code null}
     * @param archivePath the path within the assembly, or {@code null}
     * @param hash the content hash, or {@code null}
     * @param licenses the attached licenses ({@code null} becomes empty)
     * @param nested the nested components ({@code null} becomes empty)
     */
    public PackageComponent(PackageRef ref, String archivePath, String hash,
            List<LicenseInfo> licenses, List<AssemblyComponent> nested) {
        this(ref, archivePath, hash, licenses, nested, true);
    }

    /**
     * Creates a package component with no licenses and no nested components
     * whose dependencies are assumed known.
     *
     * @param ref the package identity
     * @param archivePath the path within the assembly, or {@code null}
     * @param hash the content hash, or {@code null}
     * @return a new {@link PackageComponent}
     */
    public static PackageComponent of(PackageRef ref, String archivePath, String hash) {
        return new PackageComponent(ref, archivePath, hash, List.of(), List.of(), true);
    }

    /**
     * Creates a package component with no licenses and no nested components,
     * declaring whether its dependencies are known.
     *
     * @param ref the package identity
     * @param archivePath the path within the assembly, or {@code null}
     * @param hash the content hash, or {@code null}
     * @param dependenciesKnown whether this component's dependencies are known
     * @return a new {@link PackageComponent}
     */
    public static PackageComponent of(PackageRef ref, String archivePath, String hash,
            boolean dependenciesKnown) {
        return new PackageComponent(ref, archivePath, hash, List.of(), List.of(), dependenciesKnown);
    }

    /**
     * Returns a copy of this component with the given licenses, preserving all
     * other attributes (including {@link #dependenciesKnown()}).
     *
     * @param licenses the licenses to attach
     * @return this component, or a copy with the given licenses
     */
    public PackageComponent withLicenses(List<LicenseInfo> licenses) {
        if (sameOrBothEmpty(licenses, this.licenses)) {
            return this;
        }
        return new PackageComponent(ref, archivePath, hash, licenses, nested, dependenciesKnown);
    }

    /**
     * Returns a copy of this component with the given nested components,
     * preserving all other attributes (including {@link #dependenciesKnown()}).
     *
     * @param nested the nested components
     * @return this component, or a copy with the given nested components
     */
    public PackageComponent withNested(List<AssemblyComponent> nested) {
        if (sameOrBothEmpty(nested, this.nested)) {
            return this;
        }
        return new PackageComponent(ref, archivePath, hash, licenses, nested, dependenciesKnown);
    }

    /**
     * Returns {@code true} when replacing {@code current} with {@code candidate}
     * would be a no-op: they are the same list instance, or both are empty
     * ({@code candidate} may be {@code null}). {@code current} is always a
     * non-null (possibly empty) list produced by the canonical constructor.
     *
     * @param candidate the replacement list, possibly {@code null}
     * @param current the current (non-null) list
     * @return {@code true} if replacing {@code current} with {@code candidate}
     *         would leave the component unchanged
     */
    private static boolean sameOrBothEmpty(List<?> candidate, List<?> current) {
        return candidate == current || ((candidate == null || candidate.isEmpty()) && current.isEmpty());
    }
}
