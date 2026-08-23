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
 */
public record PackageComponent(PackageRef ref, String archivePath, String hash,
        List<LicenseInfo> licenses, List<AssemblyComponent> nested) implements AssemblyComponent {

    public PackageComponent {
        Objects.requireNonNull(ref, "ref");
        licenses = licenses == null ? List.of() : List.copyOf(licenses);
        nested = nested == null ? List.of() : List.copyOf(nested);
    }

    /**
     * Creates a package component with no licenses and no nested
     * components.
     *
     * @param ref the package identity
     * @param archivePath the path within the assembly, or {@code null}
     * @param hash the content hash, or {@code null}
     * @return a new {@link PackageComponent}
     */
    public static PackageComponent of(PackageRef ref, String archivePath, String hash) {
        return new PackageComponent(ref, archivePath, hash, List.of(), List.of());
    }
}
