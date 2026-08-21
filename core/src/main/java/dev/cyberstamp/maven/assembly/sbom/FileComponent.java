package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;
import java.util.Objects;

/**
 * A plain file within the assembly that has no package identity.
 *
 * <p>
 * A file may still nest package components — for example a shaded or fat
 * JAR that could not be positively identified but whose embedded
 * {@code pom.properties} reveal bundled Maven artifacts.
 * </p>
 *
 * @param archivePath the path of the file within the assembly; never
 *        {@code null}
 * @param hash the content hash, or {@code null}
 * @param nested the nested components (defensively copied; {@code null}
 *        becomes empty)
 */
public record FileComponent(String archivePath, String hash, List<AssemblyComponent> nested)
        implements
            AssemblyComponent {

    public FileComponent {
        Objects.requireNonNull(archivePath, "archivePath");
        nested = nested == null ? List.of() : List.copyOf(nested);
    }

    /**
     * File components carry no license information.
     *
     * @return an empty list
     */
    @Override
    public List<LicenseInfo> licenses() {
        return List.of();
    }
}
