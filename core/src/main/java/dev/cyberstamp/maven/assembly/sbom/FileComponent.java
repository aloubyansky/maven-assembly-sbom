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
 * @param id the id of this copy (see {@link AssemblyComponent#id()});
 *        {@code null} gets a {@link ComponentId#generate() generated} one
 */
public record FileComponent(String archivePath, String hash, List<AssemblyComponent> nested, ComponentId id)
        implements
            AssemblyComponent {

    /**
     * Requires a non-null {@code archivePath}, defensively copies the nested
     * list (a {@code null} list becomes empty) and generates an id when none
     * is given.
     */
    public FileComponent {
        Objects.requireNonNull(archivePath, "archivePath");
        nested = nested == null ? List.of() : List.copyOf(nested);
        if (id == null) {
            id = ComponentId.generate();
        }
    }

    /**
     * Creates a file component with a {@link ComponentId#generate() generated}
     * id.
     *
     * @param archivePath the path of the file within the assembly; never
     *        {@code null}
     * @param hash the content hash, or {@code null}
     * @param nested the nested components ({@code null} becomes empty)
     */
    public FileComponent(String archivePath, String hash, List<AssemblyComponent> nested) {
        this(archivePath, hash, nested, null);
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
