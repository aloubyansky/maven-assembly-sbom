package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

/**
 * A node in the neutral SBOM component model.
 *
 * <p>
 * The hierarchy is cut on the <em>structural</em> axis only —
 * {@link PackageComponent} (has a package identity) versus
 * {@link FileComponent} (a plain file with no package identity). Ecosystem
 * (Maven, npm, generic, ...) is carried inside the {@link PackageRef} of a
 * {@link PackageComponent}, never by a distinct component subtype, so
 * transforms and renderers switch on structure, not ecosystem.
 * </p>
 *
 * <p>
 * This is the model's own component type and is unrelated to CycloneDX's
 * {@code org.cyclonedx.model.Component}; a renderer converts between them.
 * </p>
 */
public sealed interface AssemblyComponent permits PackageComponent, FileComponent {

    /**
     * Returns the licenses attached to this component.
     *
     * @return the licenses attached to this component; never {@code null}
     */
    List<LicenseInfo> licenses();

    /**
     * Returns the components nested under this one.
     *
     * @return the components nested under this one (shaded/bundled
     *         dependencies, assembled-jar contents); never {@code null}
     */
    List<AssemblyComponent> nested();

    /**
     * Indicates whether this component's dependencies are known.
     *
     * <p>
     * When {@code true} (the default), a component with no recorded
     * dependencies is understood to genuinely have none, and is rendered as an
     * empty leaf entry in the CycloneDX dependency graph. When {@code false},
     * the component's dependencies were never resolved, so it is omitted from
     * the dependency graph rather than misreporting "unknown" as "none".
     * Producers that record a flat inventory rather than a resolved dependency
     * tree should create components with this set to {@code false}.
     * </p>
     *
     * @return whether this component's dependencies are known
     */
    default boolean dependenciesKnown() {
        return true;
    }
}
