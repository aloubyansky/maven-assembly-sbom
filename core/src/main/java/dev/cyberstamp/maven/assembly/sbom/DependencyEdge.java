package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * A directed dependency from one component copy to another, identified by
 * their {@link ComponentId}s.
 *
 * <p>
 * An edge names <em>copies</em>, not artifacts: when an artifact ships more
 * than once (at the top level and inside a WAR, or bundled in a shaded jar),
 * each copy is its own {@link AssemblyComponent} with its own id, and an edge
 * says exactly which copy depends on which. The producer records an edge
 * where it knows both ends, e.g. from the module's own Maven resolution,
 * which connects the copies that resolution placed in the assembly.
 * </p>
 *
 * <p>
 * <strong>Contract:</strong> containment is not a dependency. A component's
 * {@link AssemblyComponent#nested() nested} components are expressed by
 * nesting alone; producers must not add an edge from a parent to a copy
 * merely because it is nested in it. An edge whose id names no component in
 * the model is ignored by {@link BomRenderer}.
 * </p>
 *
 * @param parent the id of the depending copy; never {@code null}
 * @param child the id of the depended-upon copy; never {@code null}
 */
public record DependencyEdge(ComponentId parent, ComponentId child) {

    /**
     * Requires non-null {@code parent} and {@code child}.
     */
    public DependencyEdge {
        Objects.requireNonNull(parent, "parent");
        Objects.requireNonNull(child, "child");
    }
}
