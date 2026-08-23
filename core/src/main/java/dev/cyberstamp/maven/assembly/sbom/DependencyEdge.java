package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * A directed dependency relationship between two components, identified by
 * their {@link PackageRef}s.
 *
 * <p>
 * <strong>Contract:</strong> Edges from Maven dependency resolution must not
 * reference a component already in the parent's {@code nested()} list.
 * Containment is expressed via nesting, not dependency edges. The renderer
 * filters out such inferred edges to avoid duplicate parent-child relationships.
 * However, explicit edges ({@link #explicit()} {@code == true}) bypass this
 * filter to preserve manually-declared dependencies.
 * </p>
 *
 * @param parent the depending component; never {@code null}
 * @param child the depended-upon component; never {@code null}
 * @param explicit {@code true} if this edge was explicitly declared,
 *        {@code false} if inferred from Maven dependency resolution
 */
public record DependencyEdge(PackageRef parent, PackageRef child, boolean explicit) {

    public DependencyEdge {
        Objects.requireNonNull(parent, "parent");
        Objects.requireNonNull(child, "child");
    }
}
