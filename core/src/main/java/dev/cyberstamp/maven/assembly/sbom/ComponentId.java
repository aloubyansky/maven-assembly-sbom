package dev.cyberstamp.maven.assembly.sbom;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Identifies one copy of a component in an {@link AssemblyComponents} model.
 *
 * <p>
 * An artifact can ship more than once in an assembly: at the top level and
 * inside a WAR, inside an unpacked overlay, or bundled in a shaded jar. Each
 * copy is its own {@link AssemblyComponent}, and its {@code ComponentId} is
 * what tells the copies apart. Their {@link PackageRef} (what the copy
 * <em>is</em>) is shared, while the id (<em>which</em> copy) is not.
 * {@link DependencyEdge}s connect ids, never artifacts, so an edge always
 * names the specific copies it connects.
 * </p>
 *
 * <p>
 * An id is an opaque value, unique within a model. It is internal to the
 * model and never appears in a rendered BOM: {@link BomRenderer} maps ids to
 * CycloneDX bom-refs, which are derived from the artifact (its purl, with a
 * {@code #n} suffix for every copy after the first).
 * </p>
 *
 * <p>
 * The value is a {@code long}, so equality and hashing are a primitive
 * comparison with no string building, and an id costs one small allocation.
 * </p>
 *
 * @param value the id's value; carries no meaning beyond identity
 */
public record ComponentId(long value) {

    /** Source of {@link #generate() generated} ids, shared by all models. */
    private static final AtomicLong NEXT = new AtomicLong();

    /**
     * Returns a new id, distinct from every other id generated in this JVM.
     *
     * <p>
     * Components created without an explicit id get one from here, so ids
     * are unique within any model built from them, including models that
     * combine components created by different producers.
     * </p>
     *
     * @return a new, unique id
     */
    public static ComponentId generate() {
        return new ComponentId(NEXT.incrementAndGet());
    }

    /**
     * Returns a compact form for logs and test failure messages.
     *
     * @return {@code "#c"} followed by the value
     */
    @Override
    public String toString() {
        return "#c" + value;
    }
}
