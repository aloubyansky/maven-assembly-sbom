package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * A generic package identity for artifacts that have a name and version
 * but no ecosystem-specific coordinates — notably Galleon-assembled
 * combined JARs (e.g. {@code jboss-client}).
 *
 * <p>
 * Renders (via {@link Purl}) to {@code pkg:generic/<name>@<version>}.
 * </p>
 *
 * @param name the artifact name
 * @param version the artifact version
 */
public record GenericPackageRef(String name, String version) implements PackageRef {

    public GenericPackageRef {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(version, "version");
    }

    @Override
    public Purl toPurl() {
        return Purl.generic(name, version);
    }
}
