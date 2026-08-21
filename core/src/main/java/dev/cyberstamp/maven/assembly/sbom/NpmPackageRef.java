package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * An npm package identity.
 *
 * <p>
 * Renders (via {@link Purl}) to {@code pkg:npm/<name>@<version>}, or
 * {@code pkg:npm/<@scope>/<name>@<version>} when a scope is present. The
 * leading {@code @} of a scope is added if missing; {@code Purl}
 * percent-encodes it to {@code %40} and lower-cases the npm name per the
 * purl spec.
 * </p>
 *
 * @param scope the npm scope with or without a leading {@code @}, or
 *        {@code null}/empty for an unscoped package
 * @param name the package name
 * @param version the package version
 */
public record NpmPackageRef(String scope, String name, String version) implements PackageRef {

    public NpmPackageRef {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(version, "version");
        if (scope != null && scope.isEmpty()) {
            scope = null;
        }
    }

    @Override
    public Purl toPurl() {
        String namespace = scope == null ? null : (scope.startsWith("@") ? scope : "@" + scope);
        return Purl.npm(namespace, name, version);
    }
}
