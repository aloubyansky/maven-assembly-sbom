package io.github.cyberstamp.maven.assembly.sbom;

/**
 * Thrown when license information cannot be resolved for a Maven
 * artifact and the build is configured to treat missing licenses
 * as errors.
 */
class LicenseResolutionException extends RuntimeException {

    LicenseResolutionException(String message) {
        super(message);
    }
}
