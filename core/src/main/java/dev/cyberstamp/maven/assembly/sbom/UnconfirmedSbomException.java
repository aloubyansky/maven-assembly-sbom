package dev.cyberstamp.maven.assembly.sbom;

/**
 * Thrown when merged SBOMs do not describe what they were merged into and
 * the build is configured to fail on that ({@code failOnUnconfirmedSbom}).
 */
class UnconfirmedSbomException extends RuntimeException {

    /**
     * Creates the exception.
     *
     * @param message the unconfirmed SBOMs and why
     */
    UnconfirmedSbomException(String message) {
        super(message);
    }
}
