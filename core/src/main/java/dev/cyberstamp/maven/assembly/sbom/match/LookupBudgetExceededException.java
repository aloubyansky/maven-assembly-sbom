package dev.cyberstamp.maven.assembly.sbom.match;

/**
 * Thrown when a {@link ChecksumSearchMatcherFactory}'s configured
 * {@code <maxLookups>} budget is exhausted.
 */
public class LookupBudgetExceededException extends RuntimeException {

    LookupBudgetExceededException(String message) {
        super(message);
    }
}
