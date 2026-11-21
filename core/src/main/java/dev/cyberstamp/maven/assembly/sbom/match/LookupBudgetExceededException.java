package dev.cyberstamp.maven.assembly.sbom.match;

import dev.cyberstamp.maven.assembly.sbom.ChecksumSearchMatcherFactory;

/**
 * Thrown when a {@link ChecksumSearchMatcherFactory}'s configured
 * {@code <maxLookups>} budget is exhausted.
 */
public class LookupBudgetExceededException extends RuntimeException {

    /**
     * Creates the exception.
     *
     * @param message which matcher ran out of lookups, and its budget
     */
    LookupBudgetExceededException(String message) {
        super(message);
    }
}
