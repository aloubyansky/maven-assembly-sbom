package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.Optional;

/**
 * Caps the number of remote lookups a {@link CoordinatesLookup} performs
 * during one SBOM generation run.
 */
final class BudgetedLookup implements CoordinatesLookup {

    private final CoordinatesLookup delegate;
    private final Budget budget;

    BudgetedLookup(CoordinatesLookup delegate, Budget budget) {
        this.delegate = delegate;
        this.budget = budget;
    }

    /**
     * @throws LookupBudgetExceededException if the shared budget is exhausted
     */
    @Override
    public Optional<MavenMatch> lookup(String sha1Hex, String fileName) {
        budget.consume();
        return delegate.lookup(sha1Hex, fileName);
    }

    /**
     * The lookup budget of one matcher.
     */
    static final class Budget {

        private final String matcherName;
        private final int maxLookups;
        private int used;

        Budget(String matcherName, int maxLookups) {
            this.matcherName = matcherName;
            this.maxLookups = maxLookups;
        }

        void consume() {
            if (used >= maxLookups) {
                throw new LookupBudgetExceededException(
                        "<maxLookups> of <" + matcherName + "> (" + maxLookups + ") exhausted; "
                                + "raise <maxLookups>, or narrow <includes>/<excludes> to reduce how many "
                                + "unmatched files are eligible for lookup");
            }
            used++;
        }
    }
}
