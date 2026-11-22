package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The merge reports of one SBOM generation: logs each merged SBOM, then a
 * summary, and fails the generation when asked to and an SBOM is
 * unconfirmed (see {@link MergeReport#verdict()}).
 */
final class MergeReports {

    private static final Logger log = LoggerFactory.getLogger(MergeReports.class);

    private final List<String> warnings = new ArrayList<>();
    private final Map<MergeReport.Verdict, Integer> verdicts = new EnumMap<>(MergeReport.Verdict.class);
    private int merged;

    /**
     * Logs and records one merge: at WARN when it is unconfirmed; at INFO for
     * an external SBOM or one embedded in an unpacked archive, whose
     * contents the distribution can show; at DEBUG for one embedded in a
     * packed archive, of which a distribution may hold many.
     *
     * @param sbom the SBOM's path: in the archive for an embedded one, as
     *        configured for an external one
     * @param where where it was merged, e.g. {@code under web/app.war/}
     * @param report the merge's report
     */
    void add(String sbom, String where, MergeReport report) {
        merged++;
        MergeReport.Verdict verdict = report.verdict();
        verdicts.merge(verdict, 1, Integer::sum);
        String header = "SBOM " + sbom + " " + where + " (" + label(report.mergeCase()) + "):";
        String warning = report.warning();
        if (warning != null) {
            warnings.add(sbom + " " + where + ": " + warning);
            log.warn("{}\n       {}; {}", header, warning, report.describe());
            return;
        }
        String line = switch (verdict) {
            case CONFIRMED, UNCONFIRMED, NOT_CHECKED -> report.describe();
            case CONSISTENT -> "its top component names this archive; " + report.describe();
            case NOTHING_TO_CHECK -> "nothing could be confirmed; " + report.describe();
        };
        boolean contentsShown = switch (report.mergeCase()) {
            case EMBEDDED -> report.unpacked();
            case EXTERNAL -> true;
            case FINISHED -> false;
        };
        if (contentsShown) {
            log.info("{}\n       {}", header, line);
        } else {
            log.debug("{}\n       {}", header, line);
        }
    }

    /**
     * Logs one line summing up the merges by verdict, when there were any.
     */
    void logSummary() {
        if (merged > 0) {
            log.info("Merged {} SBOMs: {} confirmed, {} consistent, {} unconfirmed, {} with nothing to check", merged,
                    count(MergeReport.Verdict.CONFIRMED), count(MergeReport.Verdict.CONSISTENT),
                    count(MergeReport.Verdict.UNCONFIRMED), count(MergeReport.Verdict.NOTHING_TO_CHECK));
        }
    }

    /**
     * The number of merges with a verdict.
     *
     * @param verdict the verdict
     * @return the count
     */
    private int count(MergeReport.Verdict verdict) {
        return verdicts.getOrDefault(verdict, 0);
    }

    /**
     * The unconfirmed SBOMs, each with where it was merged
     * and why.
     *
     * @return the warnings, in merge order
     */
    List<String> warnings() {
        return List.copyOf(warnings);
    }

    /**
     * Fails when any merged SBOM is unconfirmed.
     *
     * @throws UnconfirmedSbomException listing every such SBOM
     */
    void failIfUnconfirmed() {
        if (!warnings.isEmpty()) {
            throw new UnconfirmedSbomException(
                    "SBOMs that do not describe what they were merged into (failOnUnconfirmedSbom):\n  "
                            + String.join("\n  ", warnings));
        }
    }

    /**
     * Says where an SBOM was merged, for its log line.
     *
     * @param report the merge's report
     * @param parent the copy it was merged under
     * @return e.g. {@code in lib/a.jar} (a packed archive),
     *         {@code under web/app.war/} (an unpacked one) or
     *         {@code at the distribution root}
     */
    static String where(MergeReport report, Component parent) {
        return switch (report.mergeCase()) {
            case EMBEDDED -> report.top() == MergeReport.TopComponent.NO_COPY
                    ? "with no copy of its archive in the distribution"
                    : (report.unpacked() ? "under " : "in ") + nameOf(parent);
            case EXTERNAL, FINISHED -> "at the distribution root";
        };
    }

    /**
     * The short name of a case in a log line.
     *
     * @param mergeCase the case
     * @return the label
     */
    private static String label(MergeCase mergeCase) {
        return switch (mergeCase) {
            case EMBEDDED -> "embedded";
            case EXTERNAL -> "external";
            case FINISHED -> "finished";
        };
    }

    /**
     * A copy's first location in the distribution, else its purl, else its
     * name.
     *
     * @param c the copy
     * @return the name
     */
    private static String nameOf(Component c) {
        if (c.getEvidence() != null && c.getEvidence().getOccurrences() != null) {
            for (Occurrence o : c.getEvidence().getOccurrences()) {
                if (o.getLocation() != null && !o.getLocation().isEmpty()) {
                    return o.getLocation();
                }
            }
        }
        return c.getPurl() != null ? c.getPurl() : c.getName();
    }
}
