package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import dev.cyberstamp.maven.assembly.sbom.MergeReport.Outcome;
import dev.cyberstamp.maven.assembly.sbom.MergeReport.TopComponent;

class MergeReportsTest {

    @Test
    void failureListsEveryUnconfirmedSbom() {
        MergeReports reports = new MergeReports();
        reports.add("target/a.cdx.json", "at the distribution root", unconfirmed(MergeCase.EXTERNAL));
        reports.add("META-INF/sbom/bom.json", "under web/app.war/", unconfirmed(MergeCase.EMBEDDED));
        reports.add("target/b.cdx.json", "at the distribution root", confirmed());

        UnconfirmedSbomException e = assertThrows(UnconfirmedSbomException.class, reports::failIfUnconfirmed);

        assertTrue(e.getMessage().contains("target/a.cdx.json"), e.getMessage());
        assertTrue(e.getMessage().contains("META-INF/sbom/bom.json"), e.getMessage());
        assertTrue(!e.getMessage().contains("target/b.cdx.json"), e.getMessage());
    }

    @Test
    void noWarningsDoesNotFail() {
        MergeReports reports = new MergeReports();
        reports.add("target/b.cdx.json", "at the distribution root", confirmed());

        assertDoesNotThrow(reports::failIfUnconfirmed);
    }

    @Test
    void warningsListsSbomWhereAndReason() {
        MergeReports reports = new MergeReports();
        reports.add("target/a.cdx.json", "at the distribution root", unconfirmed(MergeCase.EXTERNAL));

        assertEquals(List.of("target/a.cdx.json at the distribution root: none of its content hashes was found in "
                + "the distribution: it may not describe what it was merged into"), reports.warnings());
    }

    /**
     * A report whose hash-checkable components were all dropped.
     *
     * @param mergeCase an embedded (unpacked) or external case
     * @return the report
     */
    private static MergeReport unconfirmed(MergeCase mergeCase) {
        return new MergeReport(mergeCase, true, Map.of(), Map.of(Outcome.DROPPED, 2), 2, 0, 0, false, "",
                TopComponent.NOT_APPLICABLE, null, null, new TreeSet<>());
    }

    /**
     * An external SBOM's report confirmed by a component whose hash the
     * layout holds.
     *
     * @return the report
     */
    private static MergeReport confirmed() {
        return new MergeReport(MergeCase.EXTERNAL, false, Map.of(), Map.of(Outcome.KEPT_HASH_IN_LAYOUT, 1), 1, 1,
                0, false, "", TopComponent.NOT_APPLICABLE, null, null, new TreeSet<>());
    }
}
