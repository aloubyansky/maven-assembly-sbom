package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;
import org.junit.jupiter.api.Test;

import dev.cyberstamp.maven.assembly.sbom.MergeReport.Anchor;
import dev.cyberstamp.maven.assembly.sbom.MergeReport.Outcome;
import dev.cyberstamp.maven.assembly.sbom.MergeReport.TopComponent;
import dev.cyberstamp.maven.assembly.sbom.MergeReport.Verdict;

class MergeReportTest {

    private static final String CONTENT_WARNING = "none of its content hashes was found in the distribution: "
            + "it may not describe what it was merged into";

    @Test
    void everyAnchorIsClassified() {
        Map<Anchor, Boolean> location = new EnumMap<>(Map.of(
                Anchor.LOCATION, true,
                Anchor.DIRECTORY, true,
                Anchor.HASH, false,
                Anchor.PURL_IN_BINARY, false,
                Anchor.PURL_AMONG_CHILDREN, false,
                Anchor.PURL_UNDER_DIRECTORY, false));
        for (Anchor a : Anchor.values()) {
            assertTrue(location.containsKey(a), "no expected classification for " + a);
            assertEquals(location.get(a), MergeReport.isLocation(a), a.name());
        }
    }

    @Test
    void everyOutcomeHasAConfirmationRule() {
        Map<Outcome, List<MergeCase>> confirmingCases = new EnumMap<>(Map.of(
                Outcome.EXCLUDED, List.of(),
                Outcome.KEPT_SHIPPED, List.of(MergeCase.EXTERNAL),
                Outcome.KEPT_HASH_IN_LAYOUT, List.of(MergeCase.values()),
                Outcome.KEPT_PATH_IN_LAYOUT, List.of(),
                Outcome.KEPT_DIRECTORY_IN_LAYOUT, List.of(),
                Outcome.KEPT_ATTRIBUTED, List.of(),
                Outcome.KEPT_UNCHECKED, List.of(),
                Outcome.DROPPED, List.of()));
        for (Outcome o : Outcome.values()) {
            assertTrue(confirmingCases.containsKey(o), "no expected confirmation for " + o);
            for (MergeCase c : MergeCase.values()) {
                assertEquals(confirmingCases.get(o).contains(c), MergeReport.confirms(o, c), o + " in " + c);
            }
        }
    }

    @Test
    void packedArchiveSbomNamingItsArchiveIsConsistent() {
        MergeReport report = embedded(false, TopComponent.MATCHES, 0, 0, false);

        assertEquals(Verdict.CONSISTENT, report.verdict());
        assertNull(report.warning());
    }

    @Test
    void packedArchiveSbomIsNeverConfirmedByItsContents() {
        MergeReport report = embedded(false, TopComponent.MATCHES, 5, 5, true);

        assertEquals(Verdict.CONSISTENT, report.verdict(), "a packed archive's contents are not its files");
    }

    @Test
    void embeddedSbomNamingAnotherArtifactWarns() {
        MergeReport report = new MergeReport(MergeCase.EMBEDDED, false, Map.of(), Map.of(), 0, 0, 0, false, "",
                TopComponent.DIFFERS, "pkg:maven/org.other/bar@1.0", "pkg:maven/org.acme/foo@2.0", new TreeSet<>());

        assertEquals(Verdict.UNCONFIRMED, report.verdict());
        assertEquals("its top component pkg:maven/org.other/bar@1.0 is not this archive (pkg:maven/org.acme/foo@2.0)",
                report.warning());
    }

    @Test
    void unpackedArchiveSbomWithHashMatchesIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, embedded(true, TopComponent.MATCHES, 3, 1, false).verdict());
        assertEquals(Verdict.CONFIRMED, embedded(true, TopComponent.NOTHING_TO_COMPARE, 3, 0, true).verdict(),
                "a root confirmed by hash is hash evidence");
    }

    @Test
    void unpackedArchiveSbomWithHashCheckableContentsButNoneFoundWarns() {
        MergeReport report = embedded(true, TopComponent.MATCHES, 3, 0, false);

        assertEquals(Verdict.UNCONFIRMED, report.verdict());
        assertEquals(CONTENT_WARNING, report.warning());
    }

    @Test
    void unpackedArchiveSbomNamingAnotherArchiveWarnsEvenWithHashMatches() {
        MergeReport report = new MergeReport(MergeCase.EMBEDDED, true, Map.of(), Map.of(), 3, 3, 0, true, "w/",
                TopComponent.DIFFERS, "pkg:maven/g/other@1?type=war", "pkg:maven/g/app@1?type=war", new TreeSet<>());

        assertEquals(Verdict.UNCONFIRMED, report.verdict());
    }

    @Test
    void embeddedSbomWithNothingToCompareIsNothingToCheck() {
        assertEquals(Verdict.NOTHING_TO_CHECK, embedded(true, TopComponent.NOTHING_TO_COMPARE, 0, 0, false).verdict());
        assertEquals(Verdict.NOTHING_TO_CHECK, embedded(false, TopComponent.NO_COPY, 0, 0, false).verdict());
    }

    @Test
    void externalSbomConfirmedByHash() {
        assertEquals(Verdict.CONFIRMED, external(2, 1, false).verdict());
        assertEquals(Verdict.CONFIRMED, external(2, 0, true).verdict());
    }

    @Test
    void externalSbomWithHashCheckableContentsButNoneFoundWarns() {
        MergeReport report = external(2, 0, false);

        assertEquals(Verdict.UNCONFIRMED, report.verdict());
        assertEquals(CONTENT_WARNING, report.warning());
    }

    @Test
    void externalSbomWithoutHashesHasNothingToCheck() {
        MergeReport report = external(0, 0, false);

        assertEquals(Verdict.NOTHING_TO_CHECK, report.verdict());
        assertNull(report.warning());
    }

    @Test
    void finishedMergeIsNotChecked() {
        MergeReport report = new MergeReport(MergeCase.FINISHED, false, Map.of(), Map.of(Outcome.KEPT_UNCHECKED, 4),
                0, 0, 0, false, "", TopComponent.NOT_APPLICABLE, null, null, new TreeSet<>());

        assertEquals(Verdict.NOT_CHECKED, report.verdict());
        assertNull(report.warning());
    }

    @Test
    void archivePurlDifferingOnlyInTypeJarMatches() {
        assertEquals(TopComponent.MATCHES, MergeReport.compareTop(
                component("pkg:maven/g/a@1?type=jar", null), component("pkg:maven/g/a@1", null)));
    }

    @Test
    void archivePurlWithAnotherVersionDiffers() {
        assertEquals(TopComponent.DIFFERS, MergeReport.compareTop(
                component("pkg:maven/g/a@2", null), component("pkg:maven/g/a@1", null)));
    }

    @Test
    void archiveSharingAHashMatches() {
        assertEquals(TopComponent.MATCHES, MergeReport.compareTop(
                component("pkg:maven/g/other@1", new Hash("SHA-256", "ABCD")),
                component("pkg:maven/g/a@1", new Hash("sha256", "abcd"))));
    }

    @Test
    void topWithoutPurlOrHashHasNothingToCompare() {
        Component top = new Component();
        top.setName("unnamed");

        assertEquals(TopComponent.NOTHING_TO_COMPARE, MergeReport.compareTop(top, component("pkg:maven/g/a@1", null)));
        assertEquals(TopComponent.NOTHING_TO_COMPARE, MergeReport.compareTop(null, component("pkg:maven/g/a@1", null)));
    }

    @Test
    void sharesHashComparesValuesOfOneAlgorithm() {
        assertTrue(MergeReport.sharesHash(component(null, new Hash("SHA-256", "AA")),
                component(null, new Hash("sha256", "aa"))));
        assertFalse(MergeReport.sharesHash(component(null, new Hash("SHA-1", "aa")),
                component(null, new Hash("SHA-256", "aa"))), "one value in two algorithms is two hashes");
        assertFalse(MergeReport.sharesHash(component(null, null), component(null, new Hash("SHA-256", "aa"))));
    }

    @Test
    void describeListsTheCountsAndTheRoot() {
        MergeReport report = new MergeReport(MergeCase.EMBEDDED, true, Map.of(Anchor.LOCATION, 82, Anchor.HASH, 2),
                Map.of(Outcome.KEPT_UNCHECKED, 345, Outcome.DROPPED, 1), 85, 83, 1, true, "web/console.war/",
                TopComponent.MATCHES, null, null, new TreeSet<>(List.of("npm")));

        assertEquals("84 matched (82 location, 2 hash), 83 hash-verified, 1 by location only, "
                + "345 kept unchecked (npm), 1 dropped; root confirmed by hash", report.describe());
    }

    @Test
    void describeSaysWhereTheRootWasAssumed() {
        assertEquals("1 dropped; root assumed at web/console.war/", new MergeReport(MergeCase.EMBEDDED, true,
                Map.of(), Map.of(Outcome.DROPPED, 1), 1, 0, 0, false, "web/console.war/", TopComponent.MATCHES, null,
                null, new TreeSet<>()).describe());
        assertEquals("1 dropped; root assumed at the distribution root", new MergeReport(MergeCase.EXTERNAL, false,
                Map.of(), Map.of(Outcome.DROPPED, 1), 1, 0, 0, false, "", TopComponent.NOT_APPLICABLE, null, null,
                new TreeSet<>()).describe());
        assertEquals("1 dropped", new MergeReport(MergeCase.EMBEDDED, false, Map.of(), Map.of(Outcome.DROPPED, 1), 1,
                0, 0, false, "", TopComponent.MATCHES, null, null, new TreeSet<>()).describe(),
                "a packed archive's SBOM has no root in the distribution");
    }

    /**
     * An embedded SBOM's report with no anchored components.
     *
     * @param unpacked whether the archive it was found in is unpacked
     * @param top the outcome of the top-component check
     * @param hashCheckable the hash-checkable count
     * @param hashVerified the hash-verified count
     * @param rootConfirmed whether the root offset was derived
     * @return the report
     */
    private static MergeReport embedded(boolean unpacked, TopComponent top, int hashCheckable, int hashVerified,
            boolean rootConfirmed) {
        return new MergeReport(MergeCase.EMBEDDED, unpacked, Map.of(), Map.of(), hashCheckable, hashVerified, 0,
                rootConfirmed, "", top, "pkg:maven/g/a@1", "pkg:maven/g/a@1", new TreeSet<>());
    }

    /**
     * An external SBOM's report with no anchored components.
     *
     * @param hashCheckable the hash-checkable count
     * @param hashVerified the hash-verified count
     * @param rootConfirmed whether the root offset was derived
     * @return the report
     */
    private static MergeReport external(int hashCheckable, int hashVerified, boolean rootConfirmed) {
        return new MergeReport(MergeCase.EXTERNAL, false, Map.of(), Map.of(), hashCheckable, hashVerified, 0,
                rootConfirmed, "", TopComponent.NOT_APPLICABLE, null, null, new TreeSet<>());
    }

    /**
     * A component with a purl and optionally one hash.
     *
     * @param purl the purl, or {@code null}
     * @param hash the hash, or {@code null}
     * @return the component
     */
    private static Component component(String purl, Hash hash) {
        Component c = new Component();
        c.setName("c");
        c.setPurl(purl);
        if (hash != null) {
            c.setHashes(List.of(hash));
        }
        return c;
    }
}
