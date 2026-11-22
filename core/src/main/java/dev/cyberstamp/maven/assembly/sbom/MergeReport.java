package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;

/**
 * What one SBOM merge did, and whether the distribution confirmed that the
 * SBOM describes what it was merged into.
 *
 * <p>
 * Only a content hash confirms: a location says where a file sits, not what
 * it is, and a purl names an artifact any project may use. A component
 * matched by location without a hash in common is counted as "by location
 * only" and confirms nothing.
 * </p>
 *
 * <p>
 * Every rule {@link AnchoredMerge} anchors a component by is an
 * {@link Anchor}, and every fate of a component that does not anchor is an
 * {@link Outcome}. How each is counted, and whether it confirms the SBOM, is
 * decided by {@code switch} expressions with no {@code default} branch: a new
 * rule does not compile until it is classified here. A change to these rules
 * also updates the README sections "Supported merges" and "How SBOMs Are
 * Merged" and the per-value tests in {@code AnchoredMergeTest} and
 * {@code MergeReportTest}.
 * </p>
 *
 * @param mergeCase the case the merge is
 * @param unpacked for an embedded SBOM, whether the archive it was found in
 *        is unpacked in the distribution, which makes its contents files the
 *        distribution can be checked against
 * @param anchors the number of source components anchored by each rule
 * @param outcomes the number of source components that did not anchor, by
 *        what became of them
 * @param hashCheckable the number of source components with a hash in the
 *        distribution's algorithm
 * @param hashVerified the number of source components the distribution
 *        holds by hash: matched to a copy with a hash in common, or kept
 *        because the distribution holds their hash
 * @param locationOnly the number of source components matched by location
 *        with no hash in common
 * @param rootConfirmed whether the SBOM's root offset was derived from a
 *        component matched by hash and location, rather than assumed
 * @param offset the root offset the merge used, possibly empty
 * @param top for an embedded SBOM, whether its top component names the
 *        archive it was found in
 * @param topPurl for an embedded SBOM, its top component's purl, or
 *        {@code null}
 * @param parentPurl for an embedded SBOM, the archive's purl, or {@code null}
 * @param uncheckedTypes the purl types of the components kept unchecked
 */
record MergeReport(MergeCase mergeCase, boolean unpacked, Map<Anchor, Integer> anchors,
        Map<Outcome, Integer> outcomes, int hashCheckable, int hashVerified, int locationOnly,
        boolean rootConfirmed, String offset, TopComponent top, String topPurl, String parentPurl,
        SortedSet<String> uncheckedTypes) {

    private static final String KEPT_IN_DISTRIBUTION = "kept in the distribution";
    private static final String KEPT_NESTED = "kept nested";
    private static final String KEPT_UNCHECKED = "kept unchecked";
    private static final String DROPPED = "dropped";
    private static final String REJECTED = "rejected";

    /** How a source component anchored to a copy already in the target. */
    enum Anchor {
        /** By a file location, after the root offset. */
        LOCATION,
        /** By a directory location, which any unpacked parent shows. */
        DIRECTORY,
        /** By content hash. */
        HASH,
        /** By purl among the nested components of the binary its parent anchored to. */
        PURL_IN_BINARY,
        /** By purl among the direct children of its anchored parent. */
        PURL_AMONG_CHILDREN,
        /** By purl among components located under its unpacked parent's directory. */
        PURL_UNDER_DIRECTORY
    }

    /** What became of a source component that did not anchor. */
    enum Outcome {
        /** The analyzer rejected its claim: dropped. */
        EXCLUDED,
        /** The analyzer matched it to an archive file by hash: kept where it found it. */
        KEPT_SHIPPED,
        /** The distribution holds its hash; the target just had no copy: kept. */
        KEPT_HASH_IN_LAYOUT,
        /** It has no hash to check, and a file sits at its location: kept. */
        KEPT_PATH_IN_LAYOUT,
        /** The distribution shows its empty or directory location: kept. */
        KEPT_DIRECTORY_IN_LAYOUT,
        /** Nested in the SBOM under a binary, with no location: kept under that binary. */
        KEPT_ATTRIBUTED,
        /** The distribution could not show it, or there is no distribution: kept on the SBOM's word. */
        KEPT_UNCHECKED,
        /** The distribution could show it but does not: it does not ship. */
        DROPPED
    }

    /** Whether an embedded SBOM's top component names the archive it was found in. */
    enum TopComponent {
        /** Same canonical purl, or a common hash. */
        MATCHES,
        /** It has a purl or a hash, and neither matches the archive. */
        DIFFERS,
        /** No top component, or one with neither a purl nor a hash. */
        NOTHING_TO_COMPARE,
        /** The archive has no copy in the distribution. */
        NO_COPY,
        /** Not an embedded SBOM. */
        NOT_APPLICABLE
    }

    /** What the distribution says about the SBOM. */
    enum Verdict {
        /** The distribution holds its contents or its root by hash. */
        CONFIRMED,
        /** An embedded SBOM whose top component names its archive, with nothing to check by hash. */
        CONSISTENT,
        /** Its top component names another artifact, or none of its content hashes was found: warns. */
        UNCONFIRMED,
        /** Nothing in it could be checked. */
        NOTHING_TO_CHECK,
        /** A finished-SBOM merge, with no distribution to check against. */
        NOT_CHECKED
    }

    /**
     * Copies the counts into complete enum maps, zero for any absent value.
     */
    MergeReport {
        anchors = complete(Anchor.class, anchors);
        outcomes = complete(Outcome.class, outcomes);
        uncheckedTypes = Collections.unmodifiableSortedSet(new TreeSet<>(uncheckedTypes));
    }

    /**
     * Whether an anchoring rule matches by location: such a match confirms
     * nothing unless the two share a hash.
     *
     * @param anchor the anchoring rule
     * @return {@code true} for a location or directory match
     */
    static boolean isLocation(Anchor anchor) {
        return switch (anchor) {
            case LOCATION, DIRECTORY -> true;
            case HASH, PURL_IN_BINARY, PURL_AMONG_CHILDREN, PURL_UNDER_DIRECTORY -> false;
        };
    }

    /**
     * Whether a component that did not anchor, but met {@code outcome}, shows
     * by hash that the distribution holds what the SBOM describes.
     *
     * @param outcome what became of it
     * @param mergeCase the merge's case
     * @return {@code true} if it confirms
     */
    static boolean confirms(Outcome outcome, MergeCase mergeCase) {
        return switch (outcome) {
            case KEPT_HASH_IN_LAYOUT -> true;
            case KEPT_SHIPPED -> mergeCase == MergeCase.EXTERNAL;
            case EXCLUDED, KEPT_PATH_IN_LAYOUT, KEPT_DIRECTORY_IN_LAYOUT, KEPT_ATTRIBUTED, KEPT_UNCHECKED,
                    DROPPED ->
                false;
        };
    }

    /**
     * Compares an embedded SBOM's top component with the archive it was
     * found in.
     *
     * @param sbomTop the SBOM's metadata component, or {@code null}
     * @param archive the archive's copy
     * @return {@link TopComponent#MATCHES} for the same canonical purl or a
     *         common hash, {@link TopComponent#NOTHING_TO_COMPARE} when the
     *         top component has neither a purl nor a hash, else
     *         {@link TopComponent#DIFFERS}
     */
    static TopComponent compareTop(Component sbomTop, Component archive) {
        boolean hasHashes = sbomTop != null && sbomTop.getHashes() != null && !sbomTop.getHashes().isEmpty();
        if (sbomTop == null || (sbomTop.getPurl() == null && !hasHashes)) {
            return TopComponent.NOTHING_TO_COMPARE;
        }
        if (sbomTop.getPurl() != null && archive.getPurl() != null
                && BomMerger.canonicalPurl(sbomTop.getPurl()).equals(BomMerger.canonicalPurl(archive.getPurl()))) {
            return TopComponent.MATCHES;
        }
        return sharesHash(sbomTop, archive) ? TopComponent.MATCHES : TopComponent.DIFFERS;
    }

    /**
     * Whether two components share a hash: the same value for one algorithm,
     * ignoring how the algorithm is spelled and the value's case.
     *
     * @param a one component
     * @param b the other
     * @return {@code true} if they share a hash
     */
    static boolean sharesHash(Component a, Component b) {
        if (a.getHashes() == null || b.getHashes() == null) {
            return false;
        }
        for (Hash h : a.getHashes()) {
            for (Hash j : b.getHashes()) {
                if (h.getAlgorithm() != null && j.getAlgorithm() != null && h.getValue() != null
                        && SbomUtils.normalizeAlgorithm(h.getAlgorithm())
                                .equals(SbomUtils.normalizeAlgorithm(j.getAlgorithm()))
                        && h.getValue().equalsIgnoreCase(j.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * What the distribution says about the SBOM.
     *
     * <ul>
     * <li>An embedded SBOM is unconfirmed when its top component names
     * another artifact. When its archive is unpacked, it is confirmed by
     * contents (or a root) found by hash, and unconfirmed when it has
     * hash-checkable contents and none was found. An SBOM inside a packed
     * archive cannot hold that archive's hash and its contents are not the
     * distribution's files, so it is at best consistent: its top component
     * names the archive.</li>
     * <li>An external SBOM is confirmed by contents (or a root) found by
     * hash, and unconfirmed when it has hash-checkable contents and none was
     * found.</li>
     * <li>A finished-SBOM merge is not checked.</li>
     * </ul>
     *
     * @return the verdict
     */
    Verdict verdict() {
        boolean foundByHash = hashVerified > 0 || rootConfirmed;
        return switch (mergeCase) {
            case EMBEDDED -> {
                if (top == TopComponent.DIFFERS) {
                    yield Verdict.UNCONFIRMED;
                }
                if (unpacked && foundByHash) {
                    yield Verdict.CONFIRMED;
                }
                if (unpacked && hashCheckable > 0) {
                    yield Verdict.UNCONFIRMED;
                }
                yield top == TopComponent.MATCHES ? Verdict.CONSISTENT : Verdict.NOTHING_TO_CHECK;
            }
            case EXTERNAL -> foundByHash ? Verdict.CONFIRMED
                    : hashCheckable > 0 ? Verdict.UNCONFIRMED : Verdict.NOTHING_TO_CHECK;
            case FINISHED -> Verdict.NOT_CHECKED;
        };
    }

    /**
     * Why the SBOM is unconfirmed.
     *
     * @return the reason, or {@code null} when the verdict is not
     *         {@link Verdict#UNCONFIRMED}
     */
    String warning() {
        return switch (verdict()) {
            case UNCONFIRMED -> top == TopComponent.DIFFERS
                    ? "its top component " + (topPurl != null ? topPurl : "(no purl)") + " is not this archive ("
                            + (parentPurl != null ? parentPurl : "no purl") + ")"
                    : "none of its content hashes was found in the distribution: "
                            + "it may not describe what it was merged into";
            case CONFIRMED, CONSISTENT, NOTHING_TO_CHECK, NOT_CHECKED -> null;
        };
    }

    /**
     * The counts, as one log line: what matched (and how), how much the
     * distribution holds by hash, what was kept, what was dropped and, where
     * the SBOM's contents are the distribution's files, where its root sits.
     *
     * @return the line
     */
    String describe() {
        Map<String, Integer> how = new LinkedHashMap<>();
        for (String label : List.of("location", "directory", "hash", "purl")) {
            how.put(label, 0);
        }
        for (Map.Entry<Anchor, Integer> e : anchors.entrySet()) {
            how.merge(label(e.getKey()), e.getValue(), Integer::sum);
        }
        Map<String, Integer> fates = new LinkedHashMap<>();
        for (String label : List.of(KEPT_IN_DISTRIBUTION, KEPT_NESTED, KEPT_UNCHECKED, DROPPED, REJECTED)) {
            fates.put(label, 0);
        }
        for (Map.Entry<Outcome, Integer> e : outcomes.entrySet()) {
            fates.merge(label(e.getKey()), e.getValue(), Integer::sum);
        }
        List<String> parts = new ArrayList<>();
        int matched = how.values().stream().mapToInt(Integer::intValue).sum();
        if (matched > 0) {
            List<String> byRule = new ArrayList<>();
            how.forEach((label, n) -> addCount(byRule, n, label));
            parts.add(matched + " matched (" + String.join(", ", byRule) + ")");
        }
        addCount(parts, hashVerified, "hash-verified");
        addCount(parts, locationOnly, "by location only");
        fates.forEach((label, n) -> addCount(parts,
                n, KEPT_UNCHECKED.equals(label) && !uncheckedTypes.isEmpty()
                        ? label + " (" + String.join(", ", uncheckedTypes) + ")"
                        : label));
        String line = parts.isEmpty() ? "nothing merged" : String.join(", ", parts);
        boolean rooted = switch (mergeCase) {
            case EMBEDDED -> unpacked;
            case EXTERNAL -> true;
            case FINISHED -> false;
        };
        return rooted ? line + "; " + rootDescription() : line;
    }

    /**
     * How an anchoring rule is counted in {@link #describe()}.
     *
     * @param anchor the rule
     * @return its label
     */
    private static String label(Anchor anchor) {
        return switch (anchor) {
            case LOCATION -> "location";
            case DIRECTORY -> "directory";
            case HASH -> "hash";
            case PURL_IN_BINARY, PURL_AMONG_CHILDREN, PURL_UNDER_DIRECTORY -> "purl";
        };
    }

    /**
     * How an outcome is counted in {@link #describe()}.
     *
     * @param outcome the outcome
     * @return its label
     */
    private static String label(Outcome outcome) {
        return switch (outcome) {
            case KEPT_SHIPPED, KEPT_HASH_IN_LAYOUT, KEPT_PATH_IN_LAYOUT, KEPT_DIRECTORY_IN_LAYOUT ->
                KEPT_IN_DISTRIBUTION;
            case KEPT_ATTRIBUTED -> KEPT_NESTED;
            case KEPT_UNCHECKED -> KEPT_UNCHECKED;
            case DROPPED -> DROPPED;
            case EXCLUDED -> REJECTED;
        };
    }

    /** Where the SBOM's root sits, and whether that was confirmed. */
    private String rootDescription() {
        if (rootConfirmed) {
            return "root confirmed by hash";
        }
        return offset == null || offset.isEmpty() ? "root assumed at the distribution root"
                : "root assumed at " + offset;
    }

    /**
     * Adds {@code "<count> <label>"} to {@code parts} when the count is not
     * zero.
     *
     * @param parts the parts of a line
     * @param count the count
     * @param label what was counted
     */
    private static void addCount(List<String> parts, int count, String label) {
        if (count > 0) {
            parts.add(count + " " + label);
        }
    }

    /**
     * Copies counts into an enum map holding every value of the enum.
     *
     * @param <E> the enum
     * @param type the enum class
     * @param counts the counts, possibly missing values or {@code null}
     * @return an unmodifiable map with a count for every value
     */
    private static <E extends Enum<E>> Map<E, Integer> complete(Class<E> type, Map<E, Integer> counts) {
        Map<E, Integer> all = new EnumMap<>(type);
        for (E e : type.getEnumConstants()) {
            Integer n = counts == null ? null : counts.get(e);
            all.put(e, n == null ? 0 : n);
        }
        return Collections.unmodifiableMap(all);
    }
}
