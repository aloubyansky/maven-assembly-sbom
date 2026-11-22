package dev.cyberstamp.maven.assembly.sbom;

/**
 * The supported ways an SBOM is merged, fixed by where it comes from: each
 * case matches the setting that brings the SBOM in.
 *
 * <p>
 * Each case states what confirms that the SBOM describes what it was merged
 * into, and what makes a merge warn (see {@link MergeReport#verdict()}). The
 * README section "Supported merges" documents each case under its
 * {@link #displayName() display name}; {@code ReadmeMergeCasesTest} fails
 * when a case is missing there.
 * </p>
 */
enum MergeCase {

    /**
     * An SBOM found inside an artifact the distribution ships
     * ({@code embeddedSboms}), packed or unpacked, merged under that
     * artifact's copy.
     */
    EMBEDDED("Embedded SBOM"),

    /**
     * An SBOM configured by {@code externalSboms}, merged as a description of
     * the whole distribution.
     */
    EXTERNAL("External SBOM"),

    /** A merge of finished SBOMs, with no distribution to check against. */
    FINISHED("Finished-SBOM merge");

    private final String displayName;

    /**
     * Creates a case.
     *
     * @param displayName the name the logs and the README use
     */
    MergeCase(String displayName) {
        this.displayName = displayName;
    }

    /**
     * The name the logs and the README use for this case.
     *
     * @return the display name
     */
    String displayName() {
        return displayName;
    }
}
