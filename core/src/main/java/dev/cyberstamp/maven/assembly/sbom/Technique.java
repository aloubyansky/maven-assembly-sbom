package dev.cyberstamp.maven.assembly.sbom;

/**
 * How a component's identity was determined. A neutral mirror of the
 * CycloneDX identity-evidence technique vocabulary, so the model stays free
 * of CycloneDX types; constant names are identical to the CycloneDX ones.
 */
public enum Technique {
    SOURCE_CODE_ANALYSIS,
    BINARY_ANALYSIS,
    MANIFEST_ANALYSIS,
    AST_FINGERPRINT,
    HASH_COMPARISON,
    INSTRUMENTATION,
    DYNAMIC_ANALYSIS,
    FILENAME,
    ATTESTATION,
    OTHER
}
