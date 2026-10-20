package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class IdentificationTest {

    @Test
    void factoriesCarrySpecValues() {
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), Identification.hashMatch());
        assertEquals(new Identification(Technique.HASH_COMPARISON, 0.8), Identification.unpackedContentMatch());
        assertEquals(new Identification(Technique.MANIFEST_ANALYSIS, 1.0), Identification.pomProperties());
        assertEquals(new Identification(Technique.MANIFEST_ANALYSIS, 0.5),
                Identification.pomPropertiesFilenameOwner());
    }

    @Test
    void rejectsNullTechnique() {
        assertThrows(NullPointerException.class, () -> new Identification(null, 1.0));
    }

    @Test
    void rejectsConfidenceOutsideUnitInterval() {
        assertThrows(IllegalArgumentException.class, () -> new Identification(Technique.OTHER, -0.01));
        assertThrows(IllegalArgumentException.class, () -> new Identification(Technique.OTHER, 1.01));
        assertThrows(IllegalArgumentException.class, () -> new Identification(Technique.OTHER, Double.NaN));
        assertEquals(0.0, new Identification(Technique.OTHER, 0.0).confidence());
        assertEquals(1.0, new Identification(Technique.OTHER, 1.0).confidence());
    }

    @Test
    void producerMayUseAnyTechnique() {
        Identification id = new Identification(Technique.ATTESTATION, 0.9);
        assertEquals(Technique.ATTESTATION, id.technique());
        assertEquals(0.9, id.confidence());
    }
}
