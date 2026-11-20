package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.junit.jupiter.api.Test;

import dev.cyberstamp.maven.assembly.sbom.ClaimedArtifactIndex.ClaimedArtifact;

class ClaimedArtifactIndexTest {

    private static final String ALG = "SHA-256";
    private static final String NIMBUS = "pkg:maven/com.nimbusds/nimbus-jose-jwt@10.6";
    private static final ArtifactCoords NIMBUS_COORDS = ArtifactCoords.of("com.nimbusds", "nimbus-jose-jwt", "10.6");
    private static final ArtifactCoords JCIP_COORDS = ArtifactCoords.of("com.github.stephenc.jcip",
            "jcip-annotations", "1.0-1");

    private static Component component(String purl, String hash) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setName("x");
        c.setPurl(purl);
        c.setBomRef(purl);
        if (hash != null) {
            c.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        }
        return c;
    }

    private static Component withIdentity(Component c, Identity.Field field,
            Method.Technique technique, Double identityConfidence, Double methodConfidence) {
        Method method = new Method();
        method.setTechnique(technique);
        method.setConfidence(methodConfidence);
        Identity identity = new Identity();
        identity.setField(field);
        identity.setConfidence(identityConfidence);
        identity.setMethods(List.of(method));
        Evidence evidence = new Evidence();
        evidence.setIdentities(new ArrayList<>(List.of(identity)));
        c.setEvidence(evidence);
        return c;
    }

    private static Component hashMatched(String purl, String hash, double confidence) {
        return withIdentity(component(purl, hash), Identity.Field.PURL,
                Method.Technique.HASH_COMPARISON, confidence, confidence);
    }

    private static Bom bomOf(Component... comps) {
        Bom b = new Bom();
        b.setComponents(new ArrayList<>(List.of(comps)));
        return b;
    }

    private static ClaimedArtifactIndex index(Bom... boms) {
        Map<String, Bom> bySource = new LinkedHashMap<>();
        for (int i = 0; i < boms.length; i++) {
            bySource.put("source-" + i, boms[i]);
        }
        return ClaimedArtifactIndex.build(List.of(), bySource, SbomUtils.normalizeAlgorithm(ALG));
    }

    @Test
    void indexesMavenComponentByHash() {
        ClaimedArtifactIndex idx = index(bomOf(hashMatched(NIMBUS, "h1", 1.0)));

        ClaimedArtifact id = idx.lookup("h1").orElseThrow();
        assertEquals(NIMBUS_COORDS, id.coords());
        assertEquals(new Identification(Technique.HASH_COMPARISON, 1.0), id.identification());
    }

    @Test
    void readsTypeAndClassifierQualifiers() {
        ClaimedArtifactIndex idx = index(bomOf(component(
                "pkg:maven/org.example/app@1.0?type=war&classifier=bin", "h1")));

        assertEquals(new ArtifactCoords("org.example", "app", "1.0", "war", "bin"),
                idx.lookup("h1").orElseThrow().coords());
    }

    @Test
    void missingTypeDefaultsToJar() {
        ClaimedArtifactIndex idx = index(bomOf(component("pkg:maven/org.example/lib@2.0", "h1")));

        assertEquals(ArtifactCoords.of("org.example", "lib", "2.0"), idx.lookup("h1").orElseThrow().coords());
    }

    @Test
    void componentWithoutIdentityYieldsNullIdentification() {
        ClaimedArtifactIndex idx = index(bomOf(component(NIMBUS, "h1")));

        assertNull(idx.lookup("h1").orElseThrow().identification());
    }

    @Test
    void methodConfidenceUsedWhenIdentityConfidenceAbsent() {
        ClaimedArtifactIndex idx = index(bomOf(withIdentity(component(NIMBUS, "h1"), Identity.Field.PURL,
                Method.Technique.MANIFEST_ANALYSIS, null, 0.5)));

        assertEquals(new Identification(Technique.MANIFEST_ANALYSIS, 0.5),
                idx.lookup("h1").orElseThrow().identification());
    }

    @Test
    void nonPurlIdentityIgnored() {
        ClaimedArtifactIndex idx = index(bomOf(withIdentity(component(NIMBUS, "h1"), Identity.Field.NAME,
                Method.Technique.HASH_COMPARISON, 1.0, 1.0)));

        assertNull(idx.lookup("h1").orElseThrow().identification());
    }

    @Test
    void skipsNonMavenAndMalformedPurls() {
        ClaimedArtifactIndex idx = index(bomOf(
                component("pkg:npm/react@18.3.1", "h1"),
                component("not-a-purl", "h2"),
                component("pkg:maven/g/a", "h3")));

        assertFalse(idx.hasClaims());
    }

    @Test
    void skipsComponentsWithoutHashInAlgorithm() {
        Component c = component(NIMBUS, null);
        c.addHash(new Hash(Hash.Algorithm.SHA1, "h1"));

        assertFalse(index(bomOf(c)).hasClaims());
    }

    @Test
    void indexesNestedComponents() {
        Component parent = component("pkg:maven/org.example/app@1.0?type=war", "hp");
        parent.addComponent(component(NIMBUS, "hc"));

        assertEquals(NIMBUS_COORDS, index(bomOf(parent)).lookup("hc").orElseThrow().coords());
    }

    @Test
    void agreeingClaimsUseHighestConfidence() {
        ClaimedArtifactIndex idx = index(
                bomOf(hashMatched(NIMBUS, "h1", 0.5)),
                bomOf(hashMatched(NIMBUS, "h1", 1.0)));

        assertEquals(1.0, idx.lookup("h1").orElseThrow().identification().confidence());
    }

    @Test
    void agreeingClaimPrefersNonNullIdentification() {
        ClaimedArtifactIndex idx = index(
                bomOf(component(NIMBUS, "h1")),
                bomOf(hashMatched(NIMBUS, "h1", 0.8)));

        assertEquals(new Identification(Technique.HASH_COMPARISON, 0.8),
                idx.lookup("h1").orElseThrow().identification());
    }

    @Test
    void conflictingClaimsDropHash() {
        ClaimedArtifactIndex idx = index(
                bomOf(hashMatched(NIMBUS, "h1", 1.0)),
                bomOf(hashMatched("pkg:maven/other/other@9", "h1", 1.0)));

        assertTrue(idx.lookup("h1").isEmpty());
    }

    @Test
    void conflictIsOrderIndependent() {
        Bom a = bomOf(hashMatched(NIMBUS, "h1", 1.0));
        Bom b = bomOf(hashMatched("pkg:maven/other/other@9", "h1", 1.0));
        Bom a2 = bomOf(hashMatched(NIMBUS, "h1", 0.9));

        assertTrue(index(a, b, a2).lookup("h1").isEmpty());
        assertTrue(index(a, a2, b).lookup("h1").isEmpty());
    }

    @Test
    void lookupNullHashIsEmpty() {
        assertTrue(index(bomOf(hashMatched(NIMBUS, "h1", 1.0))).lookup(null).isEmpty());
    }

    private static ClaimedArtifact nimbusClaim(Double confidence) {
        return new ClaimedArtifact(NIMBUS_COORDS,
                confidence == null ? null : new Identification(Technique.HASH_COMPARISON, confidence));
    }

    @Test
    void crossCheckAcceptsWhenNoDescriptors() {
        ClaimedArtifact claim = nimbusClaim(1.0);

        assertEquals(Optional.of(claim), ClaimedArtifactIndex.crossCheck(claim, List.of()));
    }

    @Test
    void crossCheckAcceptsMatchingDescriptor() {
        ClaimedArtifact claim = nimbusClaim(1.0);

        assertEquals(Optional.of(claim),
                ClaimedArtifactIndex.crossCheck(claim, List.of(NIMBUS_COORDS, JCIP_COORDS)));
    }

    @Test
    void crossCheckIgnoresTypeAndClassifier() {
        ClaimedArtifact claim = new ClaimedArtifact(new ArtifactCoords("org.example", "app", "1.0", "war", "bin"),
                new Identification(Technique.HASH_COMPARISON, 1.0));

        assertEquals(Optional.of(claim),
                ClaimedArtifactIndex.crossCheck(claim, List.of(ArtifactCoords.of("org.example", "app", "1.0"))));
    }

    @Test
    void crossCheckRejectsVersionMismatch() {
        assertTrue(ClaimedArtifactIndex.crossCheck(nimbusClaim(1.0),
                List.of(ArtifactCoords.of("com.nimbusds", "nimbus-jose-jwt", "10.5"))).isEmpty());
    }

    private static ClaimedArtifact nimbusClaim(Technique technique, double confidence) {
        return new ClaimedArtifact(NIMBUS_COORDS, new Identification(technique, confidence));
    }

    @Test
    void crossCheckKeepsHashComparisonConfidenceWhenOwnerDescriptorMissing() {
        // the source build matched these exact bytes to the claimed artifact;
        // a foreign descriptor inside is how that artifact was published
        ClaimedArtifact claim = nimbusClaim(1.0);

        assertEquals(Optional.of(claim), ClaimedArtifactIndex.crossCheck(claim, List.of(JCIP_COORDS)));
    }

    @Test
    void crossCheckCapsNonHashTechniqueWhenOwnerDescriptorMissing() {
        ClaimedArtifact checked = ClaimedArtifactIndex.crossCheck(
                nimbusClaim(Technique.MANIFEST_ANALYSIS, 1.0), List.of(JCIP_COORDS)).orElseThrow();

        assertEquals(NIMBUS_COORDS, checked.coords());
        assertEquals(new Identification(Technique.MANIFEST_ANALYSIS, 0.5), checked.identification());
    }

    @Test
    void crossCheckKeepsLowerConfidenceBelowCap() {
        ClaimedArtifact checked = ClaimedArtifactIndex.crossCheck(
                nimbusClaim(Technique.FILENAME, 0.3), List.of(JCIP_COORDS)).orElseThrow();

        assertEquals(new Identification(Technique.FILENAME, 0.3), checked.identification());
    }

    @Test
    void crossCheckKeepsNullIdentification() {
        ClaimedArtifact checked = ClaimedArtifactIndex.crossCheck(nimbusClaim(null), List.of(JCIP_COORDS)).orElseThrow();

        assertEquals(NIMBUS_COORDS, checked.coords());
        assertNull(checked.identification());
    }

    // ---- configured (externalSboms) components ----

    private static ClaimedArtifactIndex withConfigured(List<Bom> configured, Bom... embedded) {
        Map<String, Bom> bySource = new LinkedHashMap<>();
        for (int i = 0; i < embedded.length; i++) {
            bySource.put("source-" + i, embedded[i]);
        }
        return ClaimedArtifactIndex.build(configured, bySource, SbomUtils.normalizeAlgorithm(ALG));
    }

    @Test
    void configuredComponentIndexedByHashWhateverItsPurl() {
        Component npm = component("pkg:npm/react@18.3.1", "h1");

        ClaimedArtifactIndex idx = withConfigured(List.of(bomOf(npm)));

        assertSame(npm, idx.configuredComponent("h1").orElseThrow());
    }

    @Test
    void configuredNestedComponentsIndexed() {
        Component parent = component("pkg:npm/app@1.0", "hp");
        Component child = component("pkg:npm/react@18.3.1", "hc");
        parent.addComponent(child);

        assertSame(child, withConfigured(List.of(bomOf(parent))).configuredComponent("hc").orElseThrow());
    }

    @Test
    void firstConfiguredComponentWinsOnHashConflict() {
        Component first = component("pkg:npm/a@1", "h1");
        Component second = component("pkg:npm/b@1", "h1");

        assertSame(first, withConfigured(List.of(bomOf(first), bomOf(second)))
                .configuredComponent("h1").orElseThrow());
    }

    @Test
    void configuredComponentsDoNotBecomeEmbeddedClaims() {
        // configured SBOMs keep their own claim-and-merge path
        ClaimedArtifactIndex idx = withConfigured(List.of(bomOf(hashMatched(NIMBUS, "h1", 1.0))));

        assertTrue(idx.lookup("h1").isEmpty());
        assertTrue(idx.configuredComponent("h1").isPresent());
    }

    @Test
    void embeddedClaimsDoNotBecomeConfiguredComponents() {
        ClaimedArtifactIndex idx = withConfigured(List.of(), bomOf(hashMatched(NIMBUS, "h1", 1.0)));

        assertTrue(idx.configuredComponent("h1").isEmpty());
        assertTrue(idx.lookup("h1").isPresent());
    }

    @Test
    void configuredComponentLookupNullHashIsEmpty() {
        assertTrue(withConfigured(List.of(bomOf(component(NIMBUS, "h1")))).configuredComponent(null).isEmpty());
    }

    @Test
    void hasClaimsOnlyForEmbeddedClaims() {
        assertFalse(withConfigured(List.of(bomOf(component(NIMBUS, "h1")))).hasClaims(),
                "configured components alone are not embedded claims");
        assertTrue(withConfigured(List.of(), bomOf(hashMatched(NIMBUS, "h1", 1.0))).hasClaims());
        assertFalse(ClaimedArtifactIndex.empty().hasClaims());
    }
}
