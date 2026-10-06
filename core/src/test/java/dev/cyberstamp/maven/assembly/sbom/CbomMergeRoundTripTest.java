package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;

import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Round-trip tests proving that Cryptography Bill of Materials (CBOM) content —
 * {@code cryptographic-asset} components and their {@code cryptoProperties} — is
 * preserved when an external CycloneDX CBOM is merged into a distribution SBOM.
 *
 * <p>
 * This project does not <em>generate</em> CBOM data (that requires static
 * analysis of source/bytecode, done by dedicated tools such as IBM's
 * sonar-cryptography / CBOMkit or cdxgen's {@code --include-crypto}). Instead it
 * <em>consumes</em> CBOMs via the external/embedded SBOM merge paths, the same
 * way it integrates npm/JS SBOMs. These tests exercise the full pipeline a user
 * hits with {@code externalSboms}: a CBOM file on disk is read, merged, written
 * back out, and re-read — and the crypto data must survive every hop.
 * </p>
 *
 * <p>
 * Crypto properties require CycloneDX schema 1.6 or later; the serialization
 * steps here pin {@link Version#VERSION_16} so the round trip reflects a schema
 * that can actually carry the data.
 * </p>
 */
class CbomMergeRoundTripTest {

    private static final Version CBOM_SCHEMA = Version.VERSION_16;

    private static final String BC_REF = "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1";
    private static final String CRYPTO_REF = "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1";
    private static final String CRYPTO_OID = "1.2.840.113549.1.1.1";

    @Test
    void cryptographicAssetComponentSurvivesMergeRoundTrip(@TempDir Path tmp) throws Exception {
        Bom merged = mergeExternalCbomThroughDisk(tmp);

        Component crypto = findByBomRef(merged.getComponents(), CRYPTO_REF);
        assertNotNull(crypto, "cryptographic-asset component should survive the merge round trip");
        assertEquals(Component.Type.CRYPTOGRAPHIC_ASSET, crypto.getType(),
                "component type should remain cryptographic-asset");
        assertEquals("RSA-2048", crypto.getName());
    }

    @Test
    void cryptoPropertiesSurviveMergeRoundTrip(@TempDir Path tmp) throws Exception {
        Bom merged = mergeExternalCbomThroughDisk(tmp);

        Component crypto = findByBomRef(merged.getComponents(), CRYPTO_REF);
        assertNotNull(crypto);
        CryptoProperties props = crypto.getCryptoProperties();
        assertNotNull(props, "cryptoProperties must not be dropped by read/merge/write");
        assertEquals(AssetType.ALGORITHM, props.getAssetType());
        assertEquals(CRYPTO_OID, props.getOid(), "algorithm OID should be preserved");

        AlgorithmProperties alg = props.getAlgorithmProperties();
        assertNotNull(alg, "algorithmProperties should be preserved");
        assertEquals(Primitive.PKE, alg.getPrimitive());
        assertEquals("2048", alg.getParameterSetIdentifier());
        assertEquals(Integer.valueOf(0), alg.getNistQuantumSecurityLevel(),
                "nistQuantumSecurityLevel should be preserved");
    }

    @Test
    void cryptoDependencyEdgeSurvivesMergeRoundTrip(@TempDir Path tmp) throws Exception {
        Bom merged = mergeExternalCbomThroughDisk(tmp);

        Dependency bcDep = findDependency(merged.getDependencies(), BC_REF);
        assertNotNull(bcDep, "the crypto library's dependency entry should be imported");
        assertNotNull(bcDep.getDependencies(), "its dependsOn edges should be imported");
        assertTrue(bcDep.getDependencies().stream()
                .anyMatch(d -> CRYPTO_REF.equals(d.getRef())),
                "the library -> crypto-asset dependsOn edge should survive the round trip");
    }

    /**
     * Simulates the full external-CBOM pipeline: build a CBOM as a tool would
     * emit it, write it to disk, read it back (as {@code externalSboms} does),
     * merge it flat into a distribution BOM, then write and re-read the merged
     * BOM. Returns the re-parsed merged BOM.
     */
    private static Bom mergeExternalCbomThroughDisk(Path tmp) throws Exception {
        Path cbomFile = tmp.resolve("crypto.cdx.json");
        BomWriter.writeJson(buildExternalCbom(), cbomFile, true, CBOM_SCHEMA);

        Bom externalCbom = BomReader.readBom(cbomFile.toFile());
        assertNotNull(externalCbom, "external CBOM should parse");

        Bom distribution = buildDistributionBom();
        BomMerger.mergeFlat(distribution, externalCbom);

        Path mergedFile = tmp.resolve("bom.cdx.json");
        BomWriter.writeJson(distribution, mergedFile, true, CBOM_SCHEMA);

        Bom reread = BomReader.readBom(mergedFile.toFile());
        assertNotNull(reread, "merged BOM should parse");
        return reread;
    }

    /**
     * A CBOM as produced by a crypto scanner: a crypto library component, a
     * {@code cryptographic-asset} component describing an algorithm it provides,
     * and a dependency edge connecting the two.
     */
    private static Bom buildExternalCbom() {
        Bom bom = new Bom();

        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("scanned-app");
        main.setBomRef("pkg:maven/com.example/scanned-app@1.0");
        metadata.setComponent(main);
        bom.setMetadata(metadata);

        Component bc = new Component();
        bc.setType(Component.Type.LIBRARY);
        bc.setGroup("org.bouncycastle");
        bc.setName("bcprov-jdk18on");
        bc.setVersion("1.78.1");
        bc.setBomRef(BC_REF);
        bc.setPurl(BC_REF);

        Component crypto = new Component();
        crypto.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        crypto.setName("RSA-2048");
        crypto.setBomRef(CRYPTO_REF);

        AlgorithmProperties alg = new AlgorithmProperties();
        alg.setPrimitive(Primitive.PKE);
        alg.setParameterSetIdentifier("2048");
        alg.setNistQuantumSecurityLevel(0);

        CryptoProperties cryptoProps = new CryptoProperties();
        cryptoProps.setAssetType(AssetType.ALGORITHM);
        cryptoProps.setAlgorithmProperties(alg);
        cryptoProps.setOid(CRYPTO_OID);
        crypto.setCryptoProperties(cryptoProps);

        bom.setComponents(new java.util.ArrayList<>(List.of(bc, crypto)));

        Dependency bcDep = new Dependency(BC_REF);
        bcDep.addDependency(new Dependency(CRYPTO_REF));
        bom.addDependency(bcDep);
        bom.addDependency(new Dependency(CRYPTO_REF));

        return bom;
    }

    private static Bom buildDistributionBom() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component main = new Component();
        main.setType(Component.Type.APPLICATION);
        main.setName("dist");
        main.setBomRef("pkg:maven/com.example/dist@1.0");
        metadata.setComponent(main);
        bom.setMetadata(metadata);
        bom.addDependency(new Dependency("pkg:maven/com.example/dist@1.0"));
        return bom;
    }

    private static Component findByBomRef(List<Component> components, String bomRef) {
        if (components == null) {
            return null;
        }
        for (Component c : components) {
            if (bomRef.equals(c.getBomRef())) {
                return c;
            }
        }
        return null;
    }

    private static Dependency findDependency(List<Dependency> deps, String ref) {
        if (deps == null) {
            return null;
        }
        return deps.stream().filter(d -> ref.equals(d.getRef())).findFirst().orElse(null);
    }
}
