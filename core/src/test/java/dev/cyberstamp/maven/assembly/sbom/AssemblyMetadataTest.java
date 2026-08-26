package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

class AssemblyMetadataTest {

    @Test
    void roundTripsProjectCoordinates() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("my-app");
        metadata.setProjectVersion("1.0.0");

        assertEquals("org.example", metadata.getProjectGroupId());
        assertEquals("my-app", metadata.getProjectArtifactId());
        assertEquals("1.0.0", metadata.getProjectVersion());
    }

    @Test
    void roundTripsAssemblyId() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setAssemblyId("dist");
        assertEquals("dist", metadata.getAssemblyId());
    }

    @Test
    void roundTripsTimestamp() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        assertNull(metadata.getTimestamp());
        Date now = new Date();
        metadata.setTimestamp(now);
        assertSame(now, metadata.getTimestamp());
    }

    @Test
    void roundTripsHashAlgorithmSpec() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setHashAlgorithmSpec("SHA-256");
        assertEquals("SHA-256", metadata.getHashAlgorithmSpec());
    }

    @Test
    void roundTripsClassifier() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setClassifier("bin");
        assertEquals("bin", metadata.getClassifier());
    }

    @Test
    void roundTripsArchiveType() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setArchiveType("zip");
        assertEquals("zip", metadata.getArchiveType());
    }

    @Test
    void roundTripsProjectLicenses() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        assertNotNull(metadata.getProjectLicenses());
        assertTrue(metadata.getProjectLicenses().isEmpty());

        List<LicenseInfo> licenses = List.of(
                LicenseInfo.spdx("Apache-2.0"),
                LicenseInfo.spdx("MIT"));
        metadata.setProjectLicenses(licenses);

        assertEquals(2, metadata.getProjectLicenses().size());
        assertEquals("Apache-2.0", metadata.getProjectLicenses().get(0).spdxId());
        assertEquals("MIT", metadata.getProjectLicenses().get(1).spdxId());
    }

    @Test
    void projectLicensesAreDefensiveCopy() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        List<LicenseInfo> licenses = List.of(LicenseInfo.spdx("Apache-2.0"));
        metadata.setProjectLicenses(licenses);

        assertThrows(UnsupportedOperationException.class,
                () -> metadata.getProjectLicenses().add(LicenseInfo.spdx("MIT")));
    }

    @Test
    void roundTripsToolMetadata() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setToolGroupId("dev.cyberstamp");
        metadata.setToolArtifactId("maven-assembly-sbom");
        metadata.setToolVersion("1.0.0");

        assertEquals("dev.cyberstamp", metadata.getToolGroupId());
        assertEquals("maven-assembly-sbom", metadata.getToolArtifactId());
        assertEquals("1.0.0", metadata.getToolVersion());
    }

    @Test
    void roundTripsToolLicenses() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        assertNotNull(metadata.getToolLicenses());
        assertTrue(metadata.getToolLicenses().isEmpty());

        List<LicenseInfo> licenses = List.of(LicenseInfo.spdx("Apache-2.0"));
        metadata.setToolLicenses(licenses);

        assertEquals(1, metadata.getToolLicenses().size());
        assertEquals("Apache-2.0", metadata.getToolLicenses().get(0).spdxId());
    }

    @Test
    void toolLicensesAreDefensiveCopy() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        List<LicenseInfo> licenses = List.of(LicenseInfo.spdx("Apache-2.0"));
        metadata.setToolLicenses(licenses);

        assertThrows(UnsupportedOperationException.class,
                () -> metadata.getToolLicenses().add(LicenseInfo.spdx("MIT")));
    }

    @Test
    void roundTripsToolHash() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setToolHash("abc123def456");
        assertEquals("abc123def456", metadata.getToolHash());
    }

    @Test
    void roundTripsProduct() {
        AssemblyMetadata metadata = new AssemblyMetadata();
        assertNull(metadata.getProduct());

        ProductInfo product = new ProductInfo();
        product.setCpe("cpe:2.3:a:example:myapp:1.0:*:*:*:*:*:*:*");
        metadata.setProduct(product);

        assertSame(product, metadata.getProduct());
        assertEquals("cpe:2.3:a:example:myapp:1.0:*:*:*:*:*:*:*", metadata.getProduct().getCpe());
    }
}
