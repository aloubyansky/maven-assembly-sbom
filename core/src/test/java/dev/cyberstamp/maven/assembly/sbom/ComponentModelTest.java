package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

class ComponentModelTest {

    @Test
    void packageComponentOfDefaultsEmptyCollections() {
        PackageComponent pc = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), "lib/foo.jar", "abc123");
        assertEquals("pkg:maven/org.example/foo@1.0", pc.ref().toPurl().toString());
        assertEquals("lib/foo.jar", pc.archivePath());
        assertEquals("abc123", pc.hash());
        assertTrue(pc.licenses().isEmpty());
        assertTrue(pc.nested().isEmpty());
    }

    @Test
    void packageComponentRequiresRef() {
        assertThrows(NullPointerException.class,
                () -> new PackageComponent(null, null, null, List.of(), List.of()));
    }

    @Test
    void packageComponentCopiesAndCanNest() {
        PackageComponent child = PackageComponent.of(
                ArtifactCoords.of("org.eclipse.angus", "angus-core", "2.0.5"), null, null);
        PackageComponent parent = new PackageComponent(
                ArtifactCoords.of("org.eclipse.angus", "angus-mail", "2.0.5"),
                "lib/angus-mail.jar", "hash",
                List.of(LicenseInfo.spdx("EPL-2.0")),
                List.of(child));
        assertEquals(1, parent.nested().size());
        assertSame(child, parent.nested().get(0));
        assertEquals("EPL-2.0", parent.licenses().get(0).spdxId());
    }

    @Test
    void packageComponentListsAreImmutable() {
        PackageComponent pc = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null);
        assertThrows(UnsupportedOperationException.class, () -> pc.nested().add(pc));
    }

    @Test
    void fileComponentHasNoLicensesAndRequiresPath() {
        FileComponent fc = new FileComponent("bin/launcher", "deadbeef", List.of());
        assertEquals("bin/launcher", fc.archivePath());
        assertEquals("deadbeef", fc.hash());
        assertTrue(fc.licenses().isEmpty());
        assertThrows(NullPointerException.class, () -> new FileComponent(null, null, List.of()));
    }

    @Test
    void componentIsSealedOverTwoKinds() {
        AssemblyComponent pkg = PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null);
        AssemblyComponent file = new FileComponent("f", null, List.of());
        assertTrue(pkg instanceof PackageComponent);
        assertTrue(file instanceof FileComponent);
    }
}
