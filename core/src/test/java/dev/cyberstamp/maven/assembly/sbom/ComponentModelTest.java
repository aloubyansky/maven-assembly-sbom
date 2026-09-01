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
    void dependenciesKnownDefaultsTrueAndIsSettable() {
        PackageComponent known = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null);
        assertTrue(known.dependenciesKnown());

        PackageComponent unknown = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null, false);
        assertFalse(unknown.dependenciesKnown());
    }

    @Test
    void withersReturnSameInstanceWhenUnchanged() {
        PackageComponent pc = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null, false);
        // No licenses / no nested → replacing with empty is a no-op, no allocation.
        assertSame(pc, pc.withLicenses(List.of()));
        assertSame(pc, pc.withNested(List.of()));
        assertSame(pc, pc.withLicenses(null));
        assertSame(pc, pc.withNested(null));
        // Same list instance → no-op.
        assertSame(pc, pc.withLicenses(pc.licenses()));
        assertSame(pc, pc.withNested(pc.nested()));
    }

    @Test
    void withersPreserveDependenciesKnown() {
        PackageComponent pc = PackageComponent.of(
                ArtifactCoords.of("org.example", "foo", "1.0"), null, null, false);
        PackageComponent withLic = pc.withLicenses(List.of(LicenseInfo.spdx("Apache-2.0")));
        assertNotSame(pc, withLic);
        assertFalse(withLic.dependenciesKnown());

        PackageComponent child = PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null);
        PackageComponent withNested = pc.withNested(List.of(child));
        assertNotSame(pc, withNested);
        assertFalse(withNested.dependenciesKnown());
    }

    @Test
    void componentIsSealedOverTwoKinds() {
        AssemblyComponent pkg = PackageComponent.of(ArtifactCoords.of("g", "a", "1"), null, null);
        AssemblyComponent file = new FileComponent("f", null, List.of());
        assertTrue(pkg instanceof PackageComponent);
        assertTrue(file instanceof FileComponent);
    }
}
