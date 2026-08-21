package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class PackageRefTest {

    @Test
    void npmWithoutScope() {
        assertEquals("pkg:npm/left-pad@1.3.0", new NpmPackageRef(null, "left-pad", "1.3.0").toPurl().toString());
    }

    @Test
    void npmWithScopeEncodesAtSign() {
        assertEquals("pkg:npm/%40angular/animation@12.3.1",
                new NpmPackageRef("@angular", "animation", "12.3.1").toPurl().toString());
    }

    @Test
    void npmScopeWithoutAtSignStillEncodes() {
        assertEquals("pkg:npm/%40angular/animation@12.3.1",
                new NpmPackageRef("angular", "animation", "12.3.1").toPurl().toString());
    }

    @Test
    void npmEmptyScopeTreatedAsNone() {
        assertEquals("pkg:npm/left-pad@1.3.0", new NpmPackageRef("", "left-pad", "1.3.0").toPurl().toString());
    }

    @Test
    void npmRequiresNameAndVersion() {
        assertThrows(NullPointerException.class, () -> new NpmPackageRef(null, null, "1.0"));
        assertThrows(NullPointerException.class, () -> new NpmPackageRef(null, "n", null));
    }

    @Test
    void genericNameAndVersion() {
        assertEquals("pkg:generic/jboss-client@8.1.1.GA",
                new GenericPackageRef("jboss-client", "8.1.1.GA").toPurl().toString());
    }

    @Test
    void genericRequiresNameAndVersion() {
        assertThrows(NullPointerException.class, () -> new GenericPackageRef(null, "1.0"));
        assertThrows(NullPointerException.class, () -> new GenericPackageRef("n", null));
    }
}
