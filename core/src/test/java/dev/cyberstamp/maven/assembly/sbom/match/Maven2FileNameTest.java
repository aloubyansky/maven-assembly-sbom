package dev.cyberstamp.maven.assembly.sbom.match;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;

class Maven2FileNameTest {

    @Test
    void fileNameWithoutClassifierIsTheMainArtifact() {
        assertEquals(new ArtifactCoords("g", "lib", "2.0", "jar", null),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "lib-2.0.jar"));
        assertEquals(new ArtifactCoords("g", "app", "2.0", "war", null),
                Maven2FileName.classifierAndExtension("g", "app", "2.0", "app-2.0.war"));
    }

    @Test
    void fileNameClassifierAndCompoundExtension() {
        assertEquals(new ArtifactCoords("g", "lib", "2.0", "jar", "linux-x86_64"),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "lib-2.0-linux-x86_64.jar"));
        assertEquals(new ArtifactCoords("g", "dist", "2.0", "tar.gz", "bin"),
                Maven2FileName.classifierAndExtension("g", "dist", "2.0", "dist-2.0-bin.tar.gz"));
        assertEquals(new ArtifactCoords("g", "lib", "2.0", "test-jar", null),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "lib-2.0-tests.jar"),
                "jar with the tests classifier is the test-jar type");
    }

    @Test
    void timestampedAndPlainSnapshotFileNames() {
        assertEquals(new ArtifactCoords("g", "lib", "1.0-SNAPSHOT", "jar", "jdk8"),
                Maven2FileName.classifierAndExtension("g", "lib", "1.0-SNAPSHOT", "lib-1.0-20240101.123456-7-jdk8.jar"));
        assertEquals(new ArtifactCoords("g", "lib", "1.0-SNAPSHOT", "jar", null),
                Maven2FileName.classifierAndExtension("g", "lib", "1.0-SNAPSHOT", "lib-1.0-20240101.123456-7.jar"));
        assertEquals(new ArtifactCoords("g", "lib", "1.0-SNAPSHOT", "jar", null),
                Maven2FileName.classifierAndExtension("g", "lib", "1.0-SNAPSHOT", "lib-1.0-SNAPSHOT.jar"));
    }

    @Test
    void unexpectedFileNameFallsBackToCoordinatesWithoutClassifier() {
        assertEquals(ArtifactCoords.of("g", "lib", "2.0"),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "renamed.jar"));
        assertEquals(ArtifactCoords.of("g", "lib", "2.0"),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "lib-2.1.jar"));
        assertEquals(ArtifactCoords.of("g", "lib", "2.0"),
                Maven2FileName.classifierAndExtension("g", "lib", "2.0", "lib-2.0"));
    }
}
