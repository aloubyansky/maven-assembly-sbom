package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundledArtifactScannerTest {

    @TempDir
    Path tempDir;

    private Path jar(String name, String[]... gavs) throws Exception {
        Path jar = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("x".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            for (String[] g : gavs) {
                jos.putNextEntry(new JarEntry(
                        "META-INF/maven/" + g[0] + "/" + g[1] + "/pom.properties"));
                jos.write(("groupId=" + g[0] + "\nartifactId=" + g[1] + "\nversion=" + g[2] + "\n")
                        .getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
        }
        return jar;
    }

    private void writeProps(Path dir, String g, String a, String v) throws Exception {
        Path p = dir.resolve("META-INF/maven/" + g + "/" + a + "/pom.properties");
        Files.createDirectories(p.getParent());
        Files.writeString(p, "groupId=" + g + "\nartifactId=" + a + "\nversion=" + v + "\n");
    }

    @Test
    void returnsNonOwnerFromPath() throws Exception {
        Path j = jar("a.jar", new String[] { "g", "owner", "1" }, new String[] { "g2", "dep", "2" });
        List<ArtifactCoords> r = BundledArtifactScanner.bundledNonOwner(
                j, ArtifactCoords.of("g", "owner", "1"));
        assertEquals(1, r.size());
        assertEquals("pkg:maven/g2/dep@2", r.get(0).toPurl().toString());
    }

    @Test
    void singleDescriptorReturnsEmpty() throws Exception {
        Path j = jar("a.jar", new String[] { "g", "owner", "1" });
        assertTrue(BundledArtifactScanner.bundledNonOwner(
                j, ArtifactCoords.of("g", "owner", "1")).isEmpty());
    }

    @Test
    void readsFromInputStream() throws Exception {
        Path j = jar("a.jar", new String[] { "g", "owner", "1" }, new String[] { "g2", "dep", "2" });
        try (InputStream is = Files.newInputStream(j)) {
            List<ArtifactCoords> r = BundledArtifactScanner.bundledNonOwner(
                    is, ArtifactCoords.of("g", "owner", "1"));
            assertEquals(1, r.size());
            assertEquals("dep", r.get(0).artifactId());
        }
    }

    @Test
    void missingJarReturnsEmpty() {
        assertTrue(BundledArtifactScanner.bundledNonOwner(
                tempDir.resolve("nope.jar"), ArtifactCoords.of("g", "a", "1")).isEmpty());
    }

    @Test
    void explodedDirectoryIsScannedForShaded() throws Exception {
        Path dir = Files.createDirectory(tempDir.resolve("classes"));
        writeProps(dir, "g", "owner", "1");
        writeProps(dir, "g2", "dep", "2");
        List<ArtifactCoords> r = BundledArtifactScanner.bundledNonOwner(
                dir, ArtifactCoords.of("g", "owner", "1"));
        assertEquals(1, r.size());
        assertEquals("dep", r.get(0).artifactId());
    }

    @Test
    void explodedDirectoryWithOnlyOwnerReturnsEmpty() throws Exception {
        Path dir = Files.createDirectory(tempDir.resolve("classes"));
        writeProps(dir, "g", "owner", "1");
        assertTrue(BundledArtifactScanner.bundledNonOwner(
                dir, ArtifactCoords.of("g", "owner", "1")).isEmpty());
    }

    @Test
    void nonArchiveRegularFileReturnsEmpty() throws Exception {
        Path notAJar = Files.writeString(tempDir.resolve("lib.so"), "native");
        assertTrue(BundledArtifactScanner.bundledNonOwner(
                notAJar, ArtifactCoords.of("g", "a", "1")).isEmpty());
    }
}
