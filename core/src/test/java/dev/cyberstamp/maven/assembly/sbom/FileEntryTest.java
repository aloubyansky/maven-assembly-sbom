package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for the {@link FileEntry} record.
 */
class FileEntryTest {

    @TempDir
    Path tempDir;

    @Test
    void recordAccessorsRoundTrip() {
        String archivePath = "lib/mylib-1.0.jar";
        String hash = "abc123";
        File sourceFile = new File("/tmp/mylib-1.0.jar");

        FileEntry entry = new FileEntry(archivePath, hash, sourceFile);

        assertEquals(archivePath, entry.archivePath());
        assertEquals(hash, entry.hash());
        assertNotNull(entry.sourceFile());
    }

    @Test
    void convenienceConstructorWithNullSourceFile() {
        String archivePath = "conf/settings.xml";
        String hash = "def456";

        FileEntry entry = new FileEntry(archivePath, hash);

        assertEquals(archivePath, entry.archivePath());
        assertEquals(hash, entry.hash());
        assertNull(entry.sourceFile());
    }

    @Test
    void sourceFileNormalizedToCanonicalPath() throws IOException {
        File nonCanonical = tempDir.resolve("subdir").resolve("..").resolve("test.jar").toFile();
        File expected = tempDir.resolve("test.jar").toFile().getCanonicalFile();

        FileEntry entry = new FileEntry("lib/test.jar", "hash", nonCanonical);

        assertEquals(expected, entry.sourceFile());
    }

    @Test
    void sourceFileNullPassedThrough() {
        FileEntry entry = new FileEntry("path", "hash", null);

        assertNull(entry.sourceFile());
    }

    @Test
    void equalityBasedOnAllFields() throws IOException {
        Path jarPath = tempDir.resolve("lib.jar");
        Files.writeString(jarPath, "content");
        File sourceFile = jarPath.toFile().getCanonicalFile();

        FileEntry e1 = new FileEntry("lib/lib.jar", "hash1", sourceFile);
        FileEntry e2 = new FileEntry("lib/lib.jar", "hash1", sourceFile);
        FileEntry e3 = new FileEntry("lib/other.jar", "hash1", sourceFile);

        assertEquals(e1, e2);
        assertNotEquals(e1, e3);
    }
}
