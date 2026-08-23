package dev.cyberstamp.maven.assembly.sbom;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * An archive file entry pairing its path with its content hash
 * and an optional reference to the source file on disk.
 *
 * <p>
 * The {@code sourceFile} is normalized to its canonical path on
 * construction. This normalization ensures consistent path
 * comparison when detecting project-local files versus external
 * dependencies.
 * </p>
 */
record FileEntry(String archivePath, String hash, File sourceFile) {
    FileEntry(String archivePath, String hash, File sourceFile) {
        this.archivePath = archivePath;
        this.hash = hash;
        this.sourceFile = normalizeFile(sourceFile);
    }

    private static File normalizeFile(File file) {
        if (file == null) {
            return null;
        }
        try {
            return file.getCanonicalFile();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    FileEntry(String archivePath, String hash) {
        this(archivePath, hash, null);
    }
}
