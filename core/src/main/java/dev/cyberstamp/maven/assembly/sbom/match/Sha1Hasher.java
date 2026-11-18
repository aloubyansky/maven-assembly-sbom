package dev.cyberstamp.maven.assembly.sbom.match;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.cyberstamp.maven.assembly.sbom.FileEntry;
import dev.cyberstamp.maven.assembly.sbom.SbomUtils;

/**
 * Computes the SHA-1 of a file entry's source file, which the checksum-search
 * APIs are keyed by regardless of the BOM's configured hash algorithm. Hashes
 * are remembered per file so that several matchers sharing one hasher hash
 * each file only once.
 *
 * <p>
 * Not thread-safe, like the rest of the {@link ArchiveAnalyzer} pipeline.
 * </p>
 */
final class Sha1Hasher {

    private static final Logger log = LoggerFactory.getLogger(Sha1Hasher.class);

    private final MessageDigest digest;
    private final Map<File, Optional<String>> hashes = new HashMap<>();

    Sha1Hasher() {
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is guaranteed to be available on every standard JDK.
            throw new IllegalStateException("SHA-1 digest not available", e);
        }
    }

    /**
     * Returns the lowercase hex SHA-1 of the entry's source file, or empty if
     * the entry has no readable source file.
     */
    Optional<String> sha1(FileEntry entry) {
        File file = entry.sourceFile();
        if (file == null || !file.isFile()) {
            return Optional.empty();
        }
        return hashes.computeIfAbsent(file, this::compute);
    }

    private Optional<String> compute(File file) {
        try {
            return Optional.of(SbomUtils.computeHash(digest, file.toPath()));
        } catch (IOException e) {
            log.warn("Could not hash {} for remote lookup: {}", file, e.toString());
            return Optional.empty();
        }
    }
}
