package dev.cyberstamp.maven.assembly.sbom.match;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.cyberstamp.maven.assembly.sbom.ArtifactCoords;
import dev.cyberstamp.maven.assembly.sbom.FileEntry;
import dev.cyberstamp.maven.assembly.sbom.Identification;

class MavenArtifactMatcherTest {

    @TempDir
    Path tempDir;

    private static MavenMatch match(String artifactId) {
        return new MavenMatch(ArtifactCoords.of("org.example", artifactId, "1.0"), Identification.remoteCoordinatesLookup());
    }

    @Test
    void chainReturnsFirstMatchAndStopsThere() {
        AtomicInteger thirdCalls = new AtomicInteger();
        MavenArtifactMatcher chain = MavenArtifactMatcher.of(
                file -> Optional.empty(),
                file -> Optional.of(match("second")),
                file -> {
                    thirdCalls.incrementAndGet();
                    return Optional.of(match("third"));
                });

        assertEquals(Optional.of(match("second")), chain.match(new FileEntry("a.jar", "h")));
        assertEquals(0, thirdCalls.get());
    }

    @Test
    void emptyChainMatchesNothing() {
        assertTrue(MavenArtifactMatcher.of().match(new FileEntry("a.jar", "h")).isEmpty());
    }

    @Test
    void cachingMatcherAsksDelegateOncePerContent() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        MavenArtifactMatcher cached = new CachingMatcher(file -> {
            calls.incrementAndGet();
            return Optional.of(match("lib"));
        }, new Sha1Hasher());

        cached.match(entry("a.jar", "same"));
        cached.match(entry("b.jar", "same"));
        cached.match(entry("c.jar", "different"));

        assertEquals(2, calls.get());
    }

    @Test
    void budgetIsSharedAndOnlyConsumedByActualLookups() throws IOException {
        AtomicInteger lookups = new AtomicInteger();
        BudgetedLookup.Budget budget = new BudgetedLookup.Budget("nexus", 1);
        CoordinatesLookup counting = (sha1, fileName) -> {
            lookups.incrementAndGet();
            return Optional.empty();
        };
        MavenArtifactMatcher first = new ChecksumLookupMatcher(new BudgetedLookup(counting, budget), new Sha1Hasher());
        MavenArtifactMatcher second = new ChecksumLookupMatcher(new BudgetedLookup(counting, budget), new Sha1Hasher());

        // no source file, so nothing to look up and no budget spent
        first.match(new FileEntry("unpacked.jar", "h"));
        first.match(entry("a.jar", "a"));

        assertThrows(LookupBudgetExceededException.class, () -> second.match(entry("b.jar", "b")));
        assertEquals(1, lookups.get());
    }

    @Test
    void chainClosesAllMatchersEvenIfOneFails() {
        List<String> closed = new ArrayList<>();
        MavenArtifactMatcher chain = MavenArtifactMatcher.of(
                closing("first", closed, null),
                closing("second", closed, new IllegalStateException("second")),
                closing("third", closed, new IllegalStateException("third")));

        IllegalStateException e = assertThrows(IllegalStateException.class, chain::close);

        assertEquals(List.of("first", "second", "third"), closed);
        assertEquals("second", e.getMessage());
        assertEquals("third", e.getSuppressed()[0].getMessage());
    }

    @Test
    void decoratorsCloseTheirDelegate() {
        List<String> closed = new ArrayList<>();
        MavenArtifactMatcher decorated = PathFilterMatcher.of(
                new CachingMatcher(closing("inner", closed, null), new Sha1Hasher()),
                List.of("*.jar"), List.of()).orElseThrow();

        decorated.close();

        assertEquals(List.of("inner"), closed);
    }

    private static MavenArtifactMatcher closing(String name, List<String> closed, RuntimeException failure) {
        return new MavenArtifactMatcher() {
            @Override
            public Optional<MavenMatch> match(FileEntry file) {
                return Optional.empty();
            }

            @Override
            public void close() {
                closed.add(name);
                if (failure != null) {
                    throw failure;
                }
            }
        };
    }

    private FileEntry entry(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, content);
        return new FileEntry(name, "unused", file.toFile());
    }
}
