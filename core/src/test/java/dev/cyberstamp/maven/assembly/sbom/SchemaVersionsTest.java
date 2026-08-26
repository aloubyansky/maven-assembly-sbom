package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.cyclonedx.Version;
import org.junit.jupiter.api.Test;

class SchemaVersionsTest {

    @Test
    void latestIsTheLastSupportedEnumValue() {
        Version[] all = Version.values();
        assertSame(all[all.length - 1], SchemaVersions.latest());
    }

    @Test
    void resolveNullReturnsLatest() {
        assertSame(SchemaVersions.latest(), SchemaVersions.resolve(null));
    }

    @Test
    void resolveBlankReturnsLatest() {
        assertSame(SchemaVersions.latest(), SchemaVersions.resolve("   "));
    }

    @Test
    void resolveKnownVersionReturnsMatchingConstant() {
        assertSame(Version.VERSION_16, SchemaVersions.resolve("1.6"));
    }

    @Test
    void resolveTrimsWhitespace() {
        assertSame(Version.VERSION_16, SchemaVersions.resolve(" 1.6 "));
    }

    @Test
    void resolveUnknownVersionThrowsWithSupportedList() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SchemaVersions.resolve("9.9"));
        assertTrue(e.getMessage().contains("9.9"));
        assertTrue(e.getMessage().contains(SchemaVersions.latest().getVersionString()),
                "message should list supported versions");
    }
}
