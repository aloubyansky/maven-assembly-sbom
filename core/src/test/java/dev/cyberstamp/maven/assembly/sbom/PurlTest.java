package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

import org.junit.jupiter.api.Test;

class PurlTest {

    @Test
    void mavenPurlDefaultType() {
        Purl purl = Purl.maven("io.quarkus", "quarkus-rest", "3.0.0");
        assertEquals("pkg:maven/io.quarkus/quarkus-rest@3.0.0?type=jar", purl.toString());
        assertEquals("maven", purl.getType());
        assertEquals("io.quarkus", purl.getNamespace());
        assertEquals("quarkus-rest", purl.getName());
        assertEquals("3.0.0", purl.getVersion());
        assertEquals(Map.of("type", "jar"), purl.getQualifiers());
        assertNull(purl.getSubpath());
    }

    @Test
    void mavenPurlWithClassifier() {
        Purl purl = Purl.maven("org.acme", "acme-app", "1.0-SNAPSHOT", "jar", "runner");
        assertEquals("pkg:maven/org.acme/acme-app@1.0-SNAPSHOT?classifier=runner&type=jar", purl.toString());
        assertEquals(Map.of("classifier", "runner", "type", "jar"), purl.getQualifiers());
    }

    @Test
    void mavenPurlWithoutClassifier() {
        Purl purl = Purl.maven("org.acme", "acme-app", "1.0-SNAPSHOT", "jar", null);
        assertEquals("pkg:maven/org.acme/acme-app@1.0-SNAPSHOT?type=jar", purl.toString());
    }

    @Test
    void npmPurlWithScope() {
        Purl purl = Purl.npm("@babel", "core", "7.20.0");
        assertEquals("pkg:npm/%40babel/core@7.20.0", purl.toString());
        assertEquals("@babel", purl.getNamespace());
        assertTrue(purl.getQualifiers().isEmpty());
    }

    @Test
    void npmPurlWithoutScope() {
        Purl purl = Purl.npm(null, "lodash", "4.17.21");
        assertEquals("pkg:npm/lodash@4.17.21", purl.toString());
        assertNull(purl.getNamespace());
    }

    @Test
    void npmNameIsLowercased() {
        assertEquals("lodash", Purl.npm(null, "Lodash", "4.0").getName());
    }

    @Test
    void npmScopedNameIsLowercased() {
        Purl purl = Purl.npm("@Babel", "Core", "7.0");
        assertEquals("core", purl.getName());
        assertEquals("@Babel", purl.getNamespace());
    }

    @Test
    void parseNpmNameIsLowercased() {
        assertEquals("lodash", Purl.parse("pkg:npm/Lodash@4.0").getName());
    }

    @Test
    void genericPurl() {
        Purl purl = Purl.generic("quarkus-run.jar", "1.0-SNAPSHOT");
        assertEquals("pkg:generic/quarkus-run.jar@1.0-SNAPSHOT", purl.toString());
    }

    @Test
    void genericPurlNullVersion() {
        Purl purl = Purl.generic("some-file.txt", null);
        assertEquals("pkg:generic/some-file.txt", purl.toString());
        assertNull(purl.getVersion());
    }

    @Test
    void ofFactory() {
        Purl purl = Purl.of("cargo", null, "serde", "1.0.0");
        assertEquals("pkg:cargo/serde@1.0.0", purl.toString());
    }

    @Test
    void emptyNamespaceIsNull() {
        assertNull(Purl.of("npm", "", "lodash", "4.0").getNamespace());
    }

    @Test
    void emptyClassifierNotIncluded() {
        Purl purl = Purl.maven("org.acme", "acme", "1.0", "jar", "");
        assertEquals("pkg:maven/org.acme/acme@1.0?type=jar", purl.toString());
    }

    @Test
    void builderMinimal() {
        Purl purl = Purl.builder().setType("pypi").setName("requests").build();
        assertEquals("pkg:pypi/requests", purl.toString());
        assertNull(purl.getVersion());
    }

    @Test
    void builderWithAllFields() {
        Purl purl = Purl.builder().setType("maven").setNamespace("io.quarkus")
                .setName("quarkus-core").setVersion("3.0.0").addQualifier("type", "jar")
                .setSubpath("src/main").build();
        assertEquals("pkg:maven/io.quarkus/quarkus-core@3.0.0?type=jar#src/main", purl.toString());
        assertEquals("src/main", purl.getSubpath());
    }

    @Test
    void qualifiersSortedAlphabetically() {
        Purl purl = Purl.maven("org.acme", "acme", "1.0", "jar", "sources");
        String s = purl.toString();
        assertTrue(s.indexOf("classifier=") < s.indexOf("type="));
    }

    @Test
    void nullTypeThrows() {
        assertThrows(NullPointerException.class, () -> Purl.builder().setName("foo").build());
    }

    @Test
    void nullNameThrows() {
        assertThrows(NullPointerException.class, () -> Purl.builder().setType("npm").build());
    }

    @Test
    void emptyNameThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.builder().setType("npm").setName("").build())
                .getMessage().contains("name must not be empty"));
    }

    @Test
    void emptyTypeThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.builder().setType("").setName("foo").build())
                .getMessage().contains("type must not be empty"));
    }

    @Test
    void typeStartingWithDigitThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.of("1bad", null, "foo", "1.0"))
                .getMessage().contains("must start with a letter"));
    }

    @Test
    void typeWithInvalidCharThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.of("ba$d", null, "foo", "1.0"))
                .getMessage().contains("invalid character"));
    }

    @Test
    void typeWithDotsAndPlusesAndDashesAllowed() {
        assertEquals("my.type+v2-beta", Purl.of("my.type+v2-beta", null, "foo", "1.0").getType());
    }

    @Test
    void mavenNullGroupIdThrows() {
        assertTrue(assertThrows(NullPointerException.class,
                () -> Purl.maven(null, "artifact", "1.0")).getMessage().contains("groupId"));
    }

    @Test
    void mavenNullArtifactIdThrows() {
        assertTrue(assertThrows(NullPointerException.class,
                () -> Purl.maven("com.foo", null, "1.0")).getMessage().contains("artifactId"));
    }

    @Test
    void mavenRequiresNamespace() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.of("maven", null, "foo", "1.0")).getMessage().contains("namespace"));
    }

    @Test
    void mavenParseRequiresNamespace() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.parse("pkg:maven/foo@1.0")).getMessage().contains("namespace"));
    }

    @Test
    void equalsAndHashCode() {
        Purl a = Purl.maven("io.quarkus", "quarkus-rest", "3.0.0");
        Purl b = Purl.maven("io.quarkus", "quarkus-rest", "3.0.0");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void notEqual() {
        assertNotEquals(Purl.maven("io.quarkus", "quarkus-rest", "3.0.0"),
                Purl.maven("io.quarkus", "quarkus-rest", "3.1.0"));
    }

    @Test
    void parseInvalidNoPkgPrefix() {
        assertThrows(IllegalArgumentException.class, () -> Purl.parse("maven/io.quarkus/foo@1.0"));
    }

    @Test
    void parseNull() {
        assertThrows(NullPointerException.class, () -> Purl.parse(null));
    }

    @Test
    void parseRoundTripMaven() {
        Purl original = Purl.maven("org.acme", "acme-app", "1.0-SNAPSHOT", "jar", "runner");
        Purl parsed = Purl.parse(original.toString());
        assertEquals(original, parsed);
        assertEquals(original.toString(), parsed.toString());
        assertEquals(Map.of("classifier", "runner", "type", "jar"), parsed.getQualifiers());
    }

    @Test
    void parseRoundTripNpmScoped() {
        Purl original = Purl.npm("@babel", "core", "7.20.0");
        assertEquals(original, Purl.parse(original.toString()));
    }

    @Test
    void parseRoundTripGeneric() {
        Purl original = Purl.generic("quarkus-run.jar", "1.0-SNAPSHOT");
        assertEquals(original, Purl.parse(original.toString()));
    }

    @Test
    void parseDebPurl() {
        Purl purl = Purl.parse("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie");
        assertEquals("debian", purl.getNamespace());
        assertEquals(Map.of("arch", "i386", "distro", "jessie"), purl.getQualifiers());
    }

    @Test
    void parseGolangPurlWithSubpath() {
        Purl purl = Purl.parse("pkg:golang/google.golang.org/genproto#googleapis/api/annotations");
        assertEquals("google.golang.org", purl.getNamespace());
        assertEquals("genproto", purl.getName());
        assertEquals("googleapis/api/annotations", purl.getSubpath());
    }

    @Test
    void parseNpmScopedPurl() {
        Purl purl = Purl.parse("pkg:npm/%40angular/animation@12.3.1");
        assertEquals("@angular", purl.getNamespace());
        assertEquals("animation", purl.getName());
    }

    @Test
    void parseMavenPurlWithRepositoryUrl() {
        Purl purl = Purl.parse(
                "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources&repository_url=repo.acme.org%2Frelease");
        assertEquals(Map.of("packaging", "sources", "repository_url", "repo.acme.org/release"),
                purl.getQualifiers());
    }

    @Test
    void parseBothSlashEncodingVariantsProduceSameResult() {
        Purl encoded = Purl.parse(
                "pkg:maven/org.apache.james/apache-mime4j-storage@0.8.9.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar");
        Purl unencoded = Purl.parse(
                "pkg:maven/org.apache.james/apache-mime4j-storage@0.8.9.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar");
        assertEquals(encoded, unencoded);
    }

    @Test
    void toStringDoesNotEncodeSlashesAndColonsInQualifierValues() {
        Purl purl = Purl.builder().setType("maven").setNamespace("org.apache.james")
                .setName("apache-mime4j-storage").setVersion("0.8.9.redhat-00001")
                .addQualifier("repository_url", "https://maven.repository.redhat.com/ga/")
                .addQualifier("type", "jar").build();
        assertEquals(
                "pkg:maven/org.apache.james/apache-mime4j-storage@0.8.9.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
                purl.toString());
    }

    @Test
    void percentEncodeProducesTwoDigitHex() {
        assertEquals("%09", Purl.percentEncode("\t"));
        assertEquals("%00", Purl.percentEncode("\0"));
        assertEquals("%20", Purl.percentEncode(" "));
    }

    @Test
    void percentDecodeHandlesMultiByteUtf8() {
        assertEquals("é", Purl.percentDecode("%C3%A9"));
        assertEquals("clément", Purl.percentDecode("cl%C3%A9ment"));
    }

    @Test
    void percentDecodeMalformedThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.percentDecode("foo%ZZbar")).getMessage().contains("Invalid percent-encoding"));
    }

    @Test
    void percentDecodeLonePercentThrows() {
        assertThrows(IllegalArgumentException.class, () -> Purl.percentDecode("foo%"));
    }

    @Test
    void parseQualifierEmptyKeyThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.parse("pkg:maven/g/a@1.0?=value")).getMessage().contains("empty key"));
    }

    @Test
    void parseQualifierMissingEqualsThrows() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.parse("pkg:maven/g/a@1.0?noequals")).getMessage().contains("missing '='"));
    }

    @Test
    void parseQualifierKeysAreLowercased() {
        assertTrue(Purl.parse("pkg:maven/g/a@1.0?Type=jar").getQualifiers().containsKey("type"));
    }

    @Test
    void parseTypeIsCaseInsensitive() {
        assertEquals("maven", Purl.parse("pkg:Maven/io.quarkus/quarkus-core@1.0").getType());
    }

    @Test
    void parseTrailingSlashRejectsEmptyName() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> Purl.parse("pkg:maven/com.foo/")).getMessage().contains("name must not be empty"));
    }

    @Test
    void parseTrailingAtNormalizesVersionToNull() {
        assertNull(Purl.parse("pkg:maven/com.foo/bar@").getVersion());
    }

    @Test
    void encodePathEncodesSpecialCharsInSegments() {
        Purl purl = Purl.builder().setType("generic").setNamespace("org/@special")
                .setName("foo").setVersion("1.0").build();
        assertTrue(purl.toString().contains("org/%40special"));
        assertEquals("org/@special", Purl.parse(purl.toString()).getNamespace());
    }

    @Test
    void roundTripWithUnicodeInName() {
        Purl purl = Purl.builder().setType("generic").setName("clément").setVersion("1.0").build();
        assertEquals(purl, Purl.parse(purl.toString()));
    }

    @Test
    void parsePkgDoubleSlash() {
        Purl purl = Purl.parse("pkg://maven/io.quarkus/quarkus-core@1.0?type=jar");
        assertEquals("io.quarkus", purl.getNamespace());
        assertEquals("quarkus-core", purl.getName());
    }

    @Test
    void subpathDotSegmentsDiscarded() {
        Purl purl = Purl.builder().setType("generic").setName("foo").setVersion("1.0")
                .setSubpath("./src/../main").build();
        assertEquals("src/main", purl.getSubpath());
    }

    @Test
    void subpathAllDotsBecomesNull() {
        Purl purl = Purl.builder().setType("generic").setName("foo").setVersion("1.0")
                .setSubpath(".").build();
        assertNull(purl.getSubpath());
    }

    @Test
    void subpathEmptySegmentsDiscarded() {
        Purl purl = Purl.builder().setType("generic").setName("foo").setVersion("1.0")
                .setSubpath("src//main").build();
        assertEquals("src/main", purl.getSubpath());
    }
}
