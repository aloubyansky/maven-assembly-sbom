package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.cyclonedx.Format;
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Byte-identity regression guard for {@link BomRenderer}.
 *
 * <p>
 * The purpose of this test is to guarantee that SBOM output stays
 * byte-for-byte stable. The other tests assert that structurally (component
 * fields, nesting, dependency edges); this one pins the actual serialized
 * bytes: it builds a fixed {@link AssemblyComponents} model exercising the
 * tricky paths (occurrence merge on a duplicate PURL, a nested/shaded
 * component, a plain FILE component, an inter-artifact dependency edge, and
 * all three license shapes), renders it, serializes it and compares against
 * a checked-in golden document.
 * </p>
 *
 * <p>
 * Because the input model is fixed and the timestamp/schema version are pinned,
 * the output — including the content-derived {@code serialNumber} — is fully
 * deterministic. If a change to the rendering or serialization path alters the
 * output, this test fails with a full diff. When the change is intentional,
 * regenerate the golden with:
 * </p>
 *
 * <pre>{@code mvn -pl core test -Dtest=GoldenBomTest -Dgolden.regenerate=true}</pre>
 *
 * <p>
 * then review the resulting diff in
 * {@code core/src/test/resources/golden/assembly-golden.cdx.json} before
 * committing.
 * </p>
 */
class GoldenBomTest {

    private static final String GOLDEN_RESOURCE = "/golden/assembly-golden.cdx.json";
    private static final Path GOLDEN_SOURCE_PATH = Path.of("src/test/resources/golden/assembly-golden.cdx.json");

    /** Pinned so the golden bytes never drift with the CycloneDX library default. */
    private static final String SCHEMA_VERSION = "1.6";

    @TempDir
    Path tempDir;

    @Test
    void renderedBomMatchesGolden() throws Exception {
        Bom bom = new BomRenderer().render(buildFixedModel());
        Version schemaVersion = SchemaVersions.resolve(SCHEMA_VERSION);
        Path out = tempDir.resolve("golden.cdx.json");
        BomWriter.writeJson(bom, out, true, schemaVersion);
        String actual = Files.readString(out);

        if (Boolean.getBoolean("golden.regenerate")) {
            Files.createDirectories(GOLDEN_SOURCE_PATH.getParent());
            Files.writeString(GOLDEN_SOURCE_PATH, actual, StandardCharsets.UTF_8);
            System.out.println("Regenerated golden: " + GOLDEN_SOURCE_PATH.toAbsolutePath());
            return;
        }

        String expected = readGolden();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode expectedJson = mapper.readTree(expected);
        JsonNode actualJson = mapper.readTree(actual);

        boolean identical = expectedJson.equals(actualJson);

        assertTrue(identical,
                "Rendered BOM diverged from the golden document. If this change is "
                        + "intentional, regenerate with -Dgolden.regenerate=true and review the diff.");
    }

    /**
     * Schema conformance guard: the rendered document must validate against the
     * official CycloneDX JSON schema for <em>every</em> version this producer
     * can be asked to emit — not just the {@value #SCHEMA_VERSION} the golden
     * pins, since the plugin default is {@link SchemaVersions#latest()}.
     *
     * <p>
     * {@link #renderedBomMatchesGolden()} only pins the bytes, so a golden that
     * is itself schema-invalid would be regenerated and committed without
     * complaint. This test is what makes the golden meaningful.
     * </p>
     */
    @ParameterizedTest(name = "CycloneDX {0}")
    @MethodSource("supportedVersions")
    void renderedBomIsSchemaValid(Version schemaVersion) throws Exception {
        Bom bom = new BomRenderer().render(buildFixedModel());
        Path out = tempDir.resolve("validate-" + schemaVersion.getVersionString() + ".cdx.json");
        BomWriter.writeJson(bom, out, true, schemaVersion);

        List<ParseException> errors = new JsonParser().validate(out.toFile(), schemaVersion);
        assertTrue(errors.isEmpty(),
                () -> "Rendered BOM is not valid against CycloneDX "
                        + schemaVersion.getVersionString() + ":\n"
                        + errors.stream().map(Throwable::getMessage)
                                .collect(Collectors.joining("\n")));
    }

    /**
     * The schema versions this producer can emit JSON for, so adding a version
     * to the CycloneDX library automatically widens this guard.
     *
     * <p>
     * Versions below 1.4 are excluded: 1.0 and 1.1 have no JSON binding at all,
     * and 1.2/1.3 make {@code component.version} mandatory, which a FILE
     * component scanned out of an archive has no value for. Emitting those two
     * is a pre-existing limitation, not something this guard should assert.
     * </p>
     */
    static List<Version> supportedVersions() {
        return Arrays.stream(Version.values())
                .filter(v -> v.getFormats().contains(Format.JSON))
                .filter(v -> v.getVersion() >= 1.4d)
                .toList();
    }

    /**
     * Guards the checked-in golden resource itself, so a hand-edit or a
     * regeneration from a broken renderer cannot leave an invalid document in
     * the repository.
     */
    @Test
    void goldenResourceIsSchemaValid() throws Exception {
        Path copy = tempDir.resolve("golden-copy.cdx.json");
        Files.writeString(copy, readGolden(), StandardCharsets.UTF_8);

        List<ParseException> errors = new JsonParser()
                .validate(copy.toFile(), SchemaVersions.resolve(SCHEMA_VERSION));
        assertTrue(errors.isEmpty(),
                () -> "Golden document " + GOLDEN_RESOURCE + " is not valid against CycloneDX "
                        + SCHEMA_VERSION + ":\n"
                        + errors.stream().map(Throwable::getMessage)
                                .collect(Collectors.joining("\n")));
    }

    private String readGolden() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(GOLDEN_RESOURCE)) {
            assertNotNull(in, "Golden resource " + GOLDEN_RESOURCE + " is missing; "
                    + "generate it with -Dgolden.regenerate=true");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Builds a fixed model exercising the byte-identity-critical paths. Every
     * value is a literal so the serialized output is fully deterministic.
     */
    private AssemblyComponents buildFixedModel() {
        AssemblyComponents model = new AssemblyComponents();

        AssemblyMetadata metadata = new AssemblyMetadata();
        metadata.setProjectGroupId("org.example");
        metadata.setProjectArtifactId("demo-dist");
        metadata.setProjectVersion("1.0.0");
        metadata.setAssemblyId("dist");
        // Fixed instant so the metadata timestamp never varies.
        metadata.setTimestamp(new Date(1_700_000_000_000L));
        metadata.setHashAlgorithmSpec("SHA-256");
        metadata.setClassifier("dist");
        metadata.setArchiveType("zip");
        metadata.setProjectLicenses(List.of(
                LicenseInfo.spdx("Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0")));
        metadata.setToolGroupId("dev.cyberstamp.maven.assembly.sbom");
        metadata.setToolArtifactId("assembly-sbom-core");
        metadata.setToolVersion("0.0.0-golden");
        metadata.setToolLicenses(List.of(LicenseInfo.spdx("Apache-2.0", null)));
        metadata.setToolHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        model.setMetadata(metadata);

        ArtifactCoords alpha = ArtifactCoords.of("org.example", "alpha", "1.0");
        ArtifactCoords beta = ArtifactCoords.of("org.example", "beta", "2.0");

        // A shaded/bundled dependency nested under alpha, identified from its
        // own pom.properties.
        PackageComponent bundled = new PackageComponent(
                ArtifactCoords.of("com.bundled", "shaded-dep", "3.1"),
                "lib/alpha.jar", null, List.of(), List.of(), true, Identification.pomProperties());

        // Top-level alpha, identified by hash, with a nested component and an
        // SPDX-id license.
        model.addComponent(new PackageComponent(alpha, "lib/alpha.jar",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                List.of(LicenseInfo.spdx("Apache-2.0",
                        "https://www.apache.org/licenses/LICENSE-2.0")),
                List.of(bundled), true, Identification.hashMatch()));

        // Same PURL again at a second path with no license -> occurrence merge,
        // first-wins licenses.
        model.addComponent(new PackageComponent(alpha, "other/alpha.jar",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                List.of(), List.of()));

        // Top-level beta with an SPDX-expression license and no identification,
        // so it renders no identity evidence.
        model.addComponent(new PackageComponent(beta, "lib/beta.jar",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                List.of(LicenseInfo.expression("(MIT OR Apache-2.0)")), List.of()));

        // A plain FILE component (raw license comes from project licenses).
        model.addComponent(new FileComponent("bin/launcher.sh",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                List.of()));

        // An explicit inter-artifact dependency: alpha depends on beta.
        model.addDependencyEdge(new DependencyEdge(alpha, beta, true));

        return model;
    }
}
