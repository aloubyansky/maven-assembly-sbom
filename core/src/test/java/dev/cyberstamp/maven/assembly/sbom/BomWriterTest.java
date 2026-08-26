package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;

import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BomWriterTest {

    @TempDir
    Path tempDir;

    @Test
    void writeJsonProducesValidCycloneDx() throws Exception {
        Path output = tempDir.resolve("test.cdx.json");
        BomWriter.writeJson(createMinimalBom(), output, true);

        String content = Files.readString(output);
        assertTrue(content.contains("\"bomFormat\" : \"CycloneDX\""));
    }

    @Test
    void writeXmlProducesValidCycloneDx() throws Exception {
        Path output = tempDir.resolve("test.cdx.xml");
        BomWriter.writeXml(createMinimalBom(), output);

        String content = Files.readString(output);
        assertTrue(content.contains("<bom"));
        assertTrue(content.contains("cyclonedx.org"));
    }

    @Test
    void writeJsonUsesSuppliedSchemaVersion() throws Exception {
        Path output = tempDir.resolve("test.cdx.json");
        BomWriter.writeJson(createMinimalBom(), output, true, Version.VERSION_15);

        String content = Files.readString(output);
        assertTrue(content.contains("\"specVersion\" : \"1.5\""),
                "serialized specVersion should match the supplied version");
    }

    @Test
    void jsonContainsComponents() throws Exception {
        Bom bom = createMinimalBom();
        bom.addComponent(componentNamed("test-lib"));

        Path output = tempDir.resolve("test.cdx.json");
        BomWriter.writeJson(bom, output, true);

        assertTrue(Files.readString(output).contains("test-lib"));
    }

    @Test
    void xmlContainsComponents() throws Exception {
        Bom bom = createMinimalBom();
        bom.addComponent(componentNamed("test-lib"));

        Path output = tempDir.resolve("test.cdx.xml");
        BomWriter.writeXml(bom, output);

        assertTrue(Files.readString(output).contains("test-lib"));
    }

    @Test
    void writeDispatchesByFormat() throws Exception {
        Path json = tempDir.resolve("out.json");
        Path xml = tempDir.resolve("out.xml");
        BomWriter.write(createMinimalBom(), json, "json", false);
        BomWriter.write(createMinimalBom(), xml, "xml", false);

        assertTrue(Files.readString(json).contains("\"bomFormat\""));
        assertTrue(Files.readString(xml).contains("<bom"));
    }

    @Test
    void setsSerialNumber() throws Exception {
        Path output = tempDir.resolve("test.cdx.json");
        BomWriter.writeJson(createMinimalBom(), output, true);

        String content = Files.readString(output);
        assertTrue(content.contains("\"serialNumber\" : \"urn:uuid:"),
                "writer should compute and set the serial number");
    }

    private static Component componentNamed(String name) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setVersion("1.0");
        comp.setBomRef(name + "-ref");
        return comp;
    }

    private static Bom createMinimalBom() {
        return new Bom();
    }
}
