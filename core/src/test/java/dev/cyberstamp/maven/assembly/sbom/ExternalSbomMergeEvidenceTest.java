package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

/**
 * When a Maven component from an external/embedded SBOM (rich in metadata but
 * without a {@code manifest-analysis} identity, e.g. a Quarkus-generated SBOM)
 * is verified present in the assembly during archive filtering, it should gain
 * a {@code manifest-analysis} identity — asserting the assembly plugin
 * confirmed the component is in the distribution — while keeping its
 * description/publisher.
 */
class ExternalSbomMergeEvidenceTest {

    private static Component externalMaven(String hash, String occurrence) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setGroup("com.fasterxml.jackson.core");
        c.setName("jackson-core");
        c.setVersion("2.22.0");
        c.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-core@2.22.0?type=jar");
        c.setBomRef("pkg:maven/com.fasterxml.jackson.core/jackson-core@2.22.0?type=jar");
        c.setDescription("Core Jackson processing abstractions");
        c.setPublisher("FasterXML");
        if (hash != null) {
            c.addHash(new Hash(Hash.Algorithm.SHA_256, hash));
        }
        if (occurrence != null) {
            Evidence e = new Evidence();
            Occurrence o = new Occurrence();
            o.setLocation(occurrence);
            e.setOccurrences(new ArrayList<>(List.of(o)));
            c.setEvidence(e);
        }
        return c;
    }

    private static Bom bomOf(Component... comps) {
        Bom b = new Bom();
        b.setComponents(new ArrayList<>(List.of(comps)));
        return b;
    }

    @Test
    void matchedExternalComponentGainsManifestIdentityAndKeepsDescription() {
        String hash = "aabbccdd";
        Bom external = bomOf(externalMaven(hash, "lib/main/jackson-core-2.22.0.jar"));
        ArchiveIndex index = buildIndex(Map.of(hash,
                List.of("lib/main/jackson-core-2.22.0.jar")));

        Bom filtered = SbomGenerator.filterSbomByArchive(external, index, null);

        assertEquals(1, filtered.getComponents().size());
        Component c = filtered.getComponents().get(0);
        assertEquals("Core Jackson processing abstractions", c.getDescription(),
                "description must be preserved");
        assertNotNull(c.getEvidence().getIdentities(),
                "a manifest-analysis identity must be added for the verified component");
        assertEquals(Method.Technique.MANIFEST_ANALYSIS,
                c.getEvidence().getIdentities().get(0).getMethods().get(0).getTechnique());
    }

    @Test
    void npmComponentDoesNotGainMavenIdentity() {
        Component npm = new Component();
        npm.setType(Component.Type.LIBRARY);
        npm.setName("react");
        npm.setPurl("pkg:npm/react@18.0.0");
        npm.setBomRef("pkg:npm/react@18.0.0");
        Evidence e = new Evidence();
        Occurrence o = new Occurrence();
        o.setLocation("node_modules/react/index.js");
        e.setOccurrences(new ArrayList<>(List.of(o)));
        npm.setEvidence(e);

        Bom external = bomOf(npm);
        // npm components survive filtering even without an archive match
        Bom filtered = SbomGenerator.filterSbomByArchive(external, buildIndex(Map.of()), null);

        assertEquals(1, filtered.getComponents().size());
        Evidence ev = filtered.getComponents().get(0).getEvidence();
        assertTrue(ev == null || ev.getIdentities() == null || ev.getIdentities().isEmpty(),
                "non-Maven components must not gain a maven manifest-analysis identity");
    }

    private static ArchiveIndex buildIndex(Map<String, List<String>> hashToPaths) {
        List<FileEntry> entries = new ArrayList<>();
        hashToPaths.forEach((h, paths) -> {
            for (String p : paths) {
                entries.add(new FileEntry(p, h));
            }
        });
        return ArchiveIndex.of(entries, null, "sha256");
    }
}
