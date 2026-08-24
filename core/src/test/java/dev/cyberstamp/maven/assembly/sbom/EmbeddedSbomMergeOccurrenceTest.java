package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

/**
 * Regression test for occurrence locations when an SBOM embedded inside a
 * nested/unpacked artifact is merged under that artifact's component.
 *
 * <p>
 * A component from the embedded SBOM carries a location relative to the
 * containing archive (e.g. {@code WEB-INF/lib/foo.jar}); after merging it must
 * be distribution-relative (e.g. {@code web/app.war/WEB-INF/lib/foo.jar}) so it
 * resolves from the assembly root. Previously this only happened for FILE
 * components and for library components that had a top-level counterpart; a
 * library with no top-level counterpart kept its archive-relative location.
 * </p>
 */
class EmbeddedSbomMergeOccurrenceTest {

    private static Component component(Component.Type type, String name, String purl,
            String occurrenceLocation) {
        Component c = new Component();
        c.setType(type);
        c.setName(name);
        c.setPurl(purl);
        c.setBomRef(purl);
        if (occurrenceLocation != null) {
            Evidence e = new Evidence();
            Occurrence o = new Occurrence();
            o.setLocation(occurrenceLocation);
            e.setOccurrences(new ArrayList<>(List.of(o)));
            c.setEvidence(e);
        }
        return c;
    }

    @Test
    void libraryWithoutTopLevelCounterpartGetsDistributionRelativeOccurrence() {
        // Parent war component, unpacked at web/app.war/ (occurrence prefix).
        Component parent = component(Component.Type.LIBRARY, "app",
                "pkg:maven/org.example/app@1.0?type=war", "web/app.war/");
        Bom target = new Bom();
        target.setComponents(new ArrayList<>(List.of(parent)));

        // Embedded SBOM from app.war: a library with an archive-relative location
        // and no top-level counterpart in the target.
        Component lib = component(Component.Type.LIBRARY, "nested-lib",
                "pkg:maven/org.example/nested-lib@2.0", "WEB-INF/lib/nested-lib-2.0.jar");
        Bom source = new Bom();
        source.setComponents(new ArrayList<>(List.of(lib)));

        BomMerger.mergeUnder(target, parent.getBomRef(), source);

        Component nested = parent.getComponents().stream()
                .filter(c -> "nested-lib".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(nested, "library should be nested under the parent");
        assertEquals("web/app.war/WEB-INF/lib/nested-lib-2.0.jar",
                nested.getEvidence().getOccurrences().get(0).getLocation(),
                "occurrence must be distribution-relative after merge");
    }

    @Test
    void fileComponentOccurrenceIsNotDoublePrefixed() {
        // FILE components are prefixed via their file: bom-ref; ensure the added
        // library-occurrence prefixing does not double-prefix them.
        Component parent = component(Component.Type.LIBRARY, "app",
                "pkg:maven/org.example/app@1.0?type=war", "web/app.war/");
        Bom target = new Bom();
        target.setComponents(new ArrayList<>(List.of(parent)));

        Component file = new Component();
        file.setType(Component.Type.FILE);
        file.setName("app.js");
        file.setBomRef("file:static/js/app.js");
        Evidence e = new Evidence();
        Occurrence o = new Occurrence();
        o.setLocation("static/js/app.js");
        e.setOccurrences(new ArrayList<>(List.of(o)));
        file.setEvidence(e);
        Bom source = new Bom();
        source.setComponents(new ArrayList<>(List.of(file)));

        BomMerger.mergeUnder(target, parent.getBomRef(), source);

        Component nested = parent.getComponents().stream()
                .filter(c -> "app.js".equals(c.getName()))
                .findFirst().orElse(null);
        assertNotNull(nested);
        assertEquals("web/app.war/static/js/app.js",
                nested.getEvidence().getOccurrences().get(0).getLocation(),
                "FILE occurrence must be prefixed exactly once");
    }
}
