package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SbomGeneratorTest {

    @TempDir
    Path tempDir;

    // ── removeFileComponents ─────────────────────────────────────────────

    @Test
    void removeFileComponentsStripsTopLevelFiles() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.xml");
        fileComp.setBomRef("file:config.xml");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsStripsNestedFiles() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("nested.txt");
        nestedFile.setBomRef("file:nested.txt");
        Component nestedLib = createLibrary("nested-lib", "ref-nested");
        lib.setComponents(new ArrayList<>(List.of(nestedFile, nestedLib)));
        bom.setComponents(new ArrayList<>(List.of(lib)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, lib.getComponents().size());
        assertEquals("nested-lib", lib.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsCleansDependencyRefs() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("data.bin");
        fileComp.setBomRef("file:data.bin");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        Dependency depA = new Dependency("ref-a");
        depA.addDependency(new Dependency("file:data.bin"));
        Dependency depFile = new Dependency("file:data.bin");
        bom.addDependency(depA);
        bom.addDependency(depFile);

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, bom.getDependencies().size());
        assertEquals("ref-a", bom.getDependencies().get(0).getRef());
        assertTrue(bom.getDependencies().get(0).getDependencies() == null
                || bom.getDependencies().get(0).getDependencies().isEmpty());
    }

    @Test
    void removeFileComponentsCleansNestedDependencyRefs() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("deep.bin");
        fileComp.setBomRef("file:deep.bin");
        bom.setComponents(new ArrayList<>(List.of(lib, fileComp)));

        Dependency grandchild = new Dependency("file:deep.bin");
        Dependency child = new Dependency("ref-child");
        child.addDependency(grandchild);
        Dependency root = new Dependency("ref-a");
        root.addDependency(child);
        bom.addDependency(root);

        SbomGenerator.removeFileComponents(bom);

        Dependency surviving = bom.getDependencies().get(0);
        assertEquals("ref-a", surviving.getRef());
        Dependency survivingChild = surviving.getDependencies().get(0);
        assertEquals("ref-child", survivingChild.getRef());
        assertTrue(survivingChild.getDependencies() == null
                || survivingChild.getDependencies().isEmpty(),
                "grandchild file ref should be removed");
    }

    @Test
    void removeFileComponentsNullComponentsIsNoop() {
        Bom bom = new Bom();
        SbomGenerator.removeFileComponents(bom);
        assertNull(bom.getComponents());
    }

    @Test
    void removeFileComponentsEmptyComponentsIsNoop() {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>());
        SbomGenerator.removeFileComponents(bom);
        assertTrue(bom.getComponents().isEmpty());
    }

    @Test
    void removeFileComponentsPreservesNonFileComponents() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component app = new Component();
        app.setType(Component.Type.APPLICATION);
        app.setName("my-app");
        app.setBomRef("ref-app");
        bom.setComponents(new ArrayList<>(List.of(lib, app)));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(2, bom.getComponents().size());
    }

    // ── removeFileComponents with unmodifiable lists ───────────────────

    @Test
    void removeFileComponentsHandlesUnmodifiableComponentList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("config.xml");
        fileComp.setBomRef("file:config.xml");
        bom.setComponents(List.of(lib, fileComp));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals("lib-a", bom.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsHandlesUnmodifiableNestedComponentList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component nestedFile = new Component();
        nestedFile.setType(Component.Type.FILE);
        nestedFile.setName("nested.txt");
        nestedFile.setBomRef("file:nested.txt");
        Component nestedLib = createLibrary("nested-lib", "ref-nested");
        lib.setComponents(List.of(nestedFile, nestedLib));
        bom.setComponents(List.of(lib));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, lib.getComponents().size());
        assertEquals("nested-lib", lib.getComponents().get(0).getName());
    }

    @Test
    void removeFileComponentsHandlesUnmodifiableDependencyList() {
        Bom bom = new Bom();
        Component lib = createLibrary("lib-a", "ref-a");
        Component fileComp = new Component();
        fileComp.setType(Component.Type.FILE);
        fileComp.setName("data.bin");
        fileComp.setBomRef("file:data.bin");
        bom.setComponents(List.of(lib, fileComp));

        Dependency depA = new Dependency("ref-a");
        depA.addDependency(new Dependency("file:data.bin"));
        Dependency depFile = new Dependency("file:data.bin");
        bom.setDependencies(List.of(depA, depFile));

        SbomGenerator.removeFileComponents(bom);

        assertEquals(1, bom.getComponents().size());
        assertEquals(1, bom.getDependencies().size());
        assertEquals("ref-a", bom.getDependencies().get(0).getRef());
    }

    // ── removeTopLevelFilesDuplicatedByNested with unmodifiable lists ──

    // ── replaceFileComponentsWithLibraries with unmodifiable lists ─────

    // ── replaceFileComponentsWithLibraries ───────────────────────────────

    @Test
    void parseExternalBomsNullReturnsEmpty() {
        List<Bom> result = SbomGenerator.parseExternalBoms(null, tempDir);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsBlankReturnsEmpty() {
        List<Bom> result = SbomGenerator.parseExternalBoms("  ", tempDir);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsSingleValidFile() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("bom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                bomFile.toString(), null);

        assertEquals(1, result.size());
        assertNotNull(result.get(0).getComponents());
        assertEquals(1, result.get(0).getComponents().size());
    }

    @Test
    void parseExternalBomsMultipleCommasSeparatedFiles() throws Exception {
        Bom bom1 = new Bom();
        bom1.addComponent(createLibrary("lib-a", "ref-a"));
        Path file1 = tempDir.resolve("bom1.cdx.json");
        BomWriter.writeJson(bom1, file1, false);

        Bom bom2 = new Bom();
        bom2.addComponent(createLibrary("lib-b", "ref-b"));
        Path file2 = tempDir.resolve("bom2.cdx.json");
        BomWriter.writeJson(bom2, file2, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                file1 + " , " + file2, null);

        assertEquals(2, result.size());
    }

    @Test
    void parseExternalBomsMissingFileSkipped() {
        List<Bom> result = SbomGenerator.parseExternalBoms(
                "/nonexistent/bom.cdx.json", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void parseExternalBomsRelativePathResolvedAgainstBaseDir() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("sbom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                "sbom.cdx.json", tempDir);

        assertEquals(1, result.size());
    }

    @Test
    void parseExternalBomsEmptyEntriesSkipped() throws Exception {
        Bom bom = new Bom();
        bom.addComponent(createLibrary("lib-a", "ref-a"));
        Path bomFile = tempDir.resolve("bom.cdx.json");
        BomWriter.writeJson(bom, bomFile, false);

        List<Bom> result = SbomGenerator.parseExternalBoms(
                "," + bomFile + ",,", null);

        assertEquals(1, result.size());
    }

    private static Component createLibrary(String name, String bomRef) {
        Component comp = new Component();
        comp.setType(Component.Type.LIBRARY);
        comp.setName(name);
        comp.setBomRef(bomRef);
        return comp;
    }

    private static void addOccurrence(Component comp, String location) {
        Evidence evidence = comp.getEvidence();
        if (evidence == null) {
            evidence = new Evidence();
            comp.setEvidence(evidence);
        }
        Occurrence occ = new Occurrence();
        occ.setLocation(location);
        evidence.addOccurrence(occ);
    }

    private static ArchiveIndex buildIndex(
            Map<String, List<String>> hashToPath) {
        List<FileEntry> entries = new ArrayList<>();
        for (var e : hashToPath.entrySet()) {
            for (String path : e.getValue()) {
                entries.add(new FileEntry(path, e.getKey()));
            }
        }
        return ArchiveIndex.of(entries, null, "sha256");
    }

    /**
     * Models the artemis distribution: the console war's own SBOM nests its
     * WEB-INF/lib jars under a wrapper with an empty occurrence, but the
     * distribution excluded one of them from the unpacked war.
     */
    private static Bom warSbomWithShippedAndExcludedJar(Component shipped, Component excluded) {
        Component wrapper = createLibrary("console-war", "ref-wrapper");
        addOccurrence(wrapper, "");
        wrapper.setComponents(new ArrayList<>(List.of(shipped, excluded)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(wrapper)));
        Dependency wrapperDep = new Dependency("ref-wrapper");
        wrapperDep.addDependency(new Dependency(shipped.getBomRef()));
        wrapperDep.addDependency(new Dependency(excluded.getBomRef()));
        sbom.addDependency(wrapperDep);
        sbom.addDependency(new Dependency(shipped.getBomRef()));
        sbom.addDependency(new Dependency(excluded.getBomRef()));
        return sbom;
    }

    /** wrapper ("") > app.war ("app.war/") > inner.jar, as an ear-like SBOM lays out an unpacked war */
    private static Bom sbomWithUnpackedSubArchive() {
        Component inner = createLibrary("inner", "ref-inner");
        inner.addHash(new Hash(Hash.Algorithm.SHA_256, "dd44"));
        addOccurrence(inner, "app.war/WEB-INF/lib/inner.jar");
        Component war = createLibrary("app", "ref-app");
        addOccurrence(war, "app.war/");
        war.setComponents(new ArrayList<>(List.of(inner)));
        Component wrapper = createLibrary("wrapper", "ref-wrapper");
        addOccurrence(wrapper, "");
        wrapper.setComponents(new ArrayList<>(List.of(war)));
        Bom sbom = new Bom();
        sbom.setComponents(new ArrayList<>(List.of(wrapper)));
        return sbom;
    }

    private static Set<Component> identitySet(Component... components) {
        Set<Component> set = Collections.newSetFromMap(new IdentityHashMap<>());
        set.addAll(List.of(components));
        return set;
    }

}
