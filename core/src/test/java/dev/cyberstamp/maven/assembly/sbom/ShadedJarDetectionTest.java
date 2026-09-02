package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ShadedJarDetectionTest {

    @TempDir
    Path tempDir;

    private Path jarWithPomProperties(String name, String[]... gavs) throws Exception {
        Path jar = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write("content".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            for (String[] gav : gavs) {
                jos.putNextEntry(new JarEntry(
                        "META-INF/maven/" + gav[0] + "/" + gav[1] + "/pom.properties"));
                jos.write(("groupId=" + gav[0] + "\nartifactId=" + gav[1]
                        + "\nversion=" + gav[2] + "\n").getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
        }
        return jar;
    }

    @Test
    void nestsBundledNonOwnerArtifacts() throws Exception {
        Path jar = jarWithPomProperties("owner-1.0.jar",
                new String[] { "com.example", "owner", "1.0" },
                new String[] { "com.bundled", "dep", "2.0" });

        ArtifactCoords owner = ArtifactCoords.of("com.example", "owner", "1.0");
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(PackageComponent.of(owner, "lib/owner.jar", "hash"));

        new ShadedJarDetection(c -> c.equals(owner) ? jar : null).apply(model);

        PackageComponent pkg = (PackageComponent) model.components().get(0);
        assertEquals(1, pkg.nested().size(), "the non-owner bundled dep should be nested");
        PackageComponent nested = (PackageComponent) pkg.nested().get(0);
        assertEquals("pkg:maven/com.bundled/dep@2.0", nested.ref().toPurl().toString());
        assertFalse(nested.dependenciesKnown(),
                "a pom.properties-detected bundle has unresolved dependencies");
    }

    @Test
    void bundledArtifactsHaveUnknownDependencies() throws Exception {
        // A bundle is discovered from embedded pom.properties, not from a resolved
        // dependency tree, so its dependencies must be marked unknown so the
        // renderer omits it from the dependency graph rather than declaring it a
        // leaf with no dependencies.
        Path jar = jarWithPomProperties("owner-1.0.jar",
                new String[] { "com.example", "owner", "1.0" },
                new String[] { "com.bundled", "dep-a", "2.0" },
                new String[] { "com.bundled", "dep-b", "3.0" });

        ArtifactCoords owner = ArtifactCoords.of("com.example", "owner", "1.0");
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(PackageComponent.of(owner, "lib/owner.jar", "hash"));

        new ShadedJarDetection(c -> c.equals(owner) ? jar : null).apply(model);

        PackageComponent pkg = (PackageComponent) model.components().get(0);
        assertEquals(2, pkg.nested().size());
        for (AssemblyComponent nested : pkg.nested()) {
            assertFalse(nested.dependenciesKnown(),
                    "every bundled dep should have unknown dependencies: " + nested);
        }
    }

    @Test
    void singlePomPropertiesIsNotShaded() throws Exception {
        Path jar = jarWithPomProperties("plain-1.0.jar",
                new String[] { "com.example", "plain", "1.0" });
        ArtifactCoords owner = ArtifactCoords.of("com.example", "plain", "1.0");
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(PackageComponent.of(owner, "lib/plain.jar", "hash"));

        new ShadedJarDetection(c -> jar).apply(model);

        assertTrue(((PackageComponent) model.components().get(0)).nested().isEmpty());
    }

    @Test
    void missingJarLeavesComponentUnchanged() {
        ArtifactCoords owner = ArtifactCoords.of("com.example", "owner", "1.0");
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(PackageComponent.of(owner, null, null));

        new ShadedJarDetection(c -> null).apply(model);

        assertTrue(((PackageComponent) model.components().get(0)).nested().isEmpty());
    }

    @Test
    void doesNotDuplicateAlreadyNestedDep() throws Exception {
        Path jar = jarWithPomProperties("owner-1.0.jar",
                new String[] { "com.example", "owner", "1.0" },
                new String[] { "com.bundled", "dep", "2.0" });
        ArtifactCoords owner = ArtifactCoords.of("com.example", "owner", "1.0");
        PackageComponent existingNested = PackageComponent.of(
                ArtifactCoords.of("com.bundled", "dep", "2.0"), null, null);
        AssemblyComponents model = new AssemblyComponents();
        model.addComponent(new PackageComponent(owner, "lib/owner.jar", "hash",
                List.of(), List.of(existingNested)));

        new ShadedJarDetection(c -> jar).apply(model);

        assertEquals(1, ((PackageComponent) model.components().get(0)).nested().size(),
                "a bundled dep already nested must not be duplicated");
    }
}
