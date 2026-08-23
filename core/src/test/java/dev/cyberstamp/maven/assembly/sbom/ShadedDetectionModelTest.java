package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Confirms that shaded JAR detection (a JAR with multiple pom.properties,
 * whose filename resolves an owner artifact) surfaces the bundled dependencies
 * as NESTED PackageComponents under the owner PackageComponent in the neutral
 * AssemblyComponents model.
 *
 * <p>
 * This is the explicit regression lock for the shaded detection contract:
 * a shaded JAR's owner is a top-level PackageComponent, and any bundled
 * dependencies discovered via embedded pom.properties are nested under it
 * (NOT separate top-level components).
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class ShadedDetectionModelTest {

    @TempDir
    Path tempDir;

    @Mock
    EffectiveModelResolver effectiveModelResolver;

    @Mock
    RepositorySystem repoSystem;

    @Mock
    MavenProject project;

    @Mock
    MavenSession session;

    private MessageDigest digest;

    @BeforeEach
    void setUp() throws Exception {
        digest = MessageDigest.getInstance("SHA-256");
        lenient().when(session.getProjects()).thenReturn(List.of());
        Build build = new Build();
        build.setDirectory(tempDir.resolve("target").toString());
        lenient().when(project.getBuild()).thenReturn(build);
    }

    @Test
    void shadedJarOwnerIsTopLevelWithBundledDepNested() throws Exception {
        // Create a shaded JAR with two pom.properties: the owner and a bundled dep
        Path shadedJar = createShadedJarWithMultiplePomProperties("nimbus-jose-jwt-10.9.1.jar",
                "com.nimbusds", "nimbus-jose-jwt", "10.9.1",
                "com.github.stephenc.jcip", "jcip-annotations", "1.0-1",
                "nimbus-content");
        Artifact artifact = createArtifact("com.nimbusds", "nimbus-jose-jwt", "10.9.1", "jar",
                shadedJar.toFile());
        when(project.getArtifacts()).thenReturn(Set.of(artifact));

        String hash = SbomUtils.computeHash(digest, shadedJar);
        List<FileEntry> entries = List.of(
                new FileEntry("lib/nimbus-jose-jwt-10.9.1.jar", hash));

        ArchiveAnalyzer analyzer = createAnalyzer();
        AssemblyComponents model = analyzer.analyze(entries, null);

        // Find the top-level owner component
        PackageComponent owner = null;
        for (AssemblyComponent comp : model.components()) {
            if (comp instanceof PackageComponent pkg
                    && pkg.ref() instanceof ArtifactCoords coords
                    && "nimbus-jose-jwt".equals(coords.artifactId())) {
                owner = pkg;
                break;
            }
        }
        assertNotNull(owner,
                "shaded JAR owner should be a top-level PackageComponent");
        ArtifactCoords ownerCoords = (ArtifactCoords) owner.ref();
        assertEquals("com.nimbusds", ownerCoords.groupId(),
                "shaded owner groupId should match");
        assertEquals("nimbus-jose-jwt", ownerCoords.artifactId(),
                "shaded owner artifactId should match");
        assertEquals("10.9.1", ownerCoords.version(),
                "shaded owner version should match");

        // The bundled dep should be nested under the owner, not a separate top-level component
        PackageComponent bundledDep = null;
        for (AssemblyComponent nested : owner.nested()) {
            if (nested instanceof PackageComponent pkg
                    && pkg.ref() instanceof ArtifactCoords coords
                    && "jcip-annotations".equals(coords.artifactId())) {
                bundledDep = pkg;
                break;
            }
        }
        assertNotNull(bundledDep,
                "bundled dep should be a NESTED PackageComponent under the shaded owner");
        ArtifactCoords bundledCoords = (ArtifactCoords) bundledDep.ref();
        assertEquals("com.github.stephenc.jcip", bundledCoords.groupId(),
                "bundled dep groupId should match");
        assertEquals("jcip-annotations", bundledCoords.artifactId(),
                "bundled dep artifactId should match");
        assertEquals("1.0-1", bundledCoords.version(),
                "bundled dep version should match");

        // Structural type check: the bundled dep is itself a PackageComponent
        assertTrue(bundledDep instanceof PackageComponent,
                "bundled dep should be a PackageComponent (ecosystem in the coord; structure = PackageComponent vs FileComponent)");
    }

    // Minimal fixture helpers

    private ArchiveAnalyzer createAnalyzer() {
        return new ArchiveAnalyzer(
                effectiveModelResolver, repoSystem, project, session, digest, false);
    }

    private Path createShadedJarWithMultiplePomProperties(String name,
            String groupId1, String artifactId1, String version1,
            String groupId2, String artifactId2, String version2,
            String content) throws Exception {
        Path jarPath = tempDir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath))) {
            jos.putNextEntry(new JarEntry("data.txt"));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            String props1Path = "META-INF/maven/" + groupId1 + "/" + artifactId1
                    + "/pom.properties";
            jos.putNextEntry(new JarEntry(props1Path));
            jos.write(("groupId=" + groupId1 + "\nartifactId=" + artifactId1
                    + "\nversion=" + version1 + "\n").getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
            String props2Path = "META-INF/maven/" + groupId2 + "/" + artifactId2
                    + "/pom.properties";
            jos.putNextEntry(new JarEntry(props2Path));
            jos.write(("groupId=" + groupId2 + "\nartifactId=" + artifactId2
                    + "\nversion=" + version2 + "\n").getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jarPath;
    }

    private static Artifact createArtifact(String groupId, String artifactId,
            String version, String type, File file) {
        DefaultArtifact artifact = new DefaultArtifact(
                groupId, artifactId, version, "compile", type, null,
                new DefaultArtifactHandler(type));
        artifact.setFile(file);
        return artifact;
    }
}
