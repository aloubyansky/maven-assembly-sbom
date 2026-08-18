package dev.cyberstamp.maven.assembly.sbom;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/**
 * Factory methods that create {@link ArtifactCoords} from Maven and Aether
 * artifact types. Kept separate so that {@code ArtifactCoords} itself has
 * no dependency on Maven APIs.
 */
final class MavenArtifactCoords {

    private MavenArtifactCoords() {
    }

    static ArtifactCoords of(Artifact a) {
        return new ArtifactCoords(a.getGroupId(), a.getArtifactId(), a.getVersion(),
                a.getType(), a.getClassifier());
    }

    static ArtifactCoords of(org.eclipse.aether.artifact.Artifact a) {
        return new ArtifactCoords(a.getGroupId(), a.getArtifactId(), a.getVersion(),
                a.getExtension(), a.getClassifier());
    }

    static ArtifactCoords of(MavenProject p) {
        return new ArtifactCoords(p.getGroupId(), p.getArtifactId(), p.getVersion(),
                p.getPackaging(), null);
    }
}
