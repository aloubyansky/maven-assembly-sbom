package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.apache.maven.model.Model;

/**
 * A {@link LicenseSource} that resolves license declarations from Maven
 * effective POM models.
 *
 * <p>
 * This implementation wraps an {@link EffectiveModelResolver} and maps each
 * {@code <license>} entry from the effective model to a neutral
 * {@link RawLicense} record. It returns an empty list when the POM cannot be
 * resolved or declares no licenses.
 * </p>
 *
 * <p>
 * Maven Model types are confined to this class; the {@link LicenseSource}
 * interface exposes only neutral types so that downstream consumers
 * (such as the SBOM component model and SPDX license mapper) remain
 * independent of Maven.
 * </p>
 */
public class EffectiveModelLicenseSource implements LicenseSource {

    private final Function<ArtifactCoords, Model> modelResolver;

    /**
     * Creates a license source backed by the given effective model resolver.
     *
     * @param resolver the Maven effective model resolver
     */
    public EffectiveModelLicenseSource(EffectiveModelResolver resolver) {
        this.modelResolver = coords -> resolver.resolveEffectiveModel(
                coords.groupId(), coords.artifactId(), coords.version());
    }

    /**
     * Package-private constructor for the test seam.
     *
     * <p>
     * This constructor is intentionally package-private so that Maven Model
     * types do not appear in any public signature. Test code can inject a
     * stub resolver without requiring a full Maven repository session.
     * </p>
     *
     * @param modelResolver a function mapping artifact coordinates to an
     *        effective model, or {@code null} if the model
     *        cannot be resolved
     */
    EffectiveModelLicenseSource(Function<ArtifactCoords, Model> modelResolver) {
        this.modelResolver = modelResolver;
    }

    /**
     * Package-private factory method for creating a test instance.
     *
     * <p>
     * Provided for test code readability and to avoid exposing the
     * package-private constructor directly in test code.
     * </p>
     *
     * @param modelResolver a function mapping artifact coordinates to an
     *        effective model, or {@code null} if the model
     *        cannot be resolved
     * @return a license source for testing
     */
    static EffectiveModelLicenseSource forTesting(Function<ArtifactCoords, Model> modelResolver) {
        return new EffectiveModelLicenseSource(modelResolver);
    }

    /**
     * Returns the license declarations from the effective POM of the given
     * artifact.
     *
     * <p>
     * This method resolves the effective model using the configured
     * {@link EffectiveModelResolver} and maps each {@code <license>} entry
     * to a {@link RawLicense} record, preserving the order of declaration.
     * </p>
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the declared licenses, or an empty list if the model cannot be
     *         resolved or declares no licenses; never {@code null}
     */
    @Override
    public List<RawLicense> licensesFor(String groupId, String artifactId, String version) {
        ArtifactCoords coords = ArtifactCoords.of(groupId, artifactId, version);
        Model model = modelResolver.apply(coords);
        if (model == null) {
            return Collections.emptyList();
        }
        List<org.apache.maven.model.License> mavenLicenses = model.getLicenses();
        if (mavenLicenses == null || mavenLicenses.isEmpty()) {
            return Collections.emptyList();
        }
        List<RawLicense> result = new ArrayList<>(mavenLicenses.size());
        for (org.apache.maven.model.License mavenLicense : mavenLicenses) {
            result.add(new RawLicense(mavenLicense.getName(), mavenLicense.getUrl()));
        }
        return result;
    }
}
