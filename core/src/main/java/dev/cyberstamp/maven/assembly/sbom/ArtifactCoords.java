package dev.cyberstamp.maven.assembly.sbom;

import java.util.Map;
import java.util.Objects;

/**
 * Immutable Maven artifact coordinates used as a deduplication key
 * across the SBOM generation pipeline.
 *
 * <p>
 * Coordinates use the logical Maven identity: the type field stores
 * the Maven packaging type (e.g. {@code "test-jar"}, not the file
 * extension), and the classifier is only set when explicitly declared
 * in the POM. Handler-provided classifiers (e.g. {@code "tests"} for
 * {@code test-jar}) are stripped because they are implicit in the type.
 * </p>
 *
 * <p>
 * The record normalizes empty classifiers to {@code null} so that
 * coordinates with an empty string classifier and those with a
 * {@code null} classifier are considered equal.
 * </p>
 *
 * <p>
 * The {@link #toString()} representation follows the format
 * {@code groupId:artifactId:version[:classifier]}.
 * </p>
 *
 * @param groupId the Maven groupId
 * @param artifactId the Maven artifactId
 * @param version the artifact version
 * @param type the packaging type (e.g. "jar", "war", "test-jar"), or {@code null}
 * @param classifier the Maven classifier, or {@code null} if none
 */
public record ArtifactCoords(String groupId, String artifactId, String version, String type, String classifier)
        implements
            PackageRef {

    private static final String SEPARATOR = ":";

    /**
     * Maven types whose artifact handler provides an implicit classifier.
     * Key: type, value: handler-provided classifier.
     */
    private static final Map<String, String> HANDLER_CLASSIFIERS = Map.of(
            "test-jar", "tests",
            "ejb-client", "client",
            "java-source", "sources",
            "javadoc", "javadoc");

    /**
     * Reverse of {@link #HANDLER_CLASSIFIERS}: Aether extension "jar" +
     * classifier → Maven type.
     */
    private static final Map<String, String> CLASSIFIER_TO_TYPE = Map.of(
            "tests", "test-jar",
            "client", "ejb-client",
            "sources", "java-source",
            "javadoc", "javadoc");

    /**
     * Canonicalizes the coordinates: requires non-null g/a/v, defaults a
     * null/empty {@code type} to {@code jar}, normalizes an empty
     * {@code classifier} to {@code null}, and maps Aether extension+classifier
     * pairs to the equivalent Maven type (e.g. {@code jar}+{@code tests} →
     * {@code test-jar}).
     */
    public ArtifactCoords {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(version, "version");
        if (type == null || type.isEmpty()) {
            type = "jar";
        }
        if (classifier != null && classifier.isEmpty()) {
            classifier = null;
        }
        // map Aether extension+classifier to Maven type and strip the
        // handler-provided classifier (e.g. jar+tests → test-jar, null)
        if ("jar".equals(type) && classifier != null) {
            String mapped = CLASSIFIER_TO_TYPE.get(classifier);
            if (mapped != null) {
                type = mapped;
                classifier = null;
            }
        } else if (classifier != null && classifier.equals(HANDLER_CLASSIFIERS.get(type))) {
            classifier = null;
        }
    }

    /**
     * Creates an {@link ArtifactCoords} without type or classifier.
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the coordinates with a default {@code jar} type and no classifier
     */
    public static ArtifactCoords of(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, version, null, null);
    }

    /**
     * Returns the handler-provided classifier for a Maven type, or
     * {@code null} if the type does not have an implicit classifier.
     */
    static String handlerClassifier(String type) {
        return HANDLER_CLASSIFIERS.get(type);
    }

    /**
     * Returns the {@code groupId:artifactId:version} portion of the
     * coordinates, always omitting type and classifier.
     */
    String toGav() {
        return groupId + SEPARATOR + artifactId + SEPARATOR + version;
    }

    /**
     * Returns the full coordinate string. The format is
     * {@code groupId:artifactId:version} for plain JARs,
     * {@code groupId:artifactId:type:version} for non-JAR types,
     * and appends {@code :classifier} when present.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(groupId).append(SEPARATOR).append(artifactId).append(SEPARATOR);
        if (!"jar".equals(type)) {
            sb.append(type).append(SEPARATOR);
        }
        sb.append(version);
        if (classifier != null) {
            sb.append(SEPARATOR).append(classifier);
        }
        return sb.toString();
    }

    /**
     * Returns the canonical Maven Package URL for these coordinates.
     *
     * <p>
     * Built on the shared {@link Purl} engine. The default {@code jar}
     * type is omitted (spec-compliant, and matching this project's
     * long-standing output); a {@code type} qualifier is emitted only for
     * non-JAR packaging, and a {@code classifier} qualifier only when a
     * classifier is present. Qualifiers are rendered in canonical
     * (alphabetical) order.
     * </p>
     *
     * @return the canonical purl; never {@code null}
     */
    @Override
    public Purl toPurl() {
        Purl.Builder builder = Purl.builder()
                .setType("maven")
                .setNamespace(groupId)
                .setName(artifactId)
                .setVersion(version);
        if (!"jar".equals(type)) {
            builder.addQualifier("type", type);
        }
        if (classifier != null) {
            builder.addQualifier("classifier", classifier);
        }
        return builder.build();
    }
}
