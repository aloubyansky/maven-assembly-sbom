package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

import dev.cyberstamp.maven.assembly.sbom.match.MatcherContext;
import dev.cyberstamp.maven.assembly.sbom.match.MavenArtifactMatcher;

/**
 * Factory for one entry in {@code <mavenArtifactMatchers>}.
 * The XML element name selects the subclass ({@code <central/>} &rarr;
 * {@link Central}, {@code <nexus>} &rarr; {@link Nexus}, {@code <artifactory>}
 * &rarr; {@link Artifactory}), following the Maven/Plexus convention of
 * mapping an element name to the capitalized class name. That convention
 * only resolves classes declared in the same package as the Mojo/handler
 * that owns the configured field, which is why this class and its
 * subclasses live here rather than in the {@code match} subpackage with the
 * rest of the matching machinery they build. Presence in the list enables a
 * matcher, and the list order is the order in which matchers are tried.
 */
public abstract class MavenArtifactMatcherFactory {

    /**
     * Include globs used when none are configured. Both are needed because
     * {@code **&#47;*.jar} requires at least one directory segment.
     */
    static final List<String> DEFAULT_INCLUDES = List.of("*.jar", "**/*.jar");

    private List<String> includes;
    private List<String> excludes;

    /**
     * Returns the glob patterns (matched against the archive-relative path)
     * selecting which unmatched files this matcher is offered.
     *
     * @return the include patterns, or {@code null} if unset
     */
    public List<String> getIncludes() {
        return includes;
    }

    /**
     * Sets the include glob patterns. Defaults to {@code *.jar} and
     * {@code **&#47;*.jar} when unset or empty.
     *
     * @param includes the include patterns
     */
    public void setIncludes(List<String> includes) {
        this.includes = includes;
    }

    /**
     * Returns the glob patterns excluding otherwise-included files.
     *
     * @return the exclude patterns, or {@code null} if unset
     */
    public List<String> getExcludes() {
        return excludes;
    }

    /**
     * Sets the exclude glob patterns.
     *
     * @param excludes the exclude patterns
     */
    public void setExcludes(List<String> excludes) {
        this.excludes = excludes;
    }

    List<String> effectiveIncludes() {
        return includes == null || includes.isEmpty() ? DEFAULT_INCLUDES : List.copyOf(includes);
    }

    List<String> effectiveExcludes() {
        return excludes == null ? List.of() : List.copyOf(excludes);
    }

    /**
     * Returns the XML element name, used in log and error messages.
     */
    public abstract String elementName();

    /**
     * Returns whether this matcher contacts a remote service, and must
     * therefore be skipped in Maven offline mode.
     */
    public abstract boolean isRemote();

    /**
     * Builds the matcher described by this factory's configuration.
     *
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public abstract MavenArtifactMatcher create(MatcherContext context);
}
