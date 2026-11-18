package dev.cyberstamp.maven.assembly.sbom.match;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.cyberstamp.maven.assembly.sbom.Central;
import dev.cyberstamp.maven.assembly.sbom.ChecksumSearchMatcherFactory;
import dev.cyberstamp.maven.assembly.sbom.MavenArtifactMatcherFactory;

/**
 * Builds the {@link MavenArtifactMatcher} described by a
 * {@code <mavenArtifactMatchers>} configuration.
 */
public final class MavenArtifactMatchers {

    private static final Logger log = LoggerFactory.getLogger(MavenArtifactMatchers.class);

    private MavenArtifactMatchers() {
    }

    /**
     * Builds a first-match-wins chain of the configured matchers, in
     * configuration order. Remote matchers are skipped in offline mode.
     *
     * @param factories the configured matcher factories, or {@code null}
     * @param offline whether Maven runs in offline mode
     * @param credentials resolves a {@code settings.xml} server id to its
     *        decrypted credentials, or {@code null} if there is no such server
     * @return the matcher, or empty if nothing is configured (or everything
     *         configured was skipped)
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public static Optional<MavenArtifactMatcher> create(List<? extends MavenArtifactMatcherFactory> factories,
            boolean offline, Function<String, ServerCredentials> credentials) {
        if (factories == null || factories.isEmpty()) {
            return Optional.empty();
        }
        if (factories.stream().filter(Central.class::isInstance).count() > 1) {
            throw new IllegalArgumentException("<central/> may only be configured once in <mavenArtifactMatchers>");
        }
        List<MavenArtifactMatcherFactory> active = new ArrayList<>(factories.size());
        for (MavenArtifactMatcherFactory factory : factories) {
            if (offline && factory.isRemote()) {
                log.warn("Maven is running in offline mode; skipping <{}>, so files only identifiable "
                        + "through it remain file components", factory.elementName());
            } else {
                active.add(factory);
            }
        }
        if (active.isEmpty()) {
            return Optional.empty();
        }

        Sha1Hasher hasher = new Sha1Hasher();
        MatcherContext context = new MatcherContext(newHttpClient(active), hasher, credentials);
        List<MavenArtifactMatcher> matchers = new ArrayList<>(active.size());
        try {
            for (MavenArtifactMatcherFactory factory : active) {
                matchers.add(factory.create(context));
            }
        } catch (RuntimeException e) {
            MavenArtifactMatcher.of(matchers).close();
            throw e;
        }
        return Optional.of(MavenArtifactMatcher.of(matchers));
    }

    /**
     * Creates the HTTP client shared by all remote matchers. Its connect
     * timeout is the longest configured per-request timeout; each matcher
     * still applies its own timeout to its requests.
     */
    private static HttpClient newHttpClient(List<MavenArtifactMatcherFactory> factories) {
        Duration connectTimeout = factories.stream()
                .filter(ChecksumSearchMatcherFactory.class::isInstance)
                .map(f -> ((ChecksumSearchMatcherFactory) f).timeout())
                .max(Duration::compareTo)
                .orElse(Duration.ofSeconds(3));
        return HttpClient.newBuilder().connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL).build();
    }

    /**
     * Wraps a backend's raw lookup with budget enforcement, caching, and path
     * filtering, to build the matcher a {@code ChecksumSearchMatcherFactory}
     * exposes for one configured backend. Kept here so the matcher-chain
     * building blocks stay package-private to this package.
     *
     * @param rawLookup the backend-specific lookup (Nexus, Central, Artifactory)
     * @param elementName the XML element name, for budget/filter error messages
     * @param maxLookups the backend's configured lookup budget
     * @param context the shared matcher context
     * @param includes the backend's include globs
     * @param excludes the backend's exclude globs
     * @throws IllegalArgumentException if none of {@code includes} is a valid glob pattern
     */
    public static MavenArtifactMatcher wrapChecksumLookup(CoordinatesLookup rawLookup, String elementName,
            int maxLookups, MatcherContext context, List<String> includes, List<String> excludes) {
        CoordinatesLookup lookup = new BudgetedLookup(rawLookup, new BudgetedLookup.Budget(elementName, maxLookups));
        MavenArtifactMatcher matcher = new CachingMatcher(
                new ChecksumLookupMatcher(lookup, context.hasher()), context.hasher());
        return PathFilterMatcher.of(matcher, includes, excludes)
                .orElseThrow(() -> new IllegalArgumentException(
                        "None of the <includes> of <" + elementName + "> is a valid glob pattern"));
    }
}
