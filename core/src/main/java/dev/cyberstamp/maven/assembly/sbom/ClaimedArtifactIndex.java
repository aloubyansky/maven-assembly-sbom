package dev.cyberstamp.maven.assembly.sbom;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps content hashes to what SBOMs say about the files with those hashes.
 * It holds two kinds of entries, looked up separately:
 *
 * <ul>
 * <li><b>Claimed artifacts</b> ({@link #lookup}), from SBOMs embedded in
 * resolved artifacts: only {@code pkg:maven} components are indexed. When
 * several SBOMs list the same hash, agreeing claims (same coordinates) keep
 * the strongest identification, while disagreeing claims drop the hash
 * altogether: a disputed claim is not trusted.</li>
 * <li><b>Configured components</b> ({@link #configuredComponent}), from the
 * configured external SBOMs: components of any purl type, kept as they
 * appear in their SBOM; the first one listing a hash wins.</li>
 * </ul>
 *
 * <p>
 * Either way only components carrying a hash in the configured algorithm
 * are indexed, nested components included.
 * </p>
 */
final class ClaimedArtifactIndex {

    private static final Logger log = LoggerFactory.getLogger(ClaimedArtifactIndex.class);

    /**
     * Confidence ceiling for a claim whose own {@code pom.properties} is
     * absent from a jar that carries descriptors for other artifacts, unless
     * the source SBOM identified it by hash — the same level as the filename
     * heuristic.
     */
    static final double MISSING_OWNER_DESCRIPTOR_CONFIDENCE = 0.5;

    /**
     * A Maven artifact a found SBOM claims a file to be.
     *
     * @param coords the claimed coordinates; never {@code null}
     * @param identification how the SBOM says it identified the component,
     *        or {@code null} if it carries no purl identity evidence
     */
    record ClaimedArtifact(ArtifactCoords coords, Identification identification) {

        ClaimedArtifact {
            Objects.requireNonNull(coords, "coords");
        }
    }

    private record Claim(ClaimedArtifact artifact, String source, String purl) {
    }

    private static final ClaimedArtifactIndex EMPTY = new ClaimedArtifactIndex(Map.of(), Map.of());

    private final Map<String, ClaimedArtifact> byHash;
    private final Map<String, Component> configuredByHash;

    private ClaimedArtifactIndex(Map<String, ClaimedArtifact> byHash, Map<String, Component> configuredByHash) {
        this.byHash = byHash;
        this.configuredByHash = configuredByHash;
    }

    static ClaimedArtifactIndex empty() {
        return EMPTY;
    }

    /**
     * Builds the index from the configured external SBOMs and the SBOMs
     * embedded in resolved artifacts.
     *
     * <p>
     * Configured SBOM components of any purl type are indexed as they are
     * (first one wins on a hash conflict) and are returned by
     * {@link #configuredComponent}. Embedded SBOMs feed the Maven claims
     * returned by {@link #lookup}.
     * </p>
     *
     * @param configuredBoms the configured external SBOMs, in configuration order
     * @param embeddedBySource the embedded SBOMs keyed by a human-readable
     *        source label used in conflict warnings
     * @param normalizedAlg the hash algorithm, normalized via
     *        {@link SbomUtils#normalizeAlgorithm}
     * @return the index
     */
    static ClaimedArtifactIndex build(List<Bom> configuredBoms, Map<String, Bom> embeddedBySource,
            String normalizedAlg) {
        Map<String, Component> configured = new HashMap<>();
        for (Bom bom : configuredBoms) {
            forEachHashedComponent(bom.getComponents(), normalizedAlg, configured::putIfAbsent);
        }
        Map<String, Claim> claims = new HashMap<>();
        Set<String> conflicting = new HashSet<>();
        for (Map.Entry<String, Bom> e : embeddedBySource.entrySet()) {
            forEachHashedComponent(e.getValue().getComponents(), normalizedAlg,
                    (hash, comp) -> index(hash, comp, e.getKey(), claims, conflicting));
        }
        if (claims.isEmpty() && configured.isEmpty()) {
            return EMPTY;
        }
        Map<String, ClaimedArtifact> byHash = new HashMap<>(claims.size());
        claims.forEach((hash, claim) -> byHash.put(hash, claim.artifact()));
        return new ClaimedArtifactIndex(byHash, configured);
    }

    /**
     * Visits every component in the tree, nested ones included, that has a
     * hash in the given algorithm.
     */
    private static void forEachHashedComponent(List<Component> components, String normalizedAlg,
            BiConsumer<String, Component> visitor) {
        if (components == null) {
            return;
        }
        for (Component comp : components) {
            String hash = SbomUtils.extractHash(comp, normalizedAlg);
            if (hash != null) {
                visitor.accept(hash, comp);
            }
            forEachHashedComponent(comp.getComponents(), normalizedAlg, visitor);
        }
    }

    private static void index(String hash, Component comp, String source,
            Map<String, Claim> claims, Set<String> conflicting) {
        if (conflicting.contains(hash)) {
            return;
        }
        ArtifactCoords coords = mavenCoordsOf(comp.getPurl());
        if (coords == null) {
            return;
        }
        Claim claim = new Claim(new ClaimedArtifact(coords, identificationOf(comp)), source, comp.getPurl());
        Claim existing = claims.get(hash);
        if (existing == null) {
            claims.put(hash, claim);
        } else if (!existing.artifact().coords().equals(coords)) {
            conflicting.add(hash);
            claims.remove(hash);
            log.warn("Found SBOMs disagree on the identity of content {}: {} ({}) vs {} ({});"
                    + " not using them to identify it", hash, existing.purl(), existing.source(),
                    claim.purl(), claim.source());
        } else if (isStronger(claim.artifact().identification(), existing.artifact().identification())) {
            claims.put(hash, claim);
        }
    }

    private static boolean isStronger(Identification candidate, Identification current) {
        if (candidate == null) {
            return false;
        }
        return current == null || candidate.confidence() > current.confidence();
    }

    /**
     * How a claimed artifact relates to the {@code pom.properties}
     * descriptors found in the jar.
     */
    enum DescriptorCheck {
        /** The jar has no descriptors: nothing to compare with. */
        NO_DESCRIPTORS,
        /** A descriptor declares the claimed groupId, artifactId and version. */
        CONFIRMED,
        /** A descriptor declares the claimed groupId:artifactId with another version. */
        VERSION_MISMATCH,
        /** The descriptors are all for other artifacts. */
        OWNER_ABSENT
    }

    /**
     * Compares claimed coordinates with the jar's own {@code pom.properties}
     * descriptors, on groupId, artifactId and version only.
     */
    static DescriptorCheck checkDescriptors(ArtifactCoords claimed, List<ArtifactCoords> descriptors) {
        if (descriptors.isEmpty()) {
            return DescriptorCheck.NO_DESCRIPTORS;
        }
        boolean sameGaFound = false;
        for (ArtifactCoords d : descriptors) {
            if (d.groupId().equals(claimed.groupId()) && d.artifactId().equals(claimed.artifactId())) {
                if (d.version().equals(claimed.version())) {
                    return DescriptorCheck.CONFIRMED;
                }
                sameGaFound = true;
            }
        }
        return sameGaFound ? DescriptorCheck.VERSION_MISMATCH : DescriptorCheck.OWNER_ABSENT;
    }

    /**
     * Returns the Maven coordinates a purl names, or {@code null} for a
     * missing, unparsable or non-Maven purl, or one without a version.
     */
    static ArtifactCoords mavenCoordsOf(String purlString) {
        if (purlString == null) {
            return null;
        }
        Purl purl;
        try {
            purl = Purl.parse(purlString);
        } catch (IllegalArgumentException e) {
            log.debug("Ignoring unparsable purl {} in SBOM", purlString);
            return null;
        }
        if (!Purl.TYPE_MAVEN.equals(purl.getType())
                || purl.getNamespace() == null
                || purl.getName() == null
                || purl.getVersion() == null) {
            return null;
        }
        Map<String, String> q = purl.getQualifiers();
        return new ArtifactCoords(purl.getNamespace(), purl.getName(), purl.getVersion(),
                q.get("type"), q.get("classifier"));
    }

    /**
     * Derives an {@link Identification} from a component's purl identity
     * evidence: the technique of its first method and the identity's
     * confidence, else that method's confidence.
     *
     * @param component the component from a found SBOM
     * @return the identification, or {@code null} if the component carries
     *         no usable purl identity
     */
    private static Identification identificationOf(Component component) {
        Evidence evidence = component.getEvidence();
        if (evidence == null || evidence.getIdentities() == null) {
            return null;
        }
        for (Identity identity : evidence.getIdentities()) {
            if (identity.getField() != Identity.Field.PURL
                    || identity.getMethods() == null || identity.getMethods().isEmpty()) {
                continue;
            }
            Method method = identity.getMethods().get(0);
            if (method.getTechnique() == null) {
                continue;
            }
            Double confidence = identity.getConfidence() != null
                    ? identity.getConfidence()
                    : method.getConfidence();
            if (confidence == null) {
                continue;
            }
            try {
                return new Identification(Technique.valueOf(method.getTechnique().name()), confidence);
            } catch (IllegalArgumentException e) {
                log.debug("Ignoring unusable identity evidence on {}", component.getPurl(), e);
            }
        }
        return null;
    }

    /**
     * Cross-checks a claim against the jar's own {@code pom.properties}
     * descriptors, comparing groupId, artifactId and version only.
     *
     * <ul>
     * <li>no descriptors, or one with the claimed GAV: the claim stands;</li>
     * <li>a descriptor with the claimed groupId:artifactId but another
     * version: the claim is rejected;</li>
     * <li>no descriptor for the claimed groupId:artifactId: the claim stands;
     * unless the source SBOM identified the component by
     * {@code hash-comparison}, its confidence is capped at
     * {@value #MISSING_OWNER_DESCRIPTOR_CONFIDENCE}. A hash claim means the
     * source build matched these exact bytes to the claimed artifact, so a
     * foreign descriptor inside is how that artifact was published rather
     * than counter-evidence.</li>
     * </ul>
     *
     * @param claim the claim from the index
     * @param descriptors the coordinates read from the jar's
     *        {@code pom.properties} files
     * @return the claim as it stands, or empty if rejected
     */
    static Optional<ClaimedArtifact> crossCheck(ClaimedArtifact claim, List<ArtifactCoords> descriptors) {
        ArtifactCoords c = claim.coords();
        DescriptorCheck check = checkDescriptors(c, descriptors);
        if (check == DescriptorCheck.NO_DESCRIPTORS || check == DescriptorCheck.CONFIRMED) {
            return Optional.of(claim);
        }
        if (check == DescriptorCheck.VERSION_MISMATCH) {
            log.warn("Found SBOM claims {} but the jar's pom.properties declares another version;"
                    + " not using the SBOM claim", c);
            return Optional.empty();
        }
        Identification id = claim.identification();
        if (id == null || id.technique() == Technique.HASH_COMPARISON
                || id.confidence() <= MISSING_OWNER_DESCRIPTOR_CONFIDENCE) {
            log.debug("Found SBOM claims {} but the jar has no pom.properties for it", c);
            return Optional.of(claim);
        }
        log.info("Found SBOM claims {} by {} but the jar has no pom.properties for it;"
                + " capping confidence at {}", c, id.technique(), MISSING_OWNER_DESCRIPTOR_CONFIDENCE);
        return Optional.of(new ClaimedArtifact(c,
                new Identification(id.technique(), MISSING_OWNER_DESCRIPTOR_CONFIDENCE)));
    }

    /**
     * Looks up the identity claimed for the given content hash.
     *
     * @param hash the hex-encoded content hash, or {@code null}
     * @return the claimed identity, or empty
     */
    Optional<ClaimedArtifact> lookup(String hash) {
        return hash == null ? Optional.empty() : Optional.ofNullable(byHash.get(hash.toLowerCase()));
    }

    /**
     * Looks up the configured external SBOM component listing the given
     * content hash.
     *
     * @param hash the hex-encoded content hash, or {@code null}
     * @return the component as it appears in its SBOM, or empty
     */
    Optional<Component> configuredComponent(String hash) {
        return hash == null ? Optional.empty() : Optional.ofNullable(configuredByHash.get(hash.toLowerCase()));
    }

    /**
     * Returns {@code true} if any embedded SBOM claims an artifact, i.e.
     * {@link #lookup} can return something.
     */
    boolean hasClaims() {
        return !byHash.isEmpty();
    }
}
