package dev.cyberstamp.maven.assembly.sbom;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A model transform that attaches license information to the
 * {@link PackageComponent}s of an {@link AssemblyComponents} model.
 *
 * <p>
 * This is the shared license-resolution seam of the neutral SBOM design
 * (Option A): a pluggable {@link LicenseSource} supplies raw POM license
 * declarations, and the internal {@link SpdxLicenseMapper} maps them to
 * neutral {@link LicenseInfo} values. Every consumer — the assembly plugin
 * (effective-model source) and Galleon provisioning
 * ({@code MavenRepoManager} source) — injects its own {@link LicenseSource}
 * and shares this one mapper, so no SPDX-mapping logic is duplicated.
 * </p>
 *
 * <p>
 * {@link #apply(AssemblyComponents)} resolves the distinct artifact
 * coordinates of the whole model <em>in parallel</em> before rebuilding the
 * component tree, because per-artifact resolution is POM-I/O bound. The
 * {@link LicenseSource} and {@link SpdxLicenseMapper} are therefore invoked
 * concurrently and must be thread-safe. Resolution is cached per GAV so each
 * artifact is resolved at most once.
 * </p>
 *
 * <p>
 * Behavior when an artifact has no license information is controlled by
 * {@code failOnMissingLicense}: {@code true} throws
 * {@link LicenseResolutionException}; {@code false} logs a warning (once per
 * GAV). The policy is applied during the sequential rebuild, so a
 * {@code failOnMissingLicense} failure is deterministic.
 * </p>
 */
public final class LicenseEnrichment {

    private static final Logger log = LoggerFactory.getLogger(LicenseEnrichment.class);

    private final LicenseSource source;
    private final SpdxLicenseMapper mapper = new SpdxLicenseMapper();
    private final boolean failOnMissingLicense;
    /** Per-GAV cache; an empty list marks a GAV that resolved to no licenses. */
    private final Map<ArtifactCoords, List<LicenseInfo>> cache = new ConcurrentHashMap<>();
    /** GAVs whose missing-license policy has already been applied (warn once). */
    private final Set<ArtifactCoords> missingReported = ConcurrentHashMap.newKeySet();

    /**
     * Creates an enrichment over the given license source.
     *
     * @param source supplies raw POM license declarations per artifact; must be
     *        thread-safe (invoked concurrently by {@link #apply})
     * @param failOnMissingLicense whether to throw on artifacts with no
     *        license information (otherwise a warning is logged once per GAV)
     */
    public LicenseEnrichment(LicenseSource source, boolean failOnMissingLicense) {
        this.source = source;
        this.failOnMissingLicense = failOnMissingLicense;
    }

    /**
     * Resolves the neutral licenses for a single artifact, mapping each raw
     * declaration to SPDX where possible. Cached per GAV; thread-safe.
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the artifact version
     * @return the resolved licenses, or an empty list if none are declared
     * @throws LicenseResolutionException if {@code failOnMissingLicense} and
     *         no license information is available
     */
    public List<LicenseInfo> resolve(String groupId, String artifactId, String version) {
        ArtifactCoords id = ArtifactCoords.of(groupId, artifactId, version);
        List<LicenseInfo> infos = resolveIntoCache(id);
        if (infos.isEmpty() && missingReported.add(id)) {
            handleMissing(id);
        }
        return infos;
    }

    /**
     * Enriches every {@link PackageComponent} in the model (top-level and
     * nested) whose {@code ref} is an {@link ArtifactCoords} and which has no
     * licenses yet, rebuilding the immutable component records in place.
     *
     * <p>
     * Distinct coordinates are resolved concurrently first, then the tree is
     * rebuilt sequentially so the missing-license policy is deterministic.
     * </p>
     *
     * @param model the model to enrich; its component list is replaced
     */
    public void apply(AssemblyComponents model) {
        Set<ArtifactCoords> pending = new LinkedHashSet<>();
        collectUnlicensedCoords(model.components(), pending);
        // Warm the cache in parallel — per-artifact POM resolution is I/O bound.
        pending.parallelStream().forEach(this::resolveIntoCache);

        List<AssemblyComponent> enriched = new ArrayList<>(model.components().size());
        for (AssemblyComponent comp : model.components()) {
            enriched.add(enrich(comp));
        }
        model.setComponents(enriched);
    }

    /** Resolves and caches a GAV's licenses without applying the missing policy. */
    private List<LicenseInfo> resolveIntoCache(ArtifactCoords id) {
        return cache.computeIfAbsent(id, k -> {
            List<RawLicense> raws = source.licensesFor(k.groupId(), k.artifactId(), k.version());
            if (raws.isEmpty()) {
                return List.of();
            }
            List<LicenseInfo> infos = new ArrayList<>(raws.size());
            for (RawLicense raw : raws) {
                infos.add(mapper.map(raw));
            }
            return infos;
        });
    }

    /** Collects the coordinates of unlicensed package components across the tree. */
    private void collectUnlicensedCoords(List<AssemblyComponent> components, Set<ArtifactCoords> out) {
        for (AssemblyComponent comp : components) {
            if (comp instanceof PackageComponent pkg) {
                if (pkg.licenses().isEmpty() && pkg.ref() instanceof ArtifactCoords coords) {
                    out.add(coords);
                }
                collectUnlicensedCoords(pkg.nested(), out);
            } else if (comp instanceof FileComponent file) {
                collectUnlicensedCoords(file.nested(), out);
            }
        }
    }

    /**
     * Returns a copy of {@code comp} with licenses resolved for it and all of
     * its nested components. Enriches nested-first so the rebuilt parent record
     * already contains the enriched children.
     */
    private AssemblyComponent enrich(AssemblyComponent comp) {
        if (comp instanceof PackageComponent pkg) {
            List<AssemblyComponent> nested = new ArrayList<>(pkg.nested().size());
            for (AssemblyComponent child : pkg.nested()) {
                nested.add(enrich(child));
            }
            List<LicenseInfo> licenses = pkg.licenses();
            if (licenses.isEmpty() && pkg.ref() instanceof ArtifactCoords coords) {
                licenses = resolve(coords.groupId(), coords.artifactId(), coords.version());
            }
            return new PackageComponent(pkg.ref(), pkg.archivePath(), pkg.hash(), licenses, nested);
        }
        if (comp instanceof FileComponent file) {
            List<AssemblyComponent> nested = new ArrayList<>(file.nested().size());
            for (AssemblyComponent child : file.nested()) {
                nested.add(enrich(child));
            }
            return new FileComponent(file.archivePath(), file.hash(), nested);
        }
        return comp;
    }

    private void handleMissing(ArtifactCoords id) {
        if (failOnMissingLicense) {
            throw new LicenseResolutionException(
                    "No license information for " + id.toGav());
        }
        log.warn("No license information for {}", id.toGav());
    }
}
