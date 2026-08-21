package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

import org.cyclonedx.model.Bom;

/**
 * An SBOM discovered inside the assembly or inside a bundled artifact, to be
 * merged into the final BOM.
 *
 * <p>
 * This is currently the one deliberately format-aware type in the neutral
 * model: it wraps an already-parsed CycloneDX {@link Bom}. That reflects
 * today's reality (only CycloneDX embedded SBOMs are merged), but it is a
 * known neutrality compromise — an embedded SBOM is not <em>necessarily</em>
 * CycloneDX (it could be SPDX). A future phase is expected to make discovery
 * format-neutral, e.g. by having a format-specific reader adopt the external
 * document's components into {@link PackageComponent}/{@link FileComponent}
 * before the neutral model sees it, so no concrete SBOM type appears here.
 * </p>
 *
 * @param archivePath the path of the SBOM file relative to the assembly
 *        root; never {@code null}
 * @param parsedBom the eagerly-parsed BOM content; never {@code null}
 * @param owner the package whose content contains this SBOM, or
 *        {@code null} if at the assembly root or unresolved
 */
public record DiscoveredSbom(String archivePath, Bom parsedBom, PackageRef owner) {

    public DiscoveredSbom {
        Objects.requireNonNull(archivePath, "archivePath");
        Objects.requireNonNull(parsedBom, "parsedBom");
    }
}
