package dev.cyberstamp.maven.assembly.sbom;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Assembly-level metadata that feeds the CycloneDX BOM renderer.
 *
 * <p>
 * Holds rendering parameters (hash algorithm spec, schema version), project
 * coordinates, tool metadata, timestamp, and optional product information.
 * All fields are mutable and nullable unless otherwise noted; the renderer
 * applies defaults and omits nulls.
 * </p>
 *
 * <p>
 * This class is part of the neutral SBOM component model and must remain
 * free of {@code org.cyclonedx.*} types. Hash algorithms and schema versions
 * are stored as String specs; the renderer converts them to CycloneDX enums
 * at the rendering boundary.
 * </p>
 */
public final class AssemblyMetadata {

    private String projectGroupId;
    private String projectArtifactId;
    private String projectVersion;
    private String assemblyId;
    private Date timestamp;
    private String hashAlgorithmSpec;
    private String schemaVersion;
    private String classifier;
    private String archiveType;
    private String mainComponentPurl;
    private List<LicenseInfo> projectLicenses = Collections.emptyList();
    private String toolGroupId;
    private String toolArtifactId;
    private String toolVersion;
    private List<LicenseInfo> toolLicenses = Collections.emptyList();
    private String toolHash;
    private ProductInfo product;

    /**
     * Returns the Maven {@code groupId} of the project being assembled.
     *
     * @return the project group ID, or {@code null}
     */
    public String getProjectGroupId() {
        return projectGroupId;
    }

    /**
     * Sets the project group ID.
     *
     * @param projectGroupId the group ID
     */
    public void setProjectGroupId(String projectGroupId) {
        this.projectGroupId = projectGroupId;
    }

    /**
     * Returns the Maven {@code artifactId} of the project being assembled.
     *
     * @return the project artifact ID, or {@code null}
     */
    public String getProjectArtifactId() {
        return projectArtifactId;
    }

    /**
     * Sets the project artifact ID.
     *
     * @param projectArtifactId the artifact ID
     */
    public void setProjectArtifactId(String projectArtifactId) {
        this.projectArtifactId = projectArtifactId;
    }

    /**
     * Returns the Maven {@code version} of the project being assembled.
     *
     * @return the project version, or {@code null}
     */
    public String getProjectVersion() {
        return projectVersion;
    }

    /**
     * Sets the project version.
     *
     * @param projectVersion the version
     */
    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    /**
     * Returns the assembly descriptor ID (e.g., {@code "bin"}, {@code "dist"}).
     *
     * @return the assembly ID, or {@code null}
     */
    public String getAssemblyId() {
        return assemblyId;
    }

    /**
     * Sets the assembly ID.
     *
     * @param assemblyId the assembly ID
     */
    public void setAssemblyId(String assemblyId) {
        this.assemblyId = assemblyId;
    }

    /**
     * Returns the BOM generation timestamp.
     *
     * @return the timestamp, or {@code null} to let the renderer use the
     *         current time
     */
    public Date getTimestamp() {
        return timestamp;
    }

    /**
     * Sets the BOM generation timestamp.
     *
     * @param timestamp the timestamp, or {@code null}
     */
    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Returns the hash algorithm specification string for component hashes
     * (e.g., {@code "SHA-256"}, {@code "SHA-512"}).
     *
     * <p>
     * The renderer maps this string to a CycloneDX {@code Hash.Algorithm}
     * enum at the rendering boundary. Stored as a String to honor the
     * CycloneDX confinement rule (Ruling P2).
     * </p>
     *
     * @return the hash algorithm spec, or {@code null} for renderer default
     */
    public String getHashAlgorithmSpec() {
        return hashAlgorithmSpec;
    }

    /**
     * Sets the hash algorithm spec.
     *
     * @param hashAlgorithmSpec the algorithm spec (e.g., {@code "SHA-256"})
     */
    public void setHashAlgorithmSpec(String hashAlgorithmSpec) {
        this.hashAlgorithmSpec = hashAlgorithmSpec;
    }

    /**
     * Returns the CycloneDX schema version string (e.g., {@code "1.6"},
     * {@code "1.5"}).
     *
     * <p>
     * The renderer maps this string to a CycloneDX {@code Version} enum
     * at the rendering boundary. Stored as a String to honor the
     * CycloneDX confinement rule (Ruling P2).
     * </p>
     *
     * @return the schema version, or {@code null} for renderer default
     */
    public String getSchemaVersion() {
        return schemaVersion;
    }

    /**
     * Sets the schema version.
     *
     * @param schemaVersion the version string (e.g., {@code "1.6"})
     */
    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    /**
     * Returns the Maven classifier of the generated assembly archive
     * (e.g., {@code "bin"}, {@code "sources"}).
     *
     * @return the classifier, or {@code null}
     */
    public String getClassifier() {
        return classifier;
    }

    /**
     * Sets the classifier.
     *
     * @param classifier the classifier
     */
    public void setClassifier(String classifier) {
        this.classifier = classifier;
    }

    /**
     * Returns the archive type (e.g., {@code "zip"}, {@code "tar.gz"}).
     *
     * @return the archive type, or {@code null}
     */
    public String getArchiveType() {
        return archiveType;
    }

    /**
     * Sets the archive type.
     *
     * @param archiveType the archive type
     */
    public void setArchiveType(String archiveType) {
        this.archiveType = archiveType;
    }

    /**
     * Returns the explicit Package URL to use for the main component, or
     * {@code null} to derive a Maven purl from the project coordinates.
     *
     * <p>
     * Producers whose main component is not a Maven artifact (e.g. a
     * provisioned server distribution) set this to a synthetic identity such
     * as {@code pkg:generic/jboss-eap@8.1-update-7.1}. When set, the renderer
     * uses it for both the main component's {@code purl} and its
     * {@code bom-ref} (the dependency-graph root).
     * </p>
     *
     * @return the main component purl override, or {@code null}
     */
    public String getMainComponentPurl() {
        return mainComponentPurl;
    }

    /**
     * Sets an explicit Package URL for the main component.
     *
     * @param mainComponentPurl the main component purl, or {@code null} to
     *        derive a Maven purl from the project coordinates
     */
    public void setMainComponentPurl(String mainComponentPurl) {
        this.mainComponentPurl = mainComponentPurl;
    }

    /**
     * Returns the list of licenses for the project being assembled.
     *
     * @return an unmodifiable view of the project licenses; never {@code null},
     *         empty if none set
     */
    public List<LicenseInfo> getProjectLicenses() {
        return projectLicenses;
    }

    /**
     * Sets the project licenses. Stores a defensive copy.
     *
     * @param projectLicenses the licenses, or {@code null}/empty for none
     */
    public void setProjectLicenses(List<LicenseInfo> projectLicenses) {
        this.projectLicenses = (projectLicenses == null || projectLicenses.isEmpty())
                ? Collections.emptyList()
                : List.copyOf(projectLicenses);
    }

    /**
     * Returns the Maven {@code groupId} of the tool that generated this SBOM.
     *
     * @return the tool group ID, or {@code null}
     */
    public String getToolGroupId() {
        return toolGroupId;
    }

    /**
     * Sets the tool group ID.
     *
     * @param toolGroupId the group ID
     */
    public void setToolGroupId(String toolGroupId) {
        this.toolGroupId = toolGroupId;
    }

    /**
     * Returns the Maven {@code artifactId} of the tool that generated this SBOM.
     *
     * @return the tool artifact ID, or {@code null}
     */
    public String getToolArtifactId() {
        return toolArtifactId;
    }

    /**
     * Sets the tool artifact ID.
     *
     * @param toolArtifactId the artifact ID
     */
    public void setToolArtifactId(String toolArtifactId) {
        this.toolArtifactId = toolArtifactId;
    }

    /**
     * Returns the version of the tool that generated this SBOM.
     *
     * @return the tool version, or {@code null}
     */
    public String getToolVersion() {
        return toolVersion;
    }

    /**
     * Sets the tool version.
     *
     * @param toolVersion the version
     */
    public void setToolVersion(String toolVersion) {
        this.toolVersion = toolVersion;
    }

    /**
     * Returns the list of licenses for the tool itself.
     *
     * @return an unmodifiable view of the tool licenses; never {@code null},
     *         empty if none set
     */
    public List<LicenseInfo> getToolLicenses() {
        return toolLicenses;
    }

    /**
     * Sets the tool licenses. Stores a defensive copy.
     *
     * @param toolLicenses the licenses, or {@code null}/empty for none
     */
    public void setToolLicenses(List<LicenseInfo> toolLicenses) {
        this.toolLicenses = (toolLicenses == null || toolLicenses.isEmpty())
                ? Collections.emptyList()
                : List.copyOf(toolLicenses);
    }

    /**
     * Returns the hash of the tool JAR or executable.
     *
     * @return the tool hash (hex string), or {@code null}
     */
    public String getToolHash() {
        return toolHash;
    }

    /**
     * Sets the tool hash.
     *
     * @param toolHash the hash (hex string)
     */
    public void setToolHash(String toolHash) {
        this.toolHash = toolHash;
    }

    /**
     * Returns optional product metadata for the main BOM component.
     *
     * @return the product metadata, or {@code null}
     */
    public ProductInfo getProduct() {
        return product;
    }

    /**
     * Sets the product metadata.
     *
     * @param product the product metadata, or {@code null}
     */
    public void setProduct(ProductInfo product) {
        this.product = product;
    }
}
