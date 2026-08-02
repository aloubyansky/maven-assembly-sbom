package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;

import org.cyclonedx.model.OrganizationalEntity;

/**
 * User-configurable metadata for the main BOM component.
 *
 * <p>
 * Fields set here are applied to the CycloneDX metadata component
 * alongside the automatically derived group, name, version, PURL,
 * and licenses. All fields are optional — {@code null} values are
 * ignored.
 * </p>
 */
public class ProductInfo {

    private String cpe;
    private String description;
    private String publisher;
    private String copyright;
    private Organization supplier;
    private Organization manufacturer;

    /**
     * Returns the CPE 2.2 or 2.3 identifier for the product.
     *
     * @return the CPE string, or {@code null}
     */
    public String getCpe() {
        return cpe;
    }

    /**
     * Sets the CPE identifier.
     *
     * @param cpe the CPE string
     */
    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    /**
     * Returns the free-text description of the product.
     *
     * @return the description, or {@code null}
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the product description.
     *
     * @param description the description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Returns the publisher name.
     *
     * @return the publisher, or {@code null}
     */
    public String getPublisher() {
        return publisher;
    }

    /**
     * Sets the publisher name.
     *
     * @param publisher the publisher
     */
    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    /**
     * Returns the copyright text.
     *
     * @return the copyright, or {@code null}
     */
    public String getCopyright() {
        return copyright;
    }

    /**
     * Sets the copyright text.
     *
     * @param copyright the copyright
     */
    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    /**
     * Returns the organization that supplied the component.
     *
     * @return the supplier, or {@code null}
     */
    public Organization getSupplier() {
        return supplier;
    }

    /**
     * Sets the supplier organization.
     *
     * @param supplier the supplier
     */
    public void setSupplier(Organization supplier) {
        this.supplier = supplier;
    }

    /**
     * Returns the organization that manufactured the component.
     *
     * @return the manufacturer, or {@code null}
     */
    public Organization getManufacturer() {
        return manufacturer;
    }

    /**
     * Sets the manufacturer organization.
     *
     * @param manufacturer the manufacturer
     */
    public void setManufacturer(Organization manufacturer) {
        this.manufacturer = manufacturer;
    }

    /**
     * An organization identified by name and URL.
     *
     * <p>
     * Designed for XML binding in both Maven plugin {@code @Parameter}
     * and assembly plugin {@code <configuration>} contexts.
     * </p>
     */
    public static class Organization {

        private String name;
        private String url;

        /**
         * Returns the organization name.
         *
         * @return the name, or {@code null}
         */
        public String getName() {
            return name;
        }

        /**
         * Sets the organization name.
         *
         * @param name the name
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * Returns the organization URL.
         *
         * @return the URL, or {@code null}
         */
        public String getUrl() {
            return url;
        }

        /**
         * Sets the organization URL.
         *
         * @param url the URL
         */
        public void setUrl(String url) {
            this.url = url;
        }

        /**
         * Converts to a CycloneDX {@link OrganizationalEntity}.
         *
         * @return the entity, or {@code null} if {@code name} is not set
         *         (CycloneDX requires name on organizational entities)
         */
        OrganizationalEntity toModel() {
            if (name == null) {
                return null;
            }
            OrganizationalEntity entity = new OrganizationalEntity();
            entity.setName(name);
            if (url != null) {
                entity.setUrls(List.of(url));
            }
            return entity;
        }
    }
}
