package io.github.aloubyansky.maven.assembly.sbom;

import java.io.File;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.model.Bom;

@Mojo(name = "merge-sbom", defaultPhase = LifecyclePhase.PREPARE_PACKAGE)
public class MergeSbomMojo extends AbstractMojo {

    @Parameter(required = true)
    private File baseBom;

    @Parameter(required = true)
    private List<File> mergeBoms;

    @Parameter(defaultValue = "${project.build.directory}/merged-bom.cdx.json")
    private File outputFile;

    @Parameter(defaultValue = "json")
    private String format;

    @Parameter(defaultValue = "true")
    private boolean prettyPrint;

    @Parameter(defaultValue = "false")
    private boolean nested;

    @Parameter
    private String parentBomRef;

    @Override
    public void execute() throws MojoExecutionException {
        if (!baseBom.isFile()) {
            throw new MojoExecutionException("Base BOM file does not exist: " + baseBom);
        }

        Bom bom = BomReader.readBom(baseBom);
        if (bom == null) {
            throw new MojoExecutionException("Failed to parse base BOM: " + baseBom);
        }

        String parentRef = null;
        if (nested) {
            parentRef = parentBomRef;
            if (parentRef == null) {
                if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
                    parentRef = bom.getMetadata().getComponent().getBomRef();
                }
                if (parentRef == null) {
                    throw new MojoExecutionException(
                            "No parentBomRef configured and base BOM has no metadata component");
                }
            }
        }

        for (File file : mergeBoms) {
            if (!file.isFile()) {
                throw new MojoExecutionException("Merge BOM file does not exist: " + file);
            }
            Bom external = BomReader.readBom(file);
            if (external == null) {
                throw new MojoExecutionException("Failed to parse merge BOM: " + file);
            }
            int componentCount = external.getComponents() != null ? external.getComponents().size() : 0;
            if (nested) {
                BomMerger.mergeUnder(bom, parentRef, external);
            } else {
                BomMerger.mergeFlat(bom, external);
            }
            getLog().info("Merged " + componentCount + " components from " + file.getName());
        }

        outputFile.getParentFile().mkdirs();
        try {
            if ("xml".equalsIgnoreCase(format)) {
                BomWriter.writeXml(bom, outputFile.toPath());
            } else {
                BomWriter.writeJson(bom, outputFile.toPath(), prettyPrint);
            }
        } catch (java.io.IOException | GeneratorException e) {
            throw new MojoExecutionException("Failed to write merged BOM to " + outputFile, e);
        }

        getLog().info("Merged BOM written to " + outputFile);
    }
}
