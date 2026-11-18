package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.lang.reflect.Field;
import java.util.List;

import org.codehaus.plexus.classworlds.ClassWorld;
import org.codehaus.plexus.component.configurator.BasicComponentConfigurator;
import org.codehaus.plexus.configuration.xml.XmlPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.junit.jupiter.api.Test;

/**
 * Verifies that {@code <mavenArtifactMatchers>} is bound by the same Plexus
 * configurator Maven uses, mapping each element name to the capitalized class
 * in this package.
 */
class SbomContainerDescriptorHandlerMatcherConfigurationTest {

    @Test
    void elementNamesMapToMatcherClassesInOrder() throws Exception {
        List<?> matchers = configure("<configuration><mavenArtifactMatchers>"
                + "<nexus>"
                + "<url>https://nexus.example.com/service/rest/v1/search?sha1={sha1}&amp;repository=internal</url>"
                + "<serverId>my-nexus</serverId>"
                + "</nexus>"
                + "<central/>"
                + "<artifactory>"
                + "<url>https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}</url>"
                + "<includes><include>lib/*.jar</include></includes>"
                + "<maxLookups>5</maxLookups>"
                + "</artifactory>"
                + "</mavenArtifactMatchers></configuration>");

        assertEquals(3, matchers.size());
        Nexus nexus = assertInstanceOf(Nexus.class, matchers.get(0));
        assertEquals("https://nexus.example.com/service/rest/v1/search?sha1={sha1}&repository=internal", nexus.getUrl());
        assertEquals("my-nexus", nexus.getServerId());
        Central central = assertInstanceOf(Central.class, matchers.get(1));
        assertNull(central.getUrl());
        Artifactory artifactory = assertInstanceOf(Artifactory.class, matchers.get(2));
        assertEquals(List.of("lib/*.jar"), artifactory.getIncludes());
        assertEquals(5, artifactory.getMaxLookups());
    }

    private static List<?> configure(String xml) throws Exception {
        SbomContainerDescriptorHandler target = new SbomContainerDescriptorHandler();
        try (ClassWorld world = new ClassWorld("test",
                SbomContainerDescriptorHandlerMatcherConfigurationTest.class.getClassLoader())) {
            new BasicComponentConfigurator().configureComponent(target,
                    new XmlPlexusConfiguration(Xpp3DomBuilder.build(new StringReader(xml))), world.getClassRealm("test"));
        }
        Field field = SbomContainerDescriptorHandler.class.getDeclaredField("mavenArtifactMatchers");
        field.setAccessible(true);
        return (List<?>) field.get(target);
    }
}
