package dev.cyberstamp.maven.assembly.sbom.match;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.settings.building.DefaultSettingsProblem;
import org.apache.maven.settings.building.SettingsProblem;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ServerCredentialsResolverTest {

    @Mock
    MavenSession session;

    @Mock
    SettingsDecrypter decrypter;

    @Mock
    SettingsDecryptionResult result;

    @Test
    void returnsNullWhenServerIsNotConfigured() {
        when(session.getSettings()).thenReturn(new Settings());

        assertNull(ServerCredentialsResolver.resolve(session, decrypter, "missing"));
        verifyNoInteractions(decrypter);
    }

    @Test
    void returnsDecryptedCredentials() {
        when(session.getSettings()).thenReturn(settingsWithServer("my-nexus"));
        Server decrypted = new Server();
        decrypted.setUsername("alice");
        decrypted.setPassword("s3cr3t");
        when(result.getServer()).thenReturn(decrypted);
        when(result.getProblems()).thenReturn(List.of());
        when(decrypter.decrypt(any())).thenReturn(result);

        ServerCredentials creds = ServerCredentialsResolver.resolve(session, decrypter, "my-nexus");

        assertEquals("alice", creds.username());
        assertEquals("s3cr3t", creds.password());
    }

    @Test
    void fallsBackToOriginalServerWhenDecryptionReturnsNoServer() {
        Settings settings = new Settings();
        Server server = new Server();
        server.setId("my-nexus");
        server.setUsername("bob");
        server.setPassword("plain");
        settings.addServer(server);
        when(session.getSettings()).thenReturn(settings);
        when(result.getServer()).thenReturn(null);
        when(result.getProblems()).thenReturn(List.of());
        when(decrypter.decrypt(any())).thenReturn(result);

        ServerCredentials creds = ServerCredentialsResolver.resolve(session, decrypter, "my-nexus");

        assertEquals("bob", creds.username());
        assertEquals("plain", creds.password());
    }

    @Test
    void failsFastOnDecryptionError() {
        when(session.getSettings()).thenReturn(settingsWithServer("my-nexus"));
        SettingsProblem problem = new DefaultSettingsProblem(
                "master password could not be read", SettingsProblem.Severity.ERROR, null, -1, -1, null);
        when(result.getProblems()).thenReturn(List.of(problem));
        when(decrypter.decrypt(any())).thenReturn(result);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ServerCredentialsResolver.resolve(session, decrypter, "my-nexus"));
        assertTrue(e.getMessage().contains("my-nexus"));
        assertTrue(e.getMessage().contains("master password could not be read"));
    }

    @Test
    void warningsDoNotFailTheBuild() {
        when(session.getSettings()).thenReturn(settingsWithServer("my-nexus"));
        SettingsProblem warning = new DefaultSettingsProblem(
                "deprecated cipher", SettingsProblem.Severity.WARNING, null, -1, -1, null);
        when(result.getServer()).thenReturn(new Server());
        when(result.getProblems()).thenReturn(List.of(warning));
        when(decrypter.decrypt(any())).thenReturn(result);

        assertDoesNotThrow(() -> ServerCredentialsResolver.resolve(session, decrypter, "my-nexus"));
    }

    private static Settings settingsWithServer(String id) {
        Settings settings = new Settings();
        Server server = new Server();
        server.setId(id);
        settings.addServer(server);
        return settings;
    }
}
