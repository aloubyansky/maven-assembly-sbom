package dev.cyberstamp.maven.assembly.sbom.match;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.building.SettingsProblem;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves and decrypts {@code settings.xml} {@code <server>} credentials,
 * shared by the mojo and the assembly-plugin handler.
 */
public final class ServerCredentialsResolver {

    private static final Logger log = LoggerFactory.getLogger(ServerCredentialsResolver.class);

    private ServerCredentialsResolver() {
    }

    /**
     * Resolves and decrypts the username/password of a {@code settings.xml}
     * {@code <server>} entry.
     *
     * @param serverId the server id
     * @return the decrypted credentials, or {@code null} if no matching server
     *         is found
     * @throws IllegalArgumentException if decryption reported a problem more
     *         severe than a warning
     */
    public static ServerCredentials resolve(MavenSession session, SettingsDecrypter decrypter, String serverId) {
        Server server = session.getSettings().getServer(serverId);
        if (server == null) {
            log.warn("No <server> with id '{}' found in settings.xml; using anonymous access", serverId);
            return null;
        }
        SettingsDecryptionResult result = decrypter.decrypt(new DefaultSettingsDecryptionRequest(server));
        List<SettingsProblem> problems = result.getProblems().stream()
                .filter(p -> p.getSeverity() != SettingsProblem.Severity.WARNING)
                .toList();
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("Failed to decrypt <server> '" + serverId + "' in settings.xml: "
                    + problems.stream().map(SettingsProblem::getMessage).collect(Collectors.joining("; ")));
        }
        Server decrypted = result.getServer() != null ? result.getServer() : server;
        return new ServerCredentials(decrypted.getUsername(), decrypted.getPassword());
    }
}
