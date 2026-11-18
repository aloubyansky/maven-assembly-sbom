package dev.cyberstamp.maven.assembly.sbom.match;

/**
 * Decrypted credentials of a {@code settings.xml} {@code <server>}.
 *
 * @param username the username, or {@code null}
 * @param password the password, or {@code null}
 */
public record ServerCredentials(String username, String password) {

    /**
     * Returns the {@code Authorization: Basic ...} header value, or
     * {@code null} if the credentials are incomplete.
     */
    String basicAuthHeader() {
        if (username == null || username.isBlank() || password == null) {
            return null;
        }
        return HttpLookupSupport.basicAuthHeader(username, password);
    }
}
