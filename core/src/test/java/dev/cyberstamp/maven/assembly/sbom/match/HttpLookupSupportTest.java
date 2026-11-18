package dev.cyberstamp.maven.assembly.sbom.match;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URI;

import org.junit.jupiter.api.Test;

class HttpLookupSupportTest {

    private static final URI URI_ = URI.create("http://127.0.0.1/search?sha1=abc");

    @Test
    void eachHttpStatusIsReportedOnce() {
        HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Nexus");

        failures.httpStatus(URI_, 500);

        assertFalse(failures.firstOccurrence("HTTP 500"), "a repeated status must not be warned about again");
        assertTrue(failures.firstOccurrence("HTTP 401"), "a different status is a new kind of failure");
    }

    @Test
    void eachExceptionTypeIsReportedOnce() {
        HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Nexus");

        failures.exception(URI_, new IOException("connection refused"));

        assertFalse(failures.firstOccurrence(IOException.class.getName()));
        assertTrue(failures.firstOccurrence(IllegalArgumentException.class.getName()));
    }

    @Test
    void failuresAreTrackedPerBackend() {
        HttpLookupSupport.FailureLog nexus = new HttpLookupSupport.FailureLog("Nexus");
        HttpLookupSupport.FailureLog artifactory = new HttpLookupSupport.FailureLog("Artifactory");

        nexus.httpStatus(URI_, 500);

        assertTrue(artifactory.firstOccurrence("HTTP 500"));
    }
}
