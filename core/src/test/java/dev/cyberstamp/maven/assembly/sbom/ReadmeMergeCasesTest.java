package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Keeps the README's "Supported merges" section in step with
 * {@link MergeCase}: every case has a subsection under its display name.
 */
class ReadmeMergeCasesTest {

    private static final String SECTION = "#### Supported merges";

    @Test
    void everyMergeCaseIsDocumented() throws Exception {
        List<String> lines = Files.readAllLines(Path.of("..", "README.md"));
        int start = lines.indexOf(SECTION);
        assertTrue(start >= 0, "README.md has no '" + SECTION + "' section");
        int end = start + 1;
        while (end < lines.size() && !isHeadingAtOrAbove(lines.get(end), 4)) {
            end++;
        }
        List<String> section = lines.subList(start + 1, end);
        for (MergeCase c : MergeCase.values()) {
            String heading = "##### " + c.displayName();
            assertTrue(section.contains(heading),
                    "README.md '" + SECTION + "' has no '" + heading + "' subsection for " + c);
        }
    }

    /**
     * Whether a line is a Markdown heading of {@code level} or higher (fewer
     * {@code #}).
     *
     * @param line the line
     * @param level the heading level
     * @return {@code true} if it is such a heading
     */
    private static boolean isHeadingAtOrAbove(String line, int level) {
        int hashes = 0;
        while (hashes < line.length() && line.charAt(hashes) == '#') {
            hashes++;
        }
        return hashes > 0 && hashes <= level && hashes < line.length() && line.charAt(hashes) == ' ';
    }
}
