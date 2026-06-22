package io.github.dhh1128.entviz.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void parsesAConformanceRequest() {
        Object root = Json.parse("{\"entropy\": \"deadbeef\", \"params\": {\"note\": \"git\"}}");
        Map<?, ?> obj = assertInstanceOf(Map.class, root);
        assertEquals("deadbeef", obj.get("entropy"));
        Map<?, ?> params = assertInstanceOf(Map.class, obj.get("params"));
        assertEquals("git", params.get("note"));
    }

    @Test
    void deeplyNestedInputThrowsCleanlyNotStackOverflow() {
        // A malformed request must surface as an IllegalArgumentException (which
        // the CLI maps to exit 2), never an uncaught StackOverflowError that the
        // CLI's catch(RuntimeException) would miss.
        String deep = "[".repeat(10_000) + "]".repeat(10_000);
        assertThrows(IllegalArgumentException.class, () -> Json.parse(deep));
    }
}
