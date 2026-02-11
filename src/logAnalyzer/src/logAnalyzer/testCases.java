package logAnalyzer;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Vector;

import org.junit.jupiter.api.Test;

class testCases {

	@Test
    void parseLine_validLine_parsesFieldsCorrectly() {
        RecursiveLogTraversal r = new RecursiveLogTraversal(new File("."));

        String line = "2025-11-07 10:22:01 [AUTH] user=Kara ip=131.44.45.22 status=FAIL";
        logEntry e = r.parseLine(line);

        assertNotNull(e);
        assertEquals("2025-11-07 10:22:01", e.getTimestamp());
        assertEquals("Kara", e.getUser());
        assertEquals("131.44.45.22", e.getIp());
        assertEquals("FAIL", e.getStatus());
    }

    @Test
    void parseLine_invalidLine_returnsNull() {
        RecursiveLogTraversal r = new RecursiveLogTraversal(new File("."));

        String badLine = "this is not a valid auth log line";
        logEntry e = r.parseLine(badLine);

        assertNull(e);
    }
    @Test
    void suspiciousAdd_updatesFailCountUsersAndTimestamps() {
        Suspicious s = new Suspicious("131.44.45.22");

        logEntry e1 = new logEntry("2025-11-07 10:22:01", "Kara", "131.44.45.22", "FAIL");
        logEntry e2 = new logEntry("2025-11-07 10:27:55", "Eli",  "131.44.45.22", "FAIL");

        s.add(e1);
        s.add(e2);

        assertEquals(2, s.getFailCount());
        assertTrue(s.getUsers().contains("Kara"));
        assertTrue(s.getUsers().contains("Eli"));
        assertEquals("2025-11-07 10:22:01", s.getFirstTS());
        assertEquals("2025-11-07 10:27:55", s.getLastTS());
    }
    @Test
    void aggregate_twoIpsOneFailEach() {
        RecursiveLogTraversal r = new RecursiveLogTraversal(new File("."));
        Vector<logEntry> entries = new Vector<>();

        // Only 2 entries, both FAIL.
        entries.add(new logEntry("T1", "A", "1.1.1.1", "FAIL"));
        entries.add(new logEntry("T2", "B", "2.2.2.2", "FAIL"));

        Vector<Suspicious> result = r.aggregate(entries);

        // Should detect 2 unique IPs
        assertEquals(2, result.size());

        // First suspicious IP
        Suspicious ip1 = result.get(0);
        assertEquals("1.1.1.1", ip1.getIp());
        assertEquals(1, ip1.getFailCount());
        assertTrue(ip1.getUsers().contains("A"));

        // Second suspicious IP
        Suspicious ip2 = result.get(1);
        assertEquals("2.2.2.2", ip2.getIp());
        assertEquals(1, ip2.getFailCount());
        assertTrue(ip2.getUsers().contains("B"));
    }

    @Test
    void parseFile_readsEntriesFromTempLogFile() throws IOException {
        // Create a temporary .log file
        File temp = File.createTempFile("test-log", ".log");
        temp.deleteOnExit();

        try (FileWriter fw = new FileWriter(temp)) {
            fw.write("2025-11-07 10:22:01 [AUTH] user=Kara ip=131.44.45.22 status=FAIL\n");
            fw.write("2025-11-07 10:22:05 [AUTH] user=Casey ip=203.0.113.7 status=OK\n");
        }

        RecursiveLogTraversal r = new RecursiveLogTraversal(new File("."));
        Vector<logEntry> entries = new Vector<>();

        boolean valid = r.parseFile(temp, entries);

        assertTrue(valid);
        assertEquals(2, entries.size());
        assertEquals("Kara", entries.get(0).getUser());
        assertEquals("Casey", entries.get(1).getUser());
    }

    
    
}
	
