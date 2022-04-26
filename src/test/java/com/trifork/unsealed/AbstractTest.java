package com.trifork.unsealed;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.junit.jupiter.api.BeforeAll;

public class AbstractTest {

    @BeforeAll
    static void setup() {
        final ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new SimpleFormatter());

        final Logger dsig = Logger.getLogger("org.jcp.xml.dsig.internal");
        dsig.setLevel(Level.FINEST);
        dsig.addHandler(consoleHandler);

        final Logger security = Logger.getLogger("com.sun.org.apache.xml.internal.security");
        security.setLevel(Level.FINEST);
        security.addHandler(consoleHandler);

        final Logger unsealed = Logger.getLogger("com.trifork.unsealed");
        unsealed.setLevel(Level.FINEST);
        unsealed.addHandler(consoleHandler);
    }

}