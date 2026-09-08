package com.hingebridge.iasttarget.quarkus;

import java.io.File;

/**
 * The dangerous calls, kept in one place so every target in this folder reaches the SAME sinks.
 *
 * <p>{@code new File(path)} is chosen deliberately: it is in the agent's shipped sink catalog, it
 * needs no database, no external process and no network, and constructing a File touches the disk
 * not at all. A target that had to run a real query to be scanned would be testing the driver.
 */
public final class Sinks {

    private Sinks() {
    }

    /**
     * The same sink with NOTHING in between - the value goes straight into the call.
     *
     * <p>Exists to separate two questions that look identical from the outside: did the agent mark
     * the value untrusted at all, and did it keep track of it through a concatenation and a thread
     * hop. A target that only had the long path could not tell a missing SOURCE from a broken
     * PROPAGATOR, and both show up as "no findings".
     */
    public static String openExact(String userSuppliedPath) {
        return new File(userSuppliedPath).getPath();
    }

    /** PATH_TRAVERSAL. Returns something so the compiler cannot elide the call. */
    public static String openPath(String userSuppliedPath) {
        File file = new File("/var/data/" + userSuppliedPath);
        return file.getPath();
    }
}
