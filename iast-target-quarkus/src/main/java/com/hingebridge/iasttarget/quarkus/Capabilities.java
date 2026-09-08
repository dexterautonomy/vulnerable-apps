package com.hingebridge.iasttarget.quarkus;

/**
 * Prints what the agent's request boundaries actually did, at shutdown.
 *
 * <p>Reflective ON PURPOSE. The agent lives on the bootstrap classloader, so these classes are
 * visible at runtime without this project depending on the agent at build time - which matters,
 * because a target that had to be compiled against the thing it is testing could not be used to test
 * a different build of it.
 *
 * <p>Silent when there is no agent, so the application still runs normally on its own.
 */
public final class Capabilities {

    private Capabilities() {
    }

    public static void printOnShutdown() {
        Runtime.getRuntime().addShutdownHook(new Thread(Capabilities::print));
    }

    public static void print() {
        try {
            Class<?> type = Class.forName("com.hingebridge.iast.boot.report.BoundaryCapabilities");
            System.err.println("APP: capabilities " + type.getMethod("snapshot").invoke(null));
        } catch (Throwable noAgent) {
            System.err.println("APP: capabilities <no agent attached>");
        }
    }
}
