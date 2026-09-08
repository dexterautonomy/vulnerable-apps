package com.hingebridge.iasttarget.quarkus;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * Arms the capability printer once the application is up.
 *
 * <p>Quarkus owns {@code main}, so there is nowhere else to do it. The printer itself is a shutdown
 * hook - the agent flushes from one too, and this one only reads what the agent has recorded.
 */
@ApplicationScoped
public class Startup {

    void onStart(@Observes StartupEvent event) {
        Capabilities.printOnShutdown();
        System.err.println("APP: quarkus target ready");
    }
}
