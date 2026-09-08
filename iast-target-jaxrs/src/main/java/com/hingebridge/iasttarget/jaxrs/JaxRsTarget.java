package com.hingebridge.iasttarget.jaxrs;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;

/**
 * A real JAX-RS application, on the JDK's own HTTP server.
 *
 * <p>No servlet container anywhere, deliberately: a JAX-RS target on Tomcat would be served through
 * the SERVLET boundary, which already works, and would say nothing about this one.
 *
 * <p>Deliberately registers NO {@code ContainerRequestFilter}. That is the minimal realistic
 * application, and it is the interesting case: the agent's {@code jaxrs} boundary is declared against
 * {@code ContainerRequestFilter.filter}, so an application that registers none can only be seen
 * through {@code jaxrs-method}. Registering one here would hide whether that second boundary works on
 * its own. See the README.
 */
public final class JaxRsTarget {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8091;
        Capabilities.printOnShutdown();

        URI base = UriBuilder.fromUri("http://0.0.0.0/").port(port).build();
        ResourceConfig config = new ResourceConfig(Resources.class);
        // Off by default: no filter is the ordinary way to write a JAX-RS service, and it is the
        // case worth measuring. See CorrelationFilter.
        if (Boolean.getBoolean("iast.target.filter")) {
            config.register(CorrelationFilter.class);
            System.err.println("APP: request filter registered");
        }
        com.sun.net.httpserver.HttpServer server = JdkHttpServerFactory.createHttpServer(base, config, false);

        // A deterministic way to end the run, outside JAX-RS so it cannot itself be mistaken for a
        // resource method. The agent flushes from a shutdown hook, and killing the process does not
        // run one - without this the harness reads a missed flush as "no findings".
        server.createContext("/shutdown", exchange -> {
            byte[] body = "bye".getBytes("UTF-8");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
            new Thread(() -> {
                server.stop(0);
                System.exit(0);
            }).start();
        });

        server.start();
        System.err.println("APP: jax-rs target listening on " + port);
    }
}
