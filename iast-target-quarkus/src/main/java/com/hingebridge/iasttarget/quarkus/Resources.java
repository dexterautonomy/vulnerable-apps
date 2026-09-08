package com.hingebridge.iasttarget.quarkus;

import io.smallrye.common.annotation.Blocking;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * The resource, in both of the shapes RESTEasy Reactive actually runs.
 *
 * <h3>Why every route exists twice</h3>
 *
 * A plain resource method runs ON THE EVENT LOOP; a {@code @Blocking} one is dispatched to a WORKER
 * and the invoker returns as soon as that dispatch is queued. The second is the shape the Vert.x
 * carriage was built for and the majority of real endpoints - anything touching a database, a file or
 * a command has to be blocking - so a target with only the first would exercise the easy half and
 * report success.
 */
@Path("/")
public class Resources {

    /** A hotspot on the event loop: the synchronous span, which needed no carriage. */
    @GET
    @Path("weak-hash")
    @Produces(MediaType.TEXT_PLAIN)
    public String weakHash() throws Exception {
        java.security.MessageDigest.getInstance("MD5");
        return "hashed";
    }

    /**
     * The same hotspot on a WORKER. If this reports and the one above does too, the request outlived
     * the invoker's return and the thread that did the work knew which request it was serving.
     */
    @GET
    @Path("weak-hash-blocking")
    @Blocking
    @Produces(MediaType.TEXT_PLAIN)
    public String weakHashBlocking() throws Exception {
        java.security.MessageDigest.getInstance("MD5");
        return "hashed-blocking";
    }

    /** A query parameter, injected by the container, straight to a sink on a worker. */
    @GET
    @Path("path")
    @Blocking
    @Produces(MediaType.TEXT_PLAIN)
    public String queryParameter(@QueryParam("p") String p) {
        return p == null ? "missing value" : Sinks.openPath(p);
    }

    /** A JSON body through Jackson - the source the catalogue does know - then a sink on a worker. */
    @POST
    @Path("json")
    @Blocking
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String jsonBody(Payload body) {
        return body == null || body.getName() == null ? "missing value" : Sinks.openExact(body.getName());
    }

    @GET
    @Path("health")
    @Produces(MediaType.TEXT_PLAIN)
    public String health() {
        return "ok";
    }

    /**
     * A deterministic end to the run. The agent flushes from a shutdown hook, and killing the process
     * does not run one - without this the harness reads a missed flush as "no findings".
     */
    @GET
    @Path("shutdown")
    @Produces(MediaType.TEXT_PLAIN)
    public String shutdown() {
        new Thread(() -> {
            try {
                Thread.sleep(200);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            io.quarkus.runtime.Quarkus.asyncExit();
        }).start();
        return "bye";
    }
}
