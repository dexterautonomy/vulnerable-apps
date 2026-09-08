package com.hingebridge.iasttarget.jaxrs;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * The resource. Every route is a plain JAX-RS method with annotated parameters, which is how a real
 * service is written and is the shape the {@code jaxrs-method} boundary is declared against.
 *
 * <p>Parameter INJECTION is the whole difference from the Vert.x target. A Vert.x handler asks the
 * request for its parameters; here the container has already read them and hands them over as method
 * arguments, so a source that watches request accessors sees nothing at all.
 */
@Path("/")
public class Resources {

    /** A query parameter, injected. Nothing in between it and the sink. */
    @GET
    @Path("path")
    @Produces(MediaType.TEXT_PLAIN)
    public String queryParameter(@QueryParam("p") String p) {
        return p == null ? "missing value" : Sinks.openPath(p);
    }

    /** A path parameter, injected. The other half of the same question. */
    @GET
    @Path("path/{segment}")
    @Produces(MediaType.TEXT_PLAIN)
    public String pathParameter(@PathParam("segment") String segment) {
        return Sinks.openExact(segment);
    }

    /**
     * A JSON body, deserialised by Jackson - which the agent's catalogue DOES know as a source. This
     * is the route that proves the boundary and the correlation are working when the parameter
     * routes report nothing.
     */
    @POST
    @Path("json")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String jsonBody(Payload body) {
        return body == null || body.getName() == null ? "missing value" : Sinks.openExact(body.getName());
    }

    /**
     * A HOTSPOT, which needs no taint at all: asking for MD5 by name is the whole evidence.
     *
     * <p>It separates "the agent is not tracking values here" from "the agent is not reporting here
     * at all" - two things that are indistinguishable from an empty report, and the pair that took
     * the longest to tell apart on the Vert.x target.
     */
    @GET
    @Path("weak-hash")
    @Produces(MediaType.TEXT_PLAIN)
    public String weakHash() throws Exception {
        java.security.MessageDigest.getInstance("MD5");
        return "hashed";
    }

    @GET
    @Path("health")
    @Produces(MediaType.TEXT_PLAIN)
    public String health() {
        return "ok";
    }
}
