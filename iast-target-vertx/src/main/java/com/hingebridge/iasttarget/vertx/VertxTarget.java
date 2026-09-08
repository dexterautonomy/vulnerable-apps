package com.hingebridge.iasttarget.vertx;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;

/**
 * A Vert.x Web application, as small as it can be while still crossing the threads a real one does.
 *
 * <h3>What each route is for</h3>
 *
 * <ul>
 *   <li>{@code /path?p=} - a QUERY PARAMETER reaches a dangerous call. Finds nothing today, and that
 *       is the point: the agent's shipped catalogue has no Vert.x source, so a Vert.x request value
 *       is never marked untrusted in the first place. See the README.</li>
 *   <li>{@code /json} - a JSON BODY reaches the same call, through Jackson, which IS a source the
 *       catalogue knows. This is the route that proves the boundary, the correlation and the
 *       carriage are all working - the finding it raises carries the test case that provoked it.</li>
 *   <li>Both do their dangerous work on a WORKER thread, after the handler has returned. That is the
 *       shape carriage exists for, and without it the finding would arrive anonymous.</li>
 * </ul>
 *
 * <p>One event loop on purpose ({@code setEventLoopPoolSize(1)}): every request is served by the
 * same thread, so a request whose state was left bound to it would be inherited by the next one.
 * With more loops that failure hides behind luck.
 */
public final class VertxTarget {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8090;
        Capabilities.printOnShutdown();

        Vertx vertx = Vertx.vertx(new VertxOptions().setEventLoopPoolSize(1));
        Router router = Router.router(vertx);
        // BEFORE BodyHandler on purpose: this route is reached in the router's FIRST dispatch,
        // where the boundary method that opened the request is still on the stack. Every other route
        // below runs in a LATER dispatch, after the body handler has returned. If the two behave
        // differently, that difference is the finding - see the README.
        router.get("/weak-hash-first").handler(new NamedWeakHash());

        router.route().handler(BodyHandler.create());

        // A query parameter, straight to a sink, on a worker.
        router.get("/path").handler(rc -> onWorker(vertx, rc, rc.request().getParam("p")));

        // A JSON body, parsed by Jackson, then the same sink on a worker.
        router.post("/json").handler(rc -> {
            String name;
            try {
                Payload body = MAPPER.readValue(rc.body().asString(), Payload.class);
                name = body.getName();
            } catch (Exception badJson) {
                rc.response().setStatusCode(400).end("bad json");
                return;
            }
            onWorker(vertx, rc, name);
        });

        // Diagnostic: JSON body straight to the sink, on the event loop, with no concatenation and
        // no worker hop. Isolates "was the value ever marked untrusted" from "was it tracked".
        router.post("/json-inline").handler(rc -> {
            try {
                Payload body = MAPPER.readValue(rc.body().asString(), Payload.class);
                rc.response().end(Sinks.openExact(body.getName()));
            } catch (Exception badJson) {
                rc.response().setStatusCode(400).end("bad json");
            }
        });

        // Diagnostic: a HOTSPOT, which needs no taint at all - the application asking for MD5 by
        // name is the whole evidence. Separates "the agent is not tracking values here" from "the
        // agent is not reporting here at all", which are indistinguishable from an empty report.
        router.get("/weak-hash").handler(rc -> {
            try {
                java.security.MessageDigest.getInstance("MD5");
                rc.response().end("hashed");
            } catch (Exception e) {
                rc.response().setStatusCode(500).end("no md5");
            }
        });

        // The same work as /weak-hash, in a NAMED class rather than a lambda. See NamedWeakHash.
        router.get("/weak-hash-named").handler(new NamedWeakHash());

        router.get("/health").handler(rc -> rc.response().end("ok"));

        // A deterministic way to end the run. The agent flushes its findings from a shutdown hook,
        // and killing the process does not run one - so without this the harness would assert on an
        // empty report and read "no findings" as a result rather than as a missed flush.
        router.get("/shutdown").handler(rc -> rc.response().end("bye").onComplete(ignored ->
                vertx.close().onComplete(closed -> System.exit(0))));

        vertx.createHttpServer().requestHandler(router).listen(port).toCompletionStage()
                .toCompletableFuture().get();
        System.err.println("APP: vertx target listening on " + port);
    }

    /**
     * The hand-off that matters: the handler arranges the work and RETURNS, and the dangerous call
     * happens afterwards on a worker thread.
     *
     * <p>This is the Quarkus shape too - a RESTEasy Reactive resource method returning a plain type
     * is dispatched exactly like this - and it is the reason the Vert.x boundary needed carriage
     * rather than just a span around the handler.
     */
    private static void onWorker(Vertx vertx, RoutingContext rc, String value) {
        if (value == null) {
            rc.response().setStatusCode(400).end("missing value");
            return;
        }
        vertx.<String>executeBlocking(() -> Sinks.openPath(value))
                .onComplete(result -> rc.response().end(
                        result.succeeded() ? result.result() : "failed"));
    }
}
