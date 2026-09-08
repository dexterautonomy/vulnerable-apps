package com.hingebridge.iasttarget.vertx;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * The same work as the {@code /weak-hash} lambda, written as a NAMED class.
 *
 * <p>Diagnostic, and the only difference between the two routes. A lambda is a hidden class the JVM
 * builds at runtime and no agent can instrument, so if the request boundary is on the application's
 * own {@code Handler}, a lambda route is invisible to it while this one is not. Almost every real
 * Vert.x route is written as a lambda, so the difference between these two answers decides whether
 * that boundary is worth having at all.
 */
public final class NamedWeakHash implements Handler<RoutingContext> {

    @Override
    public void handle(RoutingContext rc) {
        try {
            java.security.MessageDigest.getInstance("MD5");
            rc.response().end("hashed-named");
        } catch (Exception noMd5) {
            rc.response().setStatusCode(500).end("no md5");
        }
    }
}
