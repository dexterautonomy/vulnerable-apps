package com.hingebridge.iasttarget.jaxrs;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;

/**
 * A do-nothing request filter, registered only when {@code -Diast.target.filter=true}.
 *
 * <p>It exists to make the difference measurable. The agent's {@code jaxrs} boundary is declared
 * against {@code ContainerRequestFilter.filter}, which is where the {@code ContainerRequestContext} -
 * the one portable way to read a header - is in hand. An application that registers no filter has no
 * such call, so nothing reads the correlation header and nothing opens a scope until the resource
 * method is entered, which is AFTER the container has read the body and produced every parameter.
 *
 * <p>Running the target both ways is what separates "JAX-RS is not covered" from "JAX-RS without a
 * filter is not covered", and those are very different things to report.
 */
@Provider
public class CorrelationFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) {
        // Nothing. The agent's boundary is the point, not anything this does.
    }
}
