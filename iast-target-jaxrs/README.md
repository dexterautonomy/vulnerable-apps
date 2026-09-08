# iast-target-jaxrs

A real JAX-RS application - Jersey 2.41 on the JDK's own HTTP server - for exercising the IAST agent
against the `jaxrs` and `jaxrs-method` boundaries.

No servlet container anywhere, on purpose. A JAX-RS target on Tomcat is served through the SERVLET
boundary, which already works, and would say nothing about this one.

It registers **no `ContainerRequestFilter`**, also on purpose. That is an ordinary way to write a
JAX-RS service, and it is the interesting case: see below.

## Running it

```bash
mvn package && ./run.sh
```

Starts the app under the agent, drives every route with a **signed** correlation header, shuts down
cleanly so the agent flushes, and prints what it made of the run.

## The routes

| route | what it isolates |
|---|---|
| `/weak-hash` | a hotspot - needs no taint at all, so it answers "is the agent reporting here?" |
| `/path?p=` | a `@QueryParam`, injected by the container |
| `/path/{segment}` | a `@PathParam`, the other half of the same question |
| `/json` | a JSON body through Jackson, which the catalogue does know as a source |

Parameter INJECTION is the difference from the Vert.x target. A Vert.x handler asks the request for
its parameters; here the container has already read them and hands them over as method arguments, so
a source that watches request accessors sees nothing.

## What this application found

**1. Every hotspot was off on JAX-RS.** A resource method is handed no request object - there is
nothing portable to read a header or a path from there, which the boundary's own design notes say
plainly - so its boundary opened a scope with a null request descriptor. The engine used that
descriptor as its "are we inside a request?" test, which conflates *we could not read what this
request was* with *there is no request*. Weak hash, weak cipher and insecure random were therefore
unreportable on any JAX-RS application. Fixed by asking the boundary depth instead, which is the
question the gate was actually asking and still suppresses the boot-time noise it was added for.

**2. The `jaxrs` boundary could not read the correlation header it exists to read.** That boundary is
declared against `ContainerRequestFilter.filter` precisely because the `ContainerRequestContext` is
the one portable way to read a header across Jersey, RESTEasy and CXF - and it was asking that context
for `getHeader(String)`, which the interface does not declare. It is `getHeaderString`. So the
boundary ran on every request, opened a scope, and read nothing: five requests served, five
uncorrelated, every one carrying a signed header.

Run the target with `TARGET_OPTS=-Diast.target.filter=true` to see it: `correlated` goes 0 -> 4.

## The remaining gap, and why it is a design decision rather than a fix

Even with a filter registered and the header now read, **the findings are still uncorrelated**. The
filter and the resource method are two separate boundaries that run one after the other rather than
nested: the filter opens a scope, returns, and its scope closes; the resource method then opens a
fresh one and has no request object to re-read the header from.

On Quarkus this does not arise, because the Vert.x carriage keeps the request bound across the
hand-off and the resource method joins it. Jersey has no such carriage.

Closing it means the filter boundary leaving its request OPEN across the resource method - which is
what the Vert.x boundary now does - and that raises a real question the agent must not answer by
accident: a request that is filtered but never reaches a resource method (a 404, a filter that
aborts) would leave a scope bound to a pooled thread, and the next request on that thread would
inherit another request's identity. That is the worst failure this agent has, so it wants a decision
rather than a patch.

## What it still does not find

Both are real gaps, both are in the agent rather than in this application, and neither is a defect in
what was built - they are things nobody has built yet.

**1. Nothing is correlated.** The boundary reports `correlated: 0` and `uncorrelatedNoHeader: 5`
against five requests that all carried a signed header. The `jaxrs` boundary is declared against
`ContainerRequestFilter.filter`, which is where the `ContainerRequestContext` - the one portable way
to read a header - is in hand. **An application that registers no filter has no such call**, so the
only boundary that runs is `jaxrs-method`, which by design passes no request object. Findings still
arrive; they carry a generated request id and cannot be tied to the test case that provoked them.

Registering a filter in this application would hide that, which is why it does not.

**2. An injected parameter — now covered by mechanism, pending one identity check (2026-09-07).**
This was the gap this section used to call a design decision. The engine now WALKS a returned
container — a `Map` (keys and values), an `Object[]`, and any `Iterable` — instead of minting only a
String and the String elements of an array. On the back of that, the catalogue declares
`UriInfo.getQueryParameters` / `getPathParameters` (the `MultivaluedMap` Jersey reads an injected
`@QueryParam` / `@PathParam` out of) and the multi-value header accessors. So the value the resource
method is handed is tainted through the map it came from.

The remaining question is IDENTITY, and it is why this is "pending" rather than "done": taint is
keyed on the object, so coverage holds only if the String instance Jersey injects is the SAME
instance the `MultivaluedMap` holds. The engine walk and the catalogue are proven end to end
(`SourceReturnWalkTest`, and the `mapwalk` assertion in `run-e2e.sh` — a value pulled out of a
returned parameter map reaches a SQL sink tainted). What is NOT yet proven is that Jersey's own
injection preserves that instance, which only a live run of this sample app on Jersey shows. If it
copies or re-decodes, the fix needs the source declared one accessor lower, at whatever Jersey calls
last before handing the value over.

Quarkus never had this problem: RESTEasy Reactive resolves the same annotations by reading the
underlying Vert.x request, which was already covered.

**3. `/json` reports nothing either**, and unlike the two above this is specific to Jersey: the same
JSON body is found on both the Vert.x and the Quarkus targets. Two things are in the way here - the
body is deserialised BEFORE the resource method is entered, so the boundary that would own the taint
has not opened yet, and Jersey's Jackson provider deserialises through `ObjectReader` while the
catalogue's Jackson source is declared on `ObjectMapper`. Worth separating from "JSON bodies are not
covered", which is not true.

Taken together: on a plain JAX-RS application today the agent reports hotspots and nothing else, and
its findings cannot be tied to the test case that provoked them. On Quarkus - the same JAX-RS
annotations over a Vert.x HTTP layer - all of that works, which is what makes the gap a JAX-RS-runtime
question rather than a JAX-RS one.
