# iast-target-quarkus

A real Quarkus application (3.15.1, JVM mode) for exercising the IAST agent against the stack that
puts three boundaries on one request: a resource method is **jakarta JAX-RS**, it is invoked through a
generated **RESTEasy Reactive** invoker, and the HTTP layer underneath all of it is **Vert.x**.

It is also the stack the Vert.x carriage work was done for. A resource method marked `@Blocking` is
dispatched to a worker and the invoker returns as soon as that dispatch is queued, so everything the
method does happens after the handler has returned.

JVM mode only. A native image has no agent, so there is nothing here to attach to.

## Running it

```bash
mvn package && ./run.sh
```

Starts the app under the agent, drives every route with a **signed** correlation header, shuts down
cleanly so the agent flushes, and prints what it made of the run.

## The routes, and why each exists twice

| route | thread | what it isolates |
|---|---|---|
| `/weak-hash` | event loop | a hotspot in the synchronous span - the half that never needed carriage |
| `/weak-hash-blocking` | worker | the same hotspot after the invoker has returned |
| `/path?p=` | worker | whether an injected `@QueryParam` is treated as untrusted |
| `/json` | worker | a JSON body through Jackson, then a sink, across the thread hand-off |

A target with only the event-loop shape would exercise the easy half and report success. Anything
touching a database, a file or a command has to be `@Blocking`, so the worker shape is the majority of
a real service.

## What this application found

**Correlation and taint were both being destroyed at the resource method.** The Vert.x boundary reads
the header, opens the request, and then RELEASES the thread when its handler returns - the work has
moved to a worker and the carriage binds the request back to whichever thread runs it. By the time the
JAX-RS resource method was entered the depth was back to zero, so that boundary read the thread as a
stale one from a pool: it reset the request state and re-read the correlation from its own request
object, of which it has none.

The result was two things each correct on their own, disagreeing: the Vert.x boundary reported four
correlated requests while every finding those requests produced carried a generated id. And because
the reset also cleared the request's dirty flag, `/json` produced **no finding at all** - the taint
was minted and then the request that owned it was thrown away.

Both are fixed by joining rather than starting over when a carried dispatch is in progress. On this
application: `jaxrs-method` correlated 0 -> 4, and findings 2 -> 3.

## What it still does not find

`/path` reported nothing when this application was written - the catalogue had no Vert.x or JAX-RS
source of any kind. It now reports, as `HTTP_URI(uri)`: RESTEasy Reactive resolves an injected
`@QueryParam` by reading the underlying Vert.x request, so the Vert.x source entries reach Quarkus
without needing a JAX-RS one.

What is still uncovered is any value the application pulls out of a returned MAP or LIST -
`params()`, `headers()`, `queryParams()`. A returned collection is not walked: the engine mints on a
String and on the String elements of an array, and nothing else.

So on Quarkus today the agent covers hotspots, request parameters and the request line, and anything
arriving through a JSON body - correlated correctly and across the worker hand-off.
