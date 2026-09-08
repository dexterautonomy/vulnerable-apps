# iast-target-vertx

A small, real Vert.x Web application for exercising the IAST agent against the stack it is hardest
to get right. Not a unit test and not a mock: Vert.x really does hand work between an event loop and
a worker pool, and every defect listed below survived a green unit suite and was found by running
this.

## Running it

```bash
./run.sh
```

Builds nothing - run `mvn -o package` first - starts the app under the agent, drives every route with
a **signed** correlation header, shuts down cleanly so the agent flushes, and prints what it made of
the run. Signed matters: the agent verifies signatures by default, so an unsigned request is treated
as ordinary traffic and correlates with nothing.

`/shutdown` exists for the same reason. The agent flushes from a shutdown hook, and killing the
process does not run one - so without it the harness reads a missed flush as "no findings".

## The routes, and what each one separates

| route | shape | what it isolates |
|---|---|---|
| `/weak-hash-first` | named handler, registered **before** `BodyHandler` | a hotspot in the router's FIRST dispatch |
| `/weak-hash` | lambda handler | the same, in a later dispatch, from a handler no agent can instrument |
| `/weak-hash-named` | named handler, after `BodyHandler` | the same, in a later dispatch, from a handler that can be |
| `/path?p=` | query parameter, worker hop, sink | whether a Vert.x request VALUE is treated as untrusted |
| `/json` | JSON body, worker hop, sink | taint surviving a thread hand-off |
| `/json-inline` | JSON body, sink, no hop | a missing SOURCE against a broken PROPAGATOR |

The three hotspot routes look redundant and are not. A hotspot needs no taint at all, so it answers
"is the agent reporting here?" independently of "is the agent tracking values here?" - and the three
positions tell a dispatch problem from a lambda problem from a sensor problem. All three were needed:
the first working theory was lambdas, and it was wrong.

One event loop on purpose (`setEventLoopPoolSize(1)`): every request is served by the same thread, so
a request whose state was left bound to it is inherited by the next one. With more loops that failure
hides behind luck.

## What this application found

Three defects in the agent, all of them silent, none visible from a clean build.

1. **Every hotspot was off on Vert.x and Quarkus.** The request descriptor was read with the servlet
   spelling only (`getMethod`/`getRequestURI`/`getQueryString`); Vert.x asks a request for
   `method()`/`path()`/`query()`, and a Vert.x boundary is handed a RoutingContext, which has none of
   the six. The descriptor came back null, and the engine reads a null descriptor as *not inside a
   request* - which is what gates weak hash, weak cipher and insecure random. Findings also arrived
   with no route, so a Vert.x finding could not say which endpoint produced it.

   Found by putting a hotspot on the line ABOVE a sink that did report: same class, same request,
   same thread, one line apart. That ruled out the boundary, the correlation and the carriage in one
   step.

2. **One unbalanced span per request.** The request boundary's exit called `TaintScope.clear()`,
   which removes the span stack - but on a carried framework that exit runs INSIDE a dispatch, and
   the stack belongs to the dispatch. The `endDispatch` that followed then unwound a frame that was
   not there, and the thread was stripped half way through the dispatch still serving it.

3. **The startup line named the wrong boundaries.** It was a literal, `requestBoundary=servlet+reactive`,
   from when those were the only two. On this application it named two boundaries that never attached
   and omitted the one that did.

## The gap it closed

`/path` reported nothing when this application was written, and that was the finding: **the shipped
source catalogue had no Vert.x entry at all** - not `getParam`, not `getHeader`, not the request line
- so a value read from a Vert.x request was never untrusted and nothing driven by a query, path or
header parameter could be reported on Vert.x or Quarkus. On an agent whose Vert.x boundary,
correlation and carriage all worked.

It now reports `HTTP_PARAMETER(p)`, correlated to the test case that sent it.

Adding those sources also caught a defect in the carriage work: a source minting taint leaves a scope
on the thread, and the boundary was reading "a scope exists" as "a request is already being carried" -
so it joined instead of reading the correlation header, and every finding on all three targets lost
its request id at once. The check now asks whether a BOUNDARY joined the scope, which a source mint
never does.

## What it still does not find, and why that is correct

`RoutingContext.queryParam()` returns a List and `params()`/`headers()` return maps, and a returned
collection is NOT walked - the engine mints on a String and on the String elements of an array, and
nothing else. So those accessors are deliberately left out of the catalogue rather than declared and
ineffective. Application code that reads `request().getParam("q")` is covered; code that pulls the
same value out of `params()` is not.
