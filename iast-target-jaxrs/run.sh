#!/usr/bin/env bash
# Runs the target under the agent, drives every route with a SIGNED correlation header, and prints
# what the agent made of it. One script so a run is reproducible rather than a remembered command.
set -u
PORT="${PORT:-8091}"
SECRET="${SECRET:-target-secret}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT="${AGENT:-$HERE/../../iast-agent/iast-agent/target/iast-agent-1.8.0.jar}"

W_AGENT="$(cygpath -w "$AGENT")"
W_CP="$(cygpath -w "$HERE/target/iast-target-jaxrs-1.0.0.jar");$(cygpath -w "$HERE/target/libs")\*"

sig() { printf '%s' "pl_t|tc_$1|rq_$1|attack" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1; }
bg()  { echo "iast.pipelineId=pl_t,iast.testCaseId=tc_$1,iast.requestId=rq_$1,iast.intent=attack,iast.sig=$(sig "$1")"; }

java -javaagent:"$W_AGENT" -Diast.hmac.secret="$SECRET" ${TARGET_OPTS:-} -cp "$W_CP" \
     com.hingebridge.iasttarget.jaxrs.JaxRsTarget "$PORT" > "$HERE/target/run.log" 2>&1 &
APP=$!

for _ in $(seq 1 60); do curl -fsS "http://localhost:$PORT/health" >/dev/null 2>&1 && break; sleep 0.5; done

echo "--- driving ---"
curl -s -H "baggage: $(bg 1)" "http://localhost:$PORT/weak-hash";              echo "  <- /weak-hash (hotspot, no taint needed)"
curl -s -H "baggage: $(bg 2)" "http://localhost:$PORT/path?p=../../etc/passwd"; echo "  <- /path (query parameter, injected)"
curl -s -H "baggage: $(bg 3)" "http://localhost:$PORT/path/..%2F..%2Fetc%2Fshadow"; echo "  <- /path/{segment} (path parameter)"
curl -s -H "baggage: $(bg 4)" -H 'content-type: application/json' -d '{"name":"../../etc/hosts"}'      "http://localhost:$PORT/json";                                            echo "  <- /json (Jackson body)"

curl -s "http://localhost:$PORT/shutdown" >/dev/null
wait $APP 2>/dev/null
echo "--- agent output ---"
grep -E "IAST|APP:|FINDING|capabilit" "$HERE/target/run.log" | tail -40
