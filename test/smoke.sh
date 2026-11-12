#!/usr/bin/env bash
# Smoke test for the httpd-oidc image: config parses, mod_auth_openidc loads,
# and a protected request is answered by the OIDC module.
# Usage: test/smoke.sh <image>
set -euo pipefail

image="${1:?usage: test/smoke.sh <image>}"
conf="$(cd "$(dirname "$0")" && pwd)/httpd.conf"
mount=(-v "$conf:/usr/local/apache2/conf/httpd.conf:ro")
name="httpd-oidc-smoke-$$"
port="${SMOKE_PORT:-18099}"

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== httpd version"
docker run --rm "${mount[@]}" "$image" httpd -v

echo "== config syntax"
docker run --rm "${mount[@]}" "$image" httpd -t

echo "== auth_openidc module loaded"
modules="$(docker run --rm "${mount[@]}" "$image" httpd -M)"
grep -q 'auth_openidc_module' <<<"$modules" || { echo "auth_openidc_module not loaded"; echo "$modules"; exit 1; }
echo "auth_openidc_module present"

echo "== server answers a protected request"
docker run -d --name "$name" -p "$port:8099" "${mount[@]}" "$image" >/dev/null
code=000
for _ in $(seq 1 20); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$port/" || true)"
  [[ "$code" != 000 ]] && break
  sleep 0.5
done
echo "GET / -> HTTP $code"
# The placeholder provider is unreachable, so mod_auth_openidc must try to fetch
# its metadata and answer 500 instead of proxying the request.
logs="$(docker logs "$name" 2>&1)"
if [[ "$code" == 500 ]] && grep -q 'auth_openidc:error.*could not retrieve metadata' <<<"$logs"; then
  echo "smoke test passed: mod_auth_openidc handled the request"
else
  echo "$logs"
  echo "smoke test failed: expected HTTP 500 from mod_auth_openidc, got $code"
  exit 1
fi
