#!/usr/bin/env bash
# Local build and test. Publishing to ghcr.io happens only through a GitHub
# release (see README), so published versions are never overwritten by hand.

image="httpd-oidc:local"
test=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--test)
      test="yes"
      shift
      ;;
    -p|--push|-l|--latest|-v|--version)
      echo "Publishing moved to GitHub releases: create release v<httpd version>-<build number>, e.g. v2.4.71-1." >&2
      exit 1
      ;;
    *)
      echo "usage: $0 [-t|--test]" >&2
      exit 1
      ;;
  esac
done

docker build --pull -t "$image" .

if [[ -n "$test" ]]; then
  echo docker run --rm -v "$(pwd)/httpd.conf:/usr/local/apache2/conf/httpd.conf" "$image"
  docker run --rm -it \
    -v "$(pwd)/httpd.conf:/usr/local/apache2/conf/httpd.conf" \
    "$image"
fi
