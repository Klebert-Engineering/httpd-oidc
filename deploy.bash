#!/usr/bin/env bash

image_name="httpd-oidc"
version="$(sed -n 's/^FROM httpd:\([0-9][0-9.]*\).*/\1/p' Dockerfile)"
push=""
latest=""
test=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -v|--version)
      version=$2
      shift
      shift
      ;;
    -p|--push)
      push="yes"
      shift
      ;;
    -l|--latest)
      latest="yes"
      shift
      ;;
    -t|--test)
      test="yes"
      shift
      ;;
  esac
done


image_name_full="ghcr.io/klebert-engineering/$image_name"
docker build -t "$image_name_full:$version" .

if [[ -n "$latest" ]]; then
  echo "Tagging latest."
  docker tag "$image_name_full:$version" "$image_name_full:latest"
fi

if [[ -n "$push" ]]; then
  echo "Pushing."
  docker push "$image_name_full:$version"
  if [[ -n "$latest" ]]; then
    docker push "$image_name_full:latest"
  fi
fi

if [[ -n "$test" ]]; then
  echo docker run --rm -v "$(pwd)/httpd.conf:/usr/local/apache2/conf/httpd.conf" \
    "$image_name_full:$version"
  docker run --rm -it \
    -v "$(pwd)/httpd.conf:/usr/local/apache2/conf/httpd.conf" \
    "$image_name_full:$version"
fi
