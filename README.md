# Webserver

An Apache webserver image including `mod_auth_openidc` and self-signed certificates that can be overridden with "real" certs by mounting them as volumes.

This image is useful if you would like to protect some web content with an OIDC provider, like [Keycloak](https://www.keycloak.org/). For more information, see [the original repository](https://github.com/zmartzone/mod_auth_openidc).

## Image

```
docker pull ghcr.io/klebert-engineering/httpd-oidc:2.4.71-1   # pinned, never changes
docker pull ghcr.io/klebert-engineering/httpd-oidc:latest     # newest release
```

Versions are `<httpd version>-<build number>`: `2.4.71-1` is the first build on `httpd:2.4.71`, `2.4.71-2` the next one on the same httpd (for example with newer Debian security fixes), `2.4.72-1` the first one on the next httpd. A published version is never overwritten; `latest` is the only tag that moves. Each release's notes list the image digest.

### Releasing

The Build workflow builds and smoke-tests (`test/smoke.sh`) every PR and every push to `main`, but publishes nothing. To publish, create a GitHub release with the tag `v<httpd version>-<build number>`, e.g. `v2.4.71-1`, targeting `main`:

```
gh release create v2.4.71-1 --target main --title v2.4.71-1 --notes-file notes.md
```

The Release workflow checks that the tag matches the httpd version in the `Dockerfile` and that the version is not published yet, builds without cache, runs the smoke test, pushes `<version>` and (unless it is a prerelease) `latest`, and adds the image digest to the release notes. Write release notes in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style (`### Security`, `### Changed`, …).

`deploy.bash -t` builds the image locally and runs it with a `httpd.conf` from the repository root; it does not publish.

## Vulnerability monitoring

* **Dependabot** opens a PR when a new `httpd` base image tag is published (daily) and keeps the workflow actions current (weekly).
* **Vulnerability scan** runs daily and after each release. It checks the httpd version in the published image against [Apache's advisories](https://httpd.apache.org/security/vulnerabilities_24.html) and scans the image with [Grype](https://github.com/anchore/grype) for packages with a fix available (high or critical). Findings are kept in one issue labeled `vulnerability-scan`, which says what to do, including a link to a pre-filled form for the next release, and is closed automatically when the next scan is clean. Full Grype results are in the Security tab. The people notified are set in `NOTIFY` in `.github/workflows/vulnerability-scan.yml`.

## Minimal httpd.conf for a keycloak reverse proxy

```
ServerName my.server

Listen 8099

LogLevel debug

LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule headers_module modules/mod_headers.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule unixd_module modules/mod_unixd.so

LoadModule auth_openidc_module /usr/lib/apache2/modules/mod_auth_openidc.so

# OIDC Configuration
OIDCProviderMetadataURL https://my-domain/auth/realms/my-realm/.well-known/openid-configuration
OIDCClientID my-client-id
OIDCClientSecret v3rys3cr3t
OIDCRedirectURI redirect.uri
OIDCCryptoPassphrase sup3rs3cr3t
OIDCScope "openid email profile roles"

# Reverse proxy configuration
ProxyPreserveHost On
ProxyRequests Off
ProxyPass / http://proxy:8089/
ProxyPassReverse / http://proxy:8089/

<Location />
    AuthType openid-connect
    Require valid-user
</Location>
```
