# X.509 user authentication

Configure a HANA ProviderConfig, import the trusted CA certificates, and create
the X509Provider and its PSE before creating the User. Adjust the example issuer,
subject and certificate references for your environment.

In `users.yaml`, select the provider by Kubernetes reference:

```yaml
authentication:
  x509Providers:
    - providerRef:
        name: x509provider
      subjectName: CN=example-client, O=example-org, C=US
```

Alternatively, use the HANA provider name:

```yaml
authentication:
  x509Providers:
    - name: X509_PROVIDER
      subjectName: CN=example-client, O=example-org, C=US
```

Both forms resolve to the same database provider/subject identity. Resolution
does not alter the User spec and does not remove/re-add an unchanged mapping.
An omitted subject defaults to `ANY`, matching a null subject in the HANA catalog.

When X.509 mappings are configured, the provider registers the identities and
executes `ALTER USER ... ENABLE X509`. No separate administrator enablement step
or `enableX509` field is needed. The provider observes `SYS.USERS.IS_X509_ENABLED`
as `status.atProvider.isX509Enabled` and repairs disabled authentication even if
the mappings themselves already match. Enablement failures are reconciliation
errors rather than a successful ready state.

Removing all desired X.509 mappings removes those mappings but deliberately
does **not** execute `DISABLE X509`. Users with no desired X.509 mappings do not
have their authentication flag changed by this feature.

For restricted users, set `enableClientConnect: true` and grant only the roles
and object privileges needed by the workload. Client-connect enablement, PSE
trust, and user activation/validity remain separate requirements for login.

Check reconciliation and the observed authentication flag:

```bash
kubectl get users.admin.hana.sap.crossplane.io x509-user \
  -o jsonpath='{.status.atProvider.isX509Enabled}{"\n"}'
```

Expect `true` after reconciliation. Confirm actual certificate-based login with
your HANA SQL client using the matching private key and client certificate chain;
do not commit either private keys or populated credential Secrets.
