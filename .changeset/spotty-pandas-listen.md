---
"@logto/core": patch
---

honor `IsPassive` and `Subject` on SAML application authentication requests

Follow-up to the `ForceAuthn` handling, covering the two remaining request constraints from SAML 2.0 core section 3.4.1:

- `IsPassive="true"` now maps to `prompt=none` on the OIDC authorization request, so Logto no longer takes visible control of the user interface for a passive request. When no session exists, the callback translates the provider's `login_required` / `interaction_required` error into a SAML `NoPassive` status response POSTed to the service provider, instead of landing the user on a Logto error page.
- A `<saml:Subject>` on the `AuthnRequest` is now compared against the NameID that would be asserted for the signed-in user. On a mismatch the service provider receives an `UnknownPrincipal` status response rather than an assertion for a different user.

A request carrying both `ForceAuthn="true"` and `IsPassive="true"` is rejected as malformed, since the two attributes contradict each other.

Error status responses are assertion-less and therefore never assertion-encrypted; they are produced by a dedicated identity-provider instance that leaves encryption to success responses.
