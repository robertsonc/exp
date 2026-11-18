# Release signing keys

* `release-pub.pem` — the **public** Ed25519 release key. It is provided by the project owner and committed
  here (`keys/.gitignore` un-ignores it despite the root `*.pem` rule). Agents and `verify-release.sh` trust
  this key; rotation = ship a new public key inside a release signed by the current key (SR-10).
  *Not present until the owner supplies it:* signed builds then need `EXP_RELEASE_PUBKEY=/path/to/pub.pem`.
* The **private** key never enters the repository, the manager, or logs. Locally it lives in a 0600 file
  outside any checkout; in CI it is the `EXP_RELEASE_KEY` secret of the protected `release` environment.

Generate a pair (outside the repo; prints only the public key path):

```
packaging/gen-release-key.sh ~/.config/exp-release/release.pem     # writes release.pem (0600) + release-pub.pem
```

Tests and dev builds use **throwaway** keys in temp directories, never the real one. `.gitignore` here
additionally blocks `*priv*`, `*private*` and `*.key`; the CI gitleaks scan is the backstop.

Manual verification (what agents do):

```
openssl pkeyutl -verify -pubin -inkey release-pub.pem -rawin -in exp-X.Y.Z-manifest.json -sigfile sig.bin
# where sig.bin = base64 -d exp-X.Y.Z-manifest.json.sig
```
