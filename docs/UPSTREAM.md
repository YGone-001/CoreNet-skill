# Source Governance

The repository may stage raw third-party snapshots under `third_party/` before
CoreNet-native contract integration. Such snapshots are not installed Skills and
must remain distinguishable from locally authored material.

Before importing or adapting material, maintainers must review its content, license, commit, compatibility, security impact, and relevance to this repository. Never fabricate license information or strip attribution. Preserve provenance in the imported Skill's `UPSTREAM.md`:

```yaml
repository: <canonical repository URL>
upstream_skill: <name>
upstream_path: <path>
upstream_commit: <immutable commit SHA>
license: <reviewed license identifier or text reference>
imported_at: <YYYY-MM-DD>
local_modifications: <description or none>
```

Keep local telecom-specific material separate—for example `extensions/telecom-core-network.md`—so source synchronization remains practical. Re-review provenance and license on every update.
