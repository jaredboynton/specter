# Specters Has Moved To Warpsock

The `specters` crate is deprecated. Use `warpsock` instead.

```toml
[dependencies]
warpsock = "4.2"
```

Rust import paths changed from `specter::...` to `warpsock::...`.

This compatibility crate re-exports Warpsock for existing consumers while emitting a build warning so the migration is visible in CI logs.
