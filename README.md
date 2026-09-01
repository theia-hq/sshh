# sshh

> Archived: folded into [swoosh](https://github.com/theia-hq/swoosh) as the in-workspace crate
> `crates/sshh`. It had one consumer (swoosh, behind the `ssh` feature); it now lives beside the CLI that
> injects it. Nothing to install here.

An SSH server with no ssh keys to manage. You hand it one byte stream that has already been
authenticated, and it runs a real SSH session over it: a standard `ssh` or `scp` client gets a shell, and
nobody sets up or rotates an ssh key.

**sshh does no authentication of its own.** That is the whole point, and it is the whole contract: proving
who the peer is must already be done before the stream reaches `serve()`, and guaranteeing that is the
CALLER's responsibility. Because the peer is already proven, the server accepts SSH's `none` auth method
and goes straight to a shell in a pty. This is the same shape as Tailscale SSH, which accepts `none`
behind the WireGuard tunnel.

The contract is enforced by the type system, not left to good intentions. `serve()` demands a
`nauthy::Admitted` witness: an opaque token a gate hands back only on a successful admit, with no public
constructor. You cannot fabricate one, so you cannot call `serve()` without having run a gate first, and a
keyless shell can never be handed out un-gated by accident. Note what the witness does and does not prove:
it proves a gate admitted a peer, but it carries no peer or service inside it, so it is the caller's job to
serve it on the very stream the gate just authorized. tightbeam does exactly that (it admits and serves on
one stream, inches apart), which is why the guarantee holds in practice.

```rust
// `admitted` is a gate's proof it authorized this peer; `writer`/`reader` are the two halves of the
// already-authenticated stream. There is no way to obtain an `Admitted` without a gate having admitted.
sshh::serve(&admitted, host_seed, writer, reader).await?;
```

**The name.** An SSH server with no keys to hand out or rotate: authentication happened before the shell,
so the login step falls away. The extra *h* is the *shh* of that: SSH gone quiet, nothing to set up and
nothing to say.

> Experimental. Serves a login shell (or `sh -c <command>`) in a pty; see "Not yet" below.

## How it composes, and how it's used

sshh is a library, not a server you run. It supplies the shell; something else supplies the gate that
mints the `Admitted` witness. sshh knows nothing about that gate beyond the `Admitted` type, so any gate
can drive it. In theia, two crates compose it:

- [nauthy](https://github.com/theia-hq/nauthy) is the gate. It verifies a presented capability and, on
  success, returns an `Admitted` witness for that peer and service. That witness is the key that unlocks
  `serve()`.
- [tightbeam](https://github.com/theia-hq/tightbeam) is the exposer. `tightbeam serve ssh=sshd:` runs the
  accept loop: for each connection it gates the stream through nauthy, takes the `Admitted`, and calls
  `sshh::serve` with it. A capability holder then reaches the shell with a normal ssh client, no ssh key
  involved. It lives behind tightbeam's `ssh` feature.

So a real deployment reads as `tightbeam serve ssh=sshd:` (gated to your signet by default), but that is
one example, not a dependency: hand `serve()` an authenticated stream and an `Admitted` from any gate and
you have keyless SSH. You never point sshh at a socket yourself.

`sshh` is its own crate because it pulls in a heavy dependency tree (`russh`, `ssh-key`, `pty-process`).
Keeping it separate lets tunnel binaries that never serve a shell stay lean.

## Safety model

A shell has no login of its own, so everything rests on the stream being pre-authenticated. The rules:

- **The capability is the auth.** Only ever hand `serve()` a stream a real gate already admitted. Never a
  raw socket, never an `open` gate. There is no second password behind this door.
- **It refuses to run as root.** The shell runs as this process's user, so a privileged process would
  hand every caller a root shell. `serve()` returns an error rather than serve as root.
- **The host key is stable.** It is derived from the node's own identity, so a client's `known_hosts`
  pins the machine you dial and detects a later swap, instead of showing a fresh-key warning every time.
- **A revoked capability is refused at connect.** The gate checks revocation when a session opens, so a
  revoked cap cannot start a new shell. Know the limit: it does NOT cut a session already in progress. The
  recall story is revoke plus a short cap TTL, not mid-session eviction.
- **One shell, one user: everyone admitted lands as this process's user.** There is no per-peer account
  mapping, so a delegated slip is trust to run a shell as this user, not a sandboxed guest. Scope what you
  delegate accordingly (short TTL, one service), and run the host unprivileged (it refuses root anyway).

## Not yet

- **Dynamic window resize.** A terminal resize mid-session is not yet propagated to the pty.
- **SFTP / scp.** Interactive shells and `exec` work; file transfer does not.
- **Per-user mapping.** The shell always runs as this process's own user; there is no mapping from the
  connecting peer to a local account.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
