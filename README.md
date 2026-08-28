# sshh

An SSH server with no ssh keys to manage. You hand it one byte stream that has already been
authenticated and encrypted, and it runs a real SSH session over it: a standard `ssh` or `scp` client
gets a shell, and nobody sets up or rotates an ssh key.

The trick is that SSH's usual job of proving who you are is already done. `serve()` takes a stream that
something upstream has mutually authenticated (by public key) and authorized. Because that peer is
already proven, the server accepts SSH's `none` auth method and goes straight to a shell in a pty. This
is the same shape as Tailscale SSH, which accepts `none` behind the WireGuard tunnel.

```rust
// `writer`/`reader` are the two halves of a stream a gate has already admitted.
sshh::serve(host_seed, writer, reader).await?;
```

> Experimental. Serves a login shell (or `sh -c <command>`) in a pty; see "Not yet" below.

## How it's reached

You do not point `sshh` at a socket yourself. It is reached through [tightbeam](https://github.com/theia-hq/tightbeam),
which addresses machines by public key and gates who may connect. Expose a machine's shell as a
capability-gated service:

```sh
tightbeam expose ssh=sshd: --gate cap
```

A holder of a capability link then reaches it with a normal ssh client (via tightbeam's `ProxyCommand`
recipe), and lands in a shell. It runs behind tightbeam's `ssh` feature.

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
- **A revoked capability is refused.** Once the granting capability no longer verifies, the connection
  never reaches the shell.

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
