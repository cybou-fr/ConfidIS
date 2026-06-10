# CONFIDIS .deb Docker rehearsal

This rehearsal proves the package path in a clean Debian container:

- builds the real `.deb` inside Docker;
- signs the `.deb` release artifact with a synthetic 2-of-3 authority set;
- installs the package with `dpkg -i` in a fresh Debian runtime image;
- verifies that install creates the company-node config and local data files;
- starts the installed node from `/usr/bin/confidis` as the `confidis` system user;
- checks local `/health`, `/node-info`, `/peers`, loopback-only binding and release signature verification.

It intentionally does **not** claim the full G3 proof. Plain Docker does not run the package through a real host `systemd` boot path or a public TLS reverse proxy. The real G3 rehearsal still uses `scripts/g2-5-deb-rehearsal.sh` on a Debian/Ubuntu host with systemd, TLS and independent nodes.

Run:

```bash
docker build \
  -f docker/deb-rehearsal/Dockerfile \
  --target runtime \
  -t confidis/deb-rehearsal:latest \
  .

docker run --rm confidis/deb-rehearsal:latest
```

The Docker build embeds a synthetic valid root public key only for rehearsal. A production release must be built from the real G2 authority ceremony/HSM path.
