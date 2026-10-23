# company-tls-lab

A 12-container "company-ish" network for testing an SSL/TLS scanner's
discovery, port-mapping, and vulnerability-detection logic end to end -
built with [containerlab](https://containerlab.dev/).

## Topology

```
                        core-rtr
                       /         \
                 10.10.0.0/30   10.10.0.4/30
                     /               \
               dmz-rtr             corp-rtr
                  |                 /     \
           10.20.0.0/24    10.30.10.0/24  10.30.20.0/24
             (sw-dmz)       (sw-finance)  (sw-engineering)
                |                |              |
   4 DMZ web hosts        fin-app, fin-db   eng-git, eng-fileserver, scanner
```

Three routers (FRR, static routing - deterministic, nothing to converge),
three switches (pre-created Linux bridges, zero container overhead), and
nine containers doing actual work (8 targets + your scanner) = **12
devices**, matching what you asked for.

## Why each piece is there

| Node | Image | What it's for |
|---|---|---|
| `core-rtr`, `dmz-rtr`, `corp-rtr` | `frrouting/frr` | Real routing hops. Scanner -> Finance is 1 hop; scanner -> DMZ is 2 hops. This is what actually breaks ARP-based discovery once you cross a router, forcing your scanner to fall back to ICMP/TCP-based methods - the gap a flat Docker network can't exercise. |
| `dmz-web-modern` | `nginx` (stock) | Clean baseline: TLS 1.2/1.3, strong ciphers. Your scanner should report this one as fine - a false positive here is a bug. |
| `dmz-web-legacy` | custom build, old Debian base | SSLv3/TLS1.0/1.1 + RC4/3DES/weak ciphers - the classic POODLE/BEAST-class findings. |
| `dmz-web-badcert` | `nginx` (stock) + generated cert | Expired, wrong-hostname cert on an otherwise fine TLS config - tests cert-chain checking independent of protocol/cipher checking. |
| `dmz-web-heartbleed` | [`vulnerables/cve-2014-0160`](https://hub.docker.com/r/vulnerables/cve-2014-0160) | A genuinely Heartbleed-vulnerable Apache/OpenSSL build - tests real CVE detection, not just config linting. |
| `fin-app` | `nginx` (stock) | Two TLS ports (443 + 8443) with *different* strength on each - tests that your scanner assesses every port independently instead of reusing one result per host. |
| `fin-db` | `alpine` + iptables `DROP` | Silent host - tests that "no response" is inferred as **filtered**, not down. |
| `eng-git` | `nginx` (stock) | Plain HTTP, port 80, no TLS anywhere - tests that your scanner correctly says "no TLS here" instead of erroring or false-flagging. |
| `eng-fileserver` | `alpine` + real `sshd` + iptables `REJECT` | Port 22 with a real SSH banner (tests your scanner doesn't mistake SSH for TLS), other ports send an instant RST - the direct contrast case against `fin-db`'s silent drop (**closed vs filtered**). |
| `scanner` | `nicolaka/netshoot` | Where your tool runs from - bind-mount your actual scanner into it (see below). Netshoot also ships `nmap`/`arping`/`tcpdump` for cross-checking your scanner's output. |

## Run order

```sh
# 1. one-time: create the host bridges the switches attach to
sudo ./prepare-bridges.sh

# 2. one-time: generate the certs (valid + deliberately expired)
./configs/gen-certs.sh

# 3. one-time: build the legacy-TLS image
./build-images.sh

# 4. bring the whole lab up
sudo containerlab deploy -t topology.clab.yml

# ... run your scanner from inside the `scanner` node, or from your host
# if it can reach the container subnets directly ...

# 5. tear down
sudo containerlab destroy -t topology.clab.yml
```

Before step 4, edit the `scanner` node's `binds:` line in
`topology.clab.yml` to point at wherever your actual scanner script/repo
lives, e.g. `- /home/you/ssl-scanner:/scanner`.

## Verifying it end to end

- `docker exec -it clab-company-tls-lab-scanner ping 10.20.0.11` - basic reachability across two router hops.
- `docker exec -it clab-company-tls-lab-scanner nmap -sn 10.30.20.0/24` vs `10.20.0.0/24` - compare discovery behavior local-subnet vs. routed.
- Cross-check any host's TLS findings with `testssl.sh` or `nmap --script ssl-enum-ciphers` against your scanner's own output before trusting it.

## Honest caveats

- **I haven't run this end to end myself.** My sandbox here has no network access, so I couldn't `docker pull`/`build`/`containerlab deploy` to verify it live - everything above is built from documented containerlab/FRR/nginx behavior and cross-checked for internal consistency (IPs, routes, and interface names all line up), but treat it as a strong first draft to validate on your machine, not a guaranteed zero-iteration solution.
- **The SSLv3 piece is the most fragile part.** Whether `dmz-web-legacy` actually negotiates SSLv3 depends on exactly what OpenSSL build is inside `debian:9`'s nginx package - some distro builds compile SSLv3 out entirely regardless of `ssl_protocols`. TLS 1.0/1.1 are much more reliably reproducible. If SSLv3 doesn't come up, that's the first thing to swap (try an even older base, or compile nginx against an old OpenSSL source directly).
- If any `exec` command fails with a permissions error (particularly the `iptables`/`sshd` ones), add `cap-add: [NET_ADMIN]` (already present on the nodes that need it, but worth checking first) or confirm your containerlab/Docker install grants `linux`-kind nodes enough privilege by default.
- The `-not_before`/`-not_after` flags in `gen-certs.sh` need OpenSSL 3.0+; the script notes a fallback if yours is older.
