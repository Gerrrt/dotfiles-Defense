# install/ — host tools (distro-agnostic)

No `packages.txt` here — the OS-native layer you run owns package installation,
and the heavy stack runs in `docker/`. This is the host-tool shopping list so
`bootstrap.sh` can report what's missing without assuming a package manager.

Tools probed: `docker` + compose, `jq`, `tshark`/`tcpdump`, `zeek`, `suricata`,
`chainsaw`, `hayabusa`, `sigma-cli`, `yara`, `velociraptor`, `volatility3`,
`plaso` (`log2timeline`). `bootstrap.sh` probes for these and prints which are
absent — it does not install them. If you later pin this repo to one base OS,
this file becomes that distro's real `packages.txt`.
