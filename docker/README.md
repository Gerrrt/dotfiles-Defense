# docker/ — the detection lab

The heavy blue stack runs in containers, not on the host — that's why this repo
is distro-agnostic. `siemup` / `siemdown` (in `defense/defense.zsh`) bring a
stack up/down; pick it with `DEFENSE_STACK` (default `detection-lab`).

Why containers and not Security Onion: SO bundles Zeek + Suricata + Elastic +
Wazuh + Velociraptor behind an appliance — great as a turnkey sensor, wrong
shape for a version-controlled config repo. Here you run the same components as
discrete compose stacks, adding them as you need them.

Rules: no data volumes in git (`docker/**/data/` and `.env` are gitignored); pin
image tags (no bare `:latest`); keep secrets in a local `.env`. The shipped
`detection-lab.compose.yml` is a deliberately minimal runnable stub — swap its
body for the real stack you want.
