# 🔵 dotfiles-Defense

**Detection engineering, version-controlled.** The defensive role layer —
detection engineering and a Dockerized hunt lab.

`sigma` · `sysmon` · `siem` · `docker`

[![showcase](https://img.shields.io/badge/showcase-live-7aa2f7?style=flat-square)](https://dotgibson.github.io/dotfiles-web/) ![blue team](https://img.shields.io/badge/blue--team-7dcfff?style=flat-square)

---

The **defensive (blue) role** of the dotfiles system — the mirror image of
`dotfiles-Kali`. Where Kali carries the offensive engagement layer, this repo
carries the **detection-engineering & investigation** layer: the tooling,
configs, and workspace workflow for hunting, triage, and standing up a small
detection lab.

Like Kali, it stacks **three** layers: Core (vendored) → OS-native (your
existing OS repo) → Defense (role). The defense layer is unique to this repo:
hunt/triage tooling, version-controlled detection content, and a Dockerized lab.

## The one rule that matters

**This is a public repo. Case, evidence, and log data NEVER live in it.** All
investigation data lives under `~/cases/` (outside the repo), exactly like Kali
keeps engagements in `~/engagements/`. The paranoid `.gitignore` is a backstop,
not the primary control. `mkcase` scaffolds a case outside the repo by design.

## Distro-agnostic + Docker (no blue-team distro required)

You do not need Security Onion or a dedicated blue distro — SO is a SOC sensor
appliance, not a dotfiles target. The blue stack is overwhelmingly containers, so
this repo assumes no specific OS: host tools come from your OS-native layer, and
the heavy stack comes up via `docker/` (`siemup` / `siemdown`).

## Loader integration

Adds one stage to the zsh loader, just before local overrides:
`tools → … → os → defense → local`. `defense/defense.zsh` →
`~/.config/zsh/defense.zsh` holds workflow helpers only (`mkcase`, `gocase`,
`note`, `siemup`/`siemdown`), all `HAVE_*`-guarded.

## What the layer ships

- `defense/defense.zsh` — role-stage ergonomics + case workflow
- `defense/templates/` — `case.md` / `hunt.md` seeds
- `detections/` — version-controlled detection content (Sigma, Sysmon, network, SIEM)
- `docker/` — the detection-lab compose stack(s)
- `DEFENSE-METHODOLOGY.md` — the ATT&CK → data-source → detection map
- `install/` — host-tool notes (distro-agnostic)

The attack-paired mirror lives in Kali's `PURPLE-TEAM.md`; the two cross-link.
