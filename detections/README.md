# detections/ — version-controlled detection content

Detection as code. **Sigma is the portable source of truth** — author once,
compile down to whatever SIEM the lab runs. Each rule carries its ATT&CK
technique, its data source, and a validation note that names the **exact
`dotfiles-Kali` hacktheplanet fold and `htpx` pair** that reproduces it — so the
purple loop is closed in the file itself: run the attack there, confirm the rule
fires here.

| Dir        | Holds                                                 | Start from (upstream)                          |
| ---------- | ----------------------------------------------------- | ---------------------------------------------- |
| `sigma/`   | portable rules (the source of truth)                  | SigmaHQ                                        |
| `sysmon/`  | Sysmon config baseline(s)                             | Olaf Hartong `sysmon-modular`; SwiftOnSecurity |
| `network/` | Zeek scripts + Suricata rules                         | Zeek pkgs; ET Open ruleset                     |
| `siem/`    | compiled saved-searches, props/transforms, dashboards | compile from `sigma/`                          |

Workflow: write Sigma → convert to your backend → stand up the lab (`siemup`) →
run the matching attack from Kali → confirm it fires → tune → commit rule +
validation note. Real IOC values from cases stay in `~/cases/*/iocs`, never here.

## What ships today (the starter pack)

The first content drop mirrors the **htpx red↔blue corpus**: each rule below
detects a technique that `dotfiles-Kali` can execute on demand, so every one is
purple-validatable out of the box.

### `sigma/` — 22 rules / 24 documents, organized by ATT&CK tactic

**`credential_access/`**

| Rule | Event / source | ATT&CK | Validate with (Kali fold · htpx pair) |
| ---- | -------------- | ------ | ------------------------------------- |
| `kerberoasting_rc4_tgs` | 4769 RC4 (0x17) | T1558.003 | Kerberos · kerberoast-getuserspns |
| `asrep_roast_probing_4771` | 4771 0x18 (correlation) | T1558.004 | Kerberos · asreproast-getnpusers |
| `password_spray_4625` | 4625 (value_count correlation) | T1110.003 | Kerberos/Poisoning · password-spray-kerbrute |
| `dcsync_replication_4662` | 4662 replication right | T1003.006 | DCSync/NTDS · dcsync-secretsdump |
| `gpp_cpassword_sysvol_5145` | 5145 SYSVOL prefs XML | T1552.006 | SMB · gpp-cpassword |
| `ntds_dump_ntdsutil_vss_4688` | proc create (ntdsutil/VSS) | T1003.003 | DCSync/NTDS · ntds-ntdsutil |
| `lsass_handle_access` | Sysmon 10 (LSASS) | T1003.001 | Lateral movement · lsass-dump-lsassy |

**`privilege_escalation/`**

| Rule | Event / source | ATT&CK | Validate with |
| ---- | -------------- | ------ | ------------- |
| `adcs_esc1_san_mismatch_4886` | 4886/4887 cert request | T1649 | AD CS abuse · adcs-esc1-certipy |
| `potato_seimpersonate_4688` | proc create (service→shell) | T1134.001 | Win privesc · potato-seimpersonate |
| `shadow_credentials_keycredentiallink_5136` | 5136 msDS-KeyCredentialLink | T1556 | AD attack paths · shadow-credentials-certipy |
| `rbcd_allowedtoact_5136` | 5136 msDS-AllowedToActOnBehalf… | T1098 | AD attack paths · rbcd-impacket |

**`lateral_movement/`**

| Rule | Event / source | ATT&CK | Validate with |
| ---- | -------------- | ------ | ------------- |
| `wmiexec_wmiprvse_child_4688` | proc create (WmiPrvSE child) | T1047 | Lateral movement · wmiexec-impacket |
| `rdp_hijack_tscon_4688` | proc create (tscon /dest:) | T1563.002 | Lateral movement · rdp-hijack-tscon |
| `service_creation_psexec_7045` | 7045 service install | T1569.002 | Lateral movement · pth-lateral-nxc |

**`persistence/`**

| Rule | Event / source | ATT&CK | Validate with |
| ---- | -------------- | ------ | ------------- |
| `scheduled_task_suspicious_4698` | 4698 task created | T1053.005 | Persistence · schtask-persist |
| `wmi_event_subscription_consumer` | Sysmon 19/20/21 | T1546.003 | Persistence · wmi-subscription |

**`defense_evasion/`**

| Rule | Event / source | ATT&CK | Validate with |
| ---- | -------------- | ------ | ------------- |
| `dcshadow_rogue_dc_4742` | 4742 `GC/` SPN write (+5137/4662) | T1207 | AD attack paths · dcshadow |

**`cloud/`** (multi-cloud — Entra `product: azure`, AWS `product: aws`, GCP `product: gcp`)

| Rule | Event / source | ATT&CK | Validate with |
| ---- | -------------- | ------ | ------------- |
| `entra_illicit_consent_grant` | Entra AuditLogs "Consent to application" | T1528 | M365/Entra · consent-grant |
| `entra_sp_credential_backdoor` | Entra AuditLogs "Add SP credentials" | T1098.001 | M365/Entra · sp-cred-backdoor |
| `aws_iam_access_key_created` | CloudTrail `CreateAccessKey` | T1098.001 | AWS IAM · aws-iam-backdoor-key |
| `aws_login_profile_created` | CloudTrail Create/UpdateLoginProfile | T1098 | AWS IAM · aws-console-login-profile |
| `gcp_service_account_key_created` | GCP audit `CreateServiceAccountKey` | T1098.001 | GCP IAM · gcp-sa-key |

`password_spray` and `asrep_roast_probing` are Sigma **correlation** rules
(a base event + a `value_count` over a window); the rest are single-event
selections. The `cloud/` rules are the first non-Windows logsource here and mirror
the htpx corpus's companion-only Entra pairs.

### `sysmon/` — `sysmonconfig-detection-lab.xml`

A deliberately minimal Sysmon baseline that turns on **exactly** the telemetry
the rules above need (ProcessCreate 1, ProcessAccess 10 on LSASS, Registry 12/13
for autorun/WDigest, PipeEvent 17/18 for coercion pipes, WmiEvent 19/20/21). It
is a lab baseline, not production — graduate to `sysmon-modular` and tune.

### `network/` — wire-side mirrors

- `zeek/kerberoast-rc4.zeek` — notices on an RC4 service ticket for a user SPN
  (the on-wire twin of `kerberoasting_rc4_tgs`).
- `suricata/coercion.rules` — DCERPC interface binds for PetitPotam / PrinterBug /
  DFSCoerce / ShadowCoerce (the wire twin of the 5145 coercion detection).

### `siem/` — deployable backend forms

- **`splunk/savedsearches.conf`** — five single-event rules hand-compiled to Splunk
  saved searches (the worked "compile Sigma → backend" example; real pipelines use
  `sigma convert`).
- **`splunk/correlation_searches.conf`** — the three *absence/join-based* detections
  Sigma can't express — **Golden Ticket** (4769-without-4768), **Silver Ticket**
  (4624-without-4769), and **NTLM relay** (4624 workstation/source mismatch) — as
  deployable Splunk saved searches. This is the promised next step for the
  coverage-gap items below.
- **`sentinel/*.yaml`** — Microsoft Sentinel scheduled-analytics-rule deploy forms
  of the Entra cloud detections (illicit consent grant, SP credential backdoor,
  device-code sign-in). The AWS/GCP cloud rules deploy in their native consoles
  (CloudTrail/Athena, GCP Logging) or via Sentinel's AWS/GCP connectors.

## Coverage gaps (honest notes)

- **Golden Ticket** (4769-without-4768), **Silver Ticket** (Kerberos logon
  without a matching 4769), and **NTLM relay** (4624 workstation mismatch) are all
  *absence*/join-based — they detect the lack of an expected event or a field-to-
  field comparison, which Sigma can't express cleanly. They now ship as **deployable
  Splunk correlation searches** in `siem/splunk/correlation_searches.conf` (and as
  SPL in Kali's `PURPLE-TEAM.md` via their htpx pairs). For Silver Ticket the
  durable control remains PAC validation.
- The **AWS/GCP** Sigma rules are broad event surfaces by design — the backdoor
  invariant (actor ≠ target) is a field-to-field comparison left to backend triage,
  same as the ADCS ESC1 and Entra-consent rules.
- Field names assume the Splunk Windows TA / Sysmon schema; normalize to your CIM
  before relying on them.
