# Detection rules (Sigma)

Vendor-neutral versions of detections I built and tuned as QRadar correlation rules in a managed SOC.
The originals were written as QRadar rule tests against QIDs and custom properties; here the same logic is
expressed in [Sigma](https://sigmahq.io) so it can be converted to Splunk, Microsoft Sentinel, QRadar AQL and others.
All environment-specific values (account names, group names, domains, device prefixes, country lists) are placeholders.

## Rules

| Rule | Log source | ATT&CK | Notes |
|---|---|---|---|
| Password reset by unexpected account | Windows Security 4724 | T1098 | Excludes machine accounts and approved IAM service accounts |
| Sensitive group membership change | Windows Security 47xx | T1098 | Watch list of groups, all group scopes |
| MFA denied and reported as fraud | Entra ID sign-in logs | T1621 | High-confidence signal of a stolen password |
| Managed device, unexpected country, multiple IPs | Entra ID sign-in logs | T1078.004 | Base rule + `value_count` correlation (15 min) |
| Secure link shared with external recipient | Microsoft 365 audit | T1567.002 | Intended to be joined with a leaver watch list |
| Repository made public | GitHub Enterprise audit | T1567.001 | |
| Repeated QRadar console login failures | QRadar audit | T1110 | Base rule + `event_count` correlation (1 min); watching the SIEM itself |
| Cortex XDR behavioural alert not prevented | Cortex XDR alerts | — | Drops prevented alerts and breach-simulation activity |

## Tuning notes carried over from production

- **Breach-and-attack simulation**: scheduled simulations produced a steady stream of real-looking EDR alerts.
  Excluding the simulation service account, and alerts the agent already prevented, removed that noise without
  hiding real detections.
- **Machine and service accounts**: account-management rules were unusable until computer accounts (`$`) and the
  identity-management tools' own accounts were excluded.
- **Watch lists instead of static lists**: the leaver-related detections worked because the user list was fed
  automatically from the HR system. In Sigma that part belongs in the backend (lookup, watchlist, reference set).

## Validation

Every push runs `sigma check` and converts all rules, including the correlations, to Splunk SPL
(`/workflows/validate.yml`).

```
pip install sigma-cli
sigma plugin install splunk
sigma check rules
sigma convert -t splunk --without-pipeline rules
```

## Field names

- Windows rules use the standard Sigma Windows field names.
- Entra ID rules use the Microsoft Sentinel `SigninLogs` column names; Microsoft 365 rules use the unified audit log
  schema; GitHub rules use the audit-log JSON keys.
- The QRadar audit and Cortex XDR rules use product-native field names and need a processing pipeline for your
  backend's schema.
