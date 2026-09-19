 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_| CLI - v5.42.0
|_|

Date: 2026-09-19 09:30:34


│ You're getting a snapshot 📸. Prowler Cloud gives you the full picture:
│
│ ✓ Send your findings - directly from the Prowler CLI to Prowler Cloud.
│ ✓ Continuous Security Monitoring - custom scheduling and scan configuration with history, trends and alerts.
│ ✓ Triage - review findings, flag false positives and track accepted risk with your team.
│ ✓ Lighthouse AI + MCP - autonomous triage, custom dashboards, prioritization with prevention and remediation.
│ ✓ Alerts - get notified when anything you want is happening.
│ ✓ Live Compliance - dashboards for 50+ frameworks, always up to date.
│ ✓ Remediation - complete guided remediation including Autonomous remediation with Lighthouse AI.
│ ✓ Attack Path Visualization - see how attackers chain risks to reach your crown jewels.
│ ✓ Bulk Provisioning - add your entire AWS Organization in seconds.
│ ✓ Integrations - Anything with our MCP + Jira, Slack, AWS Security Hub, Amazon S3, SSO and RBAC.
│
│ Start free at 👉 cloud.prowler.com

-> Using the AWS credentials below:
  · AWS-CLI Profile: default
  · AWS Regions: all except me-central-1, me-south-1
  · AWS Account: 858573892697
  · User Id: AIDA4PZX55RM6XDFCM6CC
  · Caller Identity ARN: arn:aws:iam::858573892697:user/QLabs

-> Using the following configuration:
  · Config File: C:\Users\Eddie\OneDrive - Default Directory\Documents\Expadox Labs\Project Folder\Breach-Zone 01\breach-zone\posture-management\.venv\Lib\site-packages\prowler\config/config.yaml
  · Mutelist File: C:\Users\Eddie\OneDrive - Default Directory\Documents\Expadox Labs\Project Folder\Breach-Zone 01\breach-zone\posture-management\.venv\Lib\site-packages\prowler\config/aws_mutelist.yaml
  · Scanning unused services and resources: False

Executing 648 checks, please wait...
-> Scan completed! |▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉| 648/648 [100%] in 22:54.6 

Overview Results:
╭─────────────────────┬─────────────────────┬────────────────╮
│ 47.71% (490) Failed │ 51.41% (528) Passed │ 0.0% (0) Muted │
╰─────────────────────┴─────────────────────┴────────────────╯

Account 858573892697 Scan Results (severity columns are for fails only):
╭────────────┬───────────────────┬───────────┬────────────┬────────┬──────────┬───────┬─────────╮
│ Provider   │ Service           │ Status    │   Critical │   High │   Medium │   Low │   Muted │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ accessanalyzer    │ FAIL (16) │          0 │      0 │        0 │    16 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ account           │ FAIL (1)  │          0 │      0 │        1 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ awslambda         │ FAIL (15) │          0 │      0 │        5 │    10 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ backup            │ FAIL (1)  │          0 │      0 │        0 │     1 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ bedrock           │ FAIL (47) │          0 │      0 │       34 │    13 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ cloudformation    │ FAIL (3)  │          0 │      0 │        3 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ cloudtrail        │ FAIL (7)  │          0 │      0 │        4 │     3 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ cloudwatch        │ FAIL (21) │          0 │      0 │       21 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ config            │ FAIL (17) │          0 │      1 │       16 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ drs               │ FAIL (17) │          0 │      0 │       17 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ ec2               │ FAIL (48) │         19 │      8 │       15 │     6 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ emr               │ PASS (17) │          0 │      0 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ eventbridge       │ PASS (34) │          0 │      0 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ guardduty         │ FAIL (34) │          0 │     34 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ iam               │ FAIL (25) │          2 │     13 │        6 │     4 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ inspector2        │ FAIL (17) │          0 │      0 │       17 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ kms               │ PASS (0)  │          0 │      0 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ macie             │ FAIL (1)  │          0 │      0 │        1 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ networkfirewall   │ FAIL (1)  │          0 │      0 │        1 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ organizations     │ FAIL (4)  │          0 │      1 │        2 │     1 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ rds               │ FAIL (64) │          1 │      2 │       41 │    20 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ resourceexplorer2 │ PASS (1)  │          0 │      0 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ s3                │ FAIL (54) │          0 │      3 │       29 │    22 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ sagemaker         │ FAIL (51) │          0 │      0 │        0 │    51 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ securityhub       │ FAIL (34) │          0 │     34 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ sns               │ FAIL (2)  │          0 │      2 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ ssm               │ FAIL (1)  │          0 │      1 │        0 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ ssmincidents      │ FAIL (1)  │          0 │      0 │        1 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ trustedadvisor    │ FAIL (1)  │          0 │      0 │        0 │     1 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ vpc               │ FAIL (7)  │          0 │      3 │        4 │     0 │       0 │
├────────────┼───────────────────┼───────────┼────────────┼────────┼──────────┼───────┼─────────┤
│ aws        │ wellarchitected   │ PASS (1)  │          0 │      0 │        0 │     0 │       0 │
╰────────────┴───────────────────┴───────────┴────────────┴────────┴──────────┴───────┴─────────╯
* You only see here those services that contains resources.

Detailed results are in:
 - JSON-OCSF: results//day0-cspm.ocsf.json

Compliance Status of ASD_ESSENTIAL_EIGHT_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 38.89% (84) FAIL │ 61.11% (132) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of AWS_ACCOUNT_SECURITY_ONBOARDING_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 56.52% (104) FAIL │ 43.48% (80) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of AWS_AUDIT_MANAGER_CONTROL_TOWER_GUARDRAILS_AWS Framework:
╭─────────────────┬─────────────────┬────────────────╮
│ 35.9% (14) FAIL │ 64.1% (25) PASS │ 0.0% (0) MUTED │
╰─────────────────┴─────────────────┴────────────────╯

Compliance Status of AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 53.13% (178) FAIL │ 46.87% (157) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of AWS_FOUNDATIONAL_TECHNICAL_REVIEW_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 41.33% (93) FAIL │ 58.67% (132) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of AWS_WELL_ARCHITECTED_FRAMEWORK_RELIABILITY_PILLAR_AWS Framework:
╭──────────────────┬────────────────┬────────────────╮
│ 92.86% (13) FAIL │ 7.14% (1) PASS │ 0.0% (0) MUTED │
╰──────────────────┴────────────────┴────────────────╯

Compliance Status of AWS_WELL_ARCHITECTED_FRAMEWORK_SECURITY_PILLAR_AWS Framework:
╭──────────────────┬──────────────────┬────────────────╮
│ 36.1% (161) FAIL │ 63.9% (285) PASS │ 0.0% (0) MUTED │
╰──────────────────┴──────────────────┴────────────────╯

Compliance Status of C5_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 40.74% (242) FAIL │ 59.26% (352) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CCC_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 41.18% (196) FAIL │ 58.82% (280) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CIS_1.4_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 47.92% (92) FAIL │ 52.08% (100) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of CIS_1.5_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 52.61% (111) FAIL │ 47.39% (100) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CIS_2.0_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 54.07% (113) FAIL │ 45.93% (96) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of CIS_3.0_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 54.68% (111) FAIL │ 45.32% (92) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of CIS_4.0_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 54.85% (113) FAIL │ 45.15% (93) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of CIS_5.0_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 54.85% (113) FAIL │ 45.15% (93) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of CIS_6.0_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 54.85% (113) FAIL │ 45.15% (93) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of CIS_7.0_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 48.28% (112) FAIL │ 51.72% (120) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CIS_CONTROLS_8.1 Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 44.04% (314) FAIL │ 55.96% (399) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CISA_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 39.57% (91) FAIL │ 60.43% (139) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of CMMC_2.0 Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 45.86% (122) FAIL │ 54.14% (144) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of CSA_CCM_4.0 Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 50.94% (217) FAIL │ 49.06% (209) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of DORA_2022_2554 Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 43.38% (239) FAIL │ 56.62% (312) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Estado de Cumplimiento de ENS_RD2022_AWS:
╭────────────────────────┬─────────────────────┬────────────────╮
│ 36.98% (125) NO CUMPLE │ 63.02% (213) CUMPLE │ 0.0% (0) MUTED │
╰────────────────────────┴─────────────────────┴────────────────╯

Compliance Status of FEDRAMP_LOW_REVISION_4_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 43.07% (87) FAIL │ 56.93% (115) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of FEDRAMP_MODERATE_REVISION_4_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 40.18% (88) FAIL │ 59.82% (131) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of FFIEC_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 37.91% (80) FAIL │ 62.09% (131) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of GDPR_AWS Framework:
╭──────────────────┬──────────────────┬────────────────╮
│ 38.89% (56) FAIL │ 61.11% (88) PASS │ 0.0% (0) MUTED │
╰──────────────────┴──────────────────┴────────────────╯

Compliance Status of GXP_21_CFR_PART_11_AWS Framework:
╭─────────────────┬──────────────────┬────────────────╮
│ 42.0% (84) FAIL │ 58.0% (116) PASS │ 0.0% (0) MUTED │
╰─────────────────┴──────────────────┴────────────────╯

Compliance Status of GXP_EU_ANNEX_11_AWS Framework:
╭──────────────────┬──────────────────┬────────────────╮
│ 67.95% (53) FAIL │ 32.05% (25) PASS │ 0.0% (0) MUTED │
╰──────────────────┴──────────────────┴────────────────╯

Compliance Status of HIPAA_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 44.68% (105) FAIL │ 55.32% (130) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of ISO27001_2013_AWS Framework:
╭─────────────────┬─────────────────┬────────────────╮
│ 50.0% (41) FAIL │ 50.0% (41) PASS │ 0.0% (0) MUTED │
╰─────────────────┴─────────────────┴────────────────╯

Compliance Status of ISO27001_2022_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 45.31% (222) FAIL │ 54.69% (268) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of KISA_ISMS_P_2023_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 46.53% (395) FAIL │ 53.47% (454) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of KISA_ISMS_P_2023_KOREAN_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 46.53% (395) FAIL │ 53.47% (454) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of MITRE_ATTACK_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 45.29% (178) FAIL │ 54.71% (215) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of NIS2_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 55.16% (139) FAIL │ 44.84% (113) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of NIST_800_171_REVISION_2_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 40.81% (91) FAIL │ 59.19% (132) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of NIST_800_53_REVISION_4_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 40.64% (89) FAIL │ 59.36% (130) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of NIST_800_53_REVISION_5_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 40.72% (90) FAIL │ 59.28% (131) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of NIST_CSF_1.1_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 47.26% (112) FAIL │ 52.74% (125) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of NIST_CSF_2.0_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 40.37% (199) FAIL │ 59.63% (294) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of PCI_3.2.1_AWS Framework:
╭───────────────────┬──────────────────┬────────────────╮
│ 64.53% (111) FAIL │ 35.47% (61) PASS │ 0.0% (0) MUTED │
╰───────────────────┴──────────────────┴────────────────╯

Compliance Status of PCI_4.0_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 56.73% (139) FAIL │ 43.27% (106) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of PROWLER_THREATSCORE_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 40.91% (126) FAIL │ 59.09% (182) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of RBI_CYBER_SECURITY_FRAMEWORK_AWS Framework:
╭──────────────────┬───────────────────┬────────────────╮
│ 36.57% (64) FAIL │ 63.43% (111) PASS │ 0.0% (0) MUTED │
╰──────────────────┴───────────────────┴────────────────╯

Compliance Status of SECNUMCLOUD_3.2_AWS Framework:
╭───────────────────┬───────────────────┬────────────────╮
│ 47.16% (183) FAIL │ 52.84% (205) PASS │ 0.0% (0) MUTED │
╰───────────────────┴───────────────────┴────────────────╯

Compliance Status of SOC2_AWS Framework:
╭──────────────────┬──────────────────┬────────────────╮
│ 50.0% (166) FAIL │ 50.0% (166) PASS │ 0.0% (0) MUTED │
╰──────────────────┴──────────────────┴────────────────╯

Detailed compliance results are in results//compliance/


│ You're getting a snapshot 📸. Prowler Cloud gives you the full picture:
│
│ ✓ Send your findings - directly from the Prowler CLI to Prowler Cloud.
│ ✓ Continuous Security Monitoring - custom scheduling and scan configuration with history, trends and alerts.
│ ✓ Triage - review findings, flag false positives and track accepted risk with your team.
│ ✓ Lighthouse AI + MCP - autonomous triage, custom dashboards, prioritization with prevention and remediation.
│ ✓ Alerts - get notified when anything you want is happening.
│ ✓ Live Compliance - dashboards for 50+ frameworks, always up to date.
│ ✓ Remediation - complete guided remediation including Autonomous remediation with Lighthouse AI.
│ ✓ Attack Path Visualization - see how attackers chain risks to reach your crown jewels.
│ ✓ Bulk Provisioning - add your entire AWS Organization in seconds.
│ ✓ Integrations - Anything with our MCP + Jira, Slack, AWS Security Hub, Amazon S3, SSO and RBAC.
│
│ Start free at 👉 cloud.prowler.com
