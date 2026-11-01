# Enterprise Cloud Security: AWS Least-Privilege IAM & Guardrails Lab

[![Security Audit](https://img.shields.io/badge/Security-LeastPrivilege-success)](https://raosecops.com)
[![Infrastructure](https://img.shields.io/badge/Cloud-IAM%20Guardrails-blue)](https://github.com/Raosecops/cloud-iam-least-privilege-auditor)

An enterprise-grade reference architecture and automated auditing framework designed to eliminate over-permissive IAM roles, enforce permissions boundaries, and mitigate cloud privilege escalation risks.

---

## 🏗️ Architecture Overview

In production cloud environments, developers frequently introduce over-permissive roles (such as wildcard `s3:*` or broad `iam:*` permissions) to avoid deployment friction. This lab demonstrates how to transition from an insecure default to a hardened, zero-trust cloud posture using two core defense layers:

1. **Permissions Boundaries (`prod-engineering-boundary.json`):** Acts as an unyielding security ceiling that restricts the maximum permissions an identity-based policy can ever grant.
2. **Scoping Least-Privilege Roles (`prod-app-least-privilege-role.json`):** Replaces dangerous global wildcards (`*`) with precise resource ARNs and specific API actions.

---

## 📂 Repository Structure

```text
cloud-iam-least-privilege-auditor/
├── policies/
│   ├── over-permissive-backup-role.json       # [FLAWED] Intentionally dangerous role with privilege escalation vectors
│   ├── prod-engineering-boundary.json         # [GUARDRAIL] Enterprise permissions boundary ceiling
│   └── prod-app-least-privilege-role.json     # [SECURE] Pristine least-privilege application role
├── security-audit.py                          # Custom automated Python security linter / CI gate
└── README.md                                  # Comprehensive technical documentation
🚨 Threat Analysis: The Flawed Role

The intentionally flawed role (over-permissive-backup-role.json) contains two primary security vulnerabilities:

    Global Storage Exposure (s3:* on Resource: "*"): Grants full administrative control over all cloud buckets, allowing unintended data exfiltration or bucket deletion.

    Privilege Escalation Vector (iam:CreatePolicyVersion & iam:PassRole): Permits a compromised entity to rewrite policy versions or attach administrative roles to compute instances, achieving full cloud takeover.

🛡️ The Defense: Permissions Boundaries

The permissions boundary policy (prod-engineering-boundary.json) enforces an explicit Deny on IAM tampering and restricts operations strictly to necessary storage and logging actions. Even if a role policy grants AdministratorAccess, the boundary overrides it.
🔍 Running the Automated Security Linter

This repository includes an automated Python security auditing engine (security-audit.py) designed to act as a CI/CD pipeline gate. It statically analyzes policy JSON files for dangerous wildcards and global resource bindings.

Run the audit on your local Linux machine:
python3 security-audit.py
✍️ Author & Professional Brand

Maintained by Rao T — Independent Cybersecurity & Cloud Security Specialist.

Portfolio & Case Studies: raosecops.com
