## ISCP-SOC-Submission

ISCP CTF - SOC Challenge Submission

This project provides a streamlined solution to detect and mask Personally Identifiable Information (PII) within datasets. It automatically scans for sensitive data types—such as Aadhaar numbers, PAN, phone numbers, email addresses, credit card details, and more—and produces sanitized outputs for safer storage, processing, and sharing.

## Features:

PII Detection: Identifies phone numbers, Aadhaar, passport numbers, UPI IDs, email addresses, IPs, and physical addresses.

Data Masking: Partially hides sensitive values (e.g., phone 98XXXXXX21, names like AXXX).

Context Awareness: Uses column names and regex patterns to reduce false positives (e.g., avoids masking values like order_id).

CSV and JSON Support: Reads both CSV and JSON formats, including slightly malformed JSON within CSV fields.

Combination Logic: Flags entries as PII if multiple weak identifiers are found together.

Output Generation: Produces a new CSV with redacted JSON content and an is_pii flag.

Modular and Extensible: Designed to easily incorporate new patterns and detection rules.

## Deployment Strategy:

The recommended deployment method is as a Sidecar container alongside existing application services.

Why Sidecar Deployment?

Scalable: Each application service gets its own PII processor without requiring code changes. New services can simply adopt the same sidecar approach.

Low Latency: Since the sidecar runs within the same pod, data processing is quick and avoids additional network overhead.

Cost-Effective: Eliminates the need for a centralized, heavyweight gateway. Resources are used only where PII scanning is needed.

Flexible Integration: Can be used with REST APIs, log streams, or file uploads by routing data to the sidecar before it leaves the pod.

Alternative Deployments:

DaemonSet: Ideal for cluster-wide log or audit monitoring, rather than per-service redaction.

API Gateway Plugin: Suitable for organizations enforcing PII policies at the ingress or egress layer.

Browser Extension: A potential client-side option for masking data before it leaves the user's device.

## Usage:

git clone https://github.com/aryan-2026/ISCP-SOC-Submission.git

cd ISCP-SOC-Submission

python3 detector_aryanpro00715.py iscp_pii_dataset.csv

## Output: 

redacted_output_aryanpro00715.csv

## Supported PII Types:

Phone Numbers, Email Addresses, Aadhaar Numbers (12-digit), PAN Numbers (e.g., ADCJBA0099A), Credit/Debit Card Numbers, Physical Addresses, Bank Account Numbers, Full Names
