# cma-IAM-Role-Analyzer
Analyzes IAM roles in AWS to identify potential privilege escalation paths. Reports on effective permissions and suggests least privilege policies. Uses boto3. - Focused on Scans cloud service configurations (e.g., AWS, GCP) for common security misconfigurations. Identifies potential vulnerabilities like overly permissive IAM roles, exposed storage buckets, and insecure network configurations. Generates reports with remediation recommendations. Supports multiple cloud platforms via their respective SDKs.

## Install
`git clone https://github.com/ShadowStrikeHQ/cma-iam-role-analyzer`

## Usage
`./cma-iam-role-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--role-name`: The name of the IAM role to analyze.
- `--profile`: AWS CLI profile to use for authentication.
- `--region`: AWS region to use. Defaults to configured region or us-east-1.
- `--output-file`: No description provided

## License
Copyright (c) ShadowStrikeHQ
