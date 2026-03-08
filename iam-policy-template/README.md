# IAM Policy Templates for Claude Code

AWS IAM policy templates to prevent AI agents from accidentally destroying infrastructure (see: [DataTalks.Club incident](https://note.com/joho_no_todai/n/n9447490ced5a)).

## Policies

### `claude-code-readonly.json` — Read-Only (Recommended starting point)

- **Allow**: Describe/Get/List for EC2, RDS, ECS, S3, Lambda, CloudFormation, CloudWatch, Logs, IAM (read), Route53, SSM
- **Deny**: All delete/terminate/create operations, IAM escalation, account operations
- **Use case**: Investigation, debugging, monitoring, architecture review

### `claude-code-dev-deploy.json` — Dev/Staging Deploy

- **Allow**: Full access to most services (region-locked to ap-northeast-1)
- **Deny**: Destructive operations on `prod`-tagged resources, IAM escalation, account operations
- **Use case**: Development and staging deployment, requires resources tagged with `Environment: production` for protection

## Usage

```bash
# Create IAM policy
aws iam create-policy \
  --policy-name claude-code-readonly \
  --policy-document file://claude-code-readonly.json

# Attach to IAM user/role
aws iam attach-user-policy \
  --user-name claude-code-agent \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/claude-code-readonly
```

## Defense in Depth

These IAM policies are one layer of a 3-layer defense:

| Layer | What | How |
|-------|------|-----|
| **1. Hook guard** | Block destructive AWS CLI commands before execution | `validate-bash.sh` PreToolUse hook |
| **2. IAM policy** | AWS-side permission boundary — cannot be bypassed by the agent | These templates |
| **3. Environment separation** | Production credentials never given to Claude Code | CI/CD-only prod deploy |

## Important Notes

- **Tag your production resources**: The dev-deploy policy relies on `Environment: production` tags
- **Region lock**: Modify `aws:RequestedRegion` to match your regions
- **SCP recommended**: For organization-level guardrails, add an SCP that denies `Delete*`/`Terminate*` on production OUs
- **Rotate credentials**: Use temporary credentials (STS AssumeRole) instead of long-lived access keys
