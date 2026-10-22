# Shared backend config — terraform init -backend-config=$(git rev-parse --show-toplevel)/backend.hcl
bucket = "kf-security-tfstate-111111111111-ap-south-1"
region = "ap-south-1"
# State bucket lives in Security Tooling; pipelines assume SecurityPipelineDeploy there for state
# and a provider-level assume_role for the target account.
