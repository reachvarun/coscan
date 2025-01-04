# coscan
Scan for issues across AWS, Azure, & Github.

## Feature Set
### Current Features:
- **AWS Integration**:
  - List and analyze EC2 and Lightsail instances.
  - Check for unpatched CVEs using SSM-managed patch compliance or AMI comparisons.
  - Supports secure configuration using IAM roles and access keys.

- **GitHub Integration**:
  - Retrieve code scanning alerts for repositories.
  - Analyze security vulnerabilities and configuration issues.
  - Leverages GitHub Personal Access Tokens (PAT) with fine-grained permissions.

- **Azure Integration**:
  - Authenticate with Microsoft Entra (Azure AD) using OAuth 2.0.
  - Access SharePoint sites and list resources securely via Microsoft Graph API.
  - Supports non-Admin user-context delegated & application-level permissions.

### Planned Features:
- **Cross-Cloud Analysis**:
  - Compare configurations across AWS, Azure, GCP, and GitHub for consistency.
  - Generate unified security reports for multi-cloud deployments.
  - Implement per-handler throttling for 3'rd party API's.

- **Agentless Vulnerability Scanning**:
  - Expand scanning capabilities for unmanaged resources without requiring agents.

- **Custom Reporting**:
  - Export detailed security findings in CSV or JSON format.
  - Integrate with third-party monitoring tools like Splunk or Datadog.

## Configuration Guide

This application integrates with AWS, GitHub, and Azure for security scanning. Follow these steps to configure each provider.

### 1. AWS
#### Create an IAM User:
- Permissions: `lightsail:GetInstances`, `ec2:DescribeInstances`, `sts:GetCallerIdentity`.
- Generate access keys.

#### Set Environment Variables:
```bash
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_REGION="your-region"  # e.g., us-east-1
```

#### Test:
```bash
aws sts get-caller-identity
```

### 2. GitHub
#### Create a Personal Access Token (PAT):
- Scopes: `repo`, `admin:repo_hook`, `security_events`.

#### Set Environment Variable:
```bash
export GITHUB_USER="your-github-user-handle"
export GITHUB_TOKEN="your-personal-access-token"
```

#### Test:
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" https://api.github.com/user/$GITHUB_USER
```

### 3. Azure
#### Register an App in Azure AD:
- Redirect URI: `http://localhost:8080/azurecallback`.
- API Permissions: `Sites.Read.All`.
- Generate a client secret.

#### Set Environment Variables:
```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_USER_SECRET="your-client-secret-Value"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_REDIRECT_URI="http://localhost:8080/azurecallback"
```

#### Test:

### Testing All Integrations
1. **AWS**:
   ```bash
   curl "http://localhost:8080/scanvm?scanPatches=true&filter=critical&amiFilter=ubuntu/images/hvm-ssd/ubuntu-*"
   ```
2. **GitHub**:
   ```bash
   curl "http://localhost:8080/scanlambdas?repo=coscan"
   ```
3. **Azure**:
   ```bash
   curl http://localhost:8080/azurelogin
   ```
4. **SharePoint**:

   Test the `/scansharepoint` endpoint with a valid `siteID` in a browser e.g.
   ```
   http://localhost:8080/scansharepoint?siteID=foobar.sharepoint.com
   ```
   Expected Response:
   ```
   {
      "displayName": "foobar",
      "webUrl": "https://foobar.sharepoint.com",
      "id": "foobar.sharepoint.com,********-****-****-****-************,********-****-****-****-************",
      "createdDateTime": "2020-01-27T15:47:38.707Z",
      "lastModifiedDateTime": "2025-01-04T00:06:06Z"
   }
   ```
