# Secret Key Management

## Overview

This document explains how CharlottesWeb manages sensitive credentials securely. **Never store secrets in code or configuration files.**

## Security Hierarchy

### Production (Recommended)
**Use environment variables ONLY** - no files involved
- Hosting platform manages variables (Heroku, AWS Lambda, GCP Cloud Run, etc.)
- Docker secrets for container environments
- Kubernetes secrets for orchestrated deployments
- No files to commit or leak

### Staging / Development
**Use environment variables + optional encryption**
- Load from `.env` file (excluded from git via `.gitignore`)
- File encryption if keys must be at-rest (optional, for additional safety)
- Regenerate frequently

### NEVER
- Commit `.env` files to git
- Hardcode secrets in Python files
- Store plaintext secrets in committed configuration files
- Use default/weak secrets in production

## How to Set Up

### 1. Generate Secrets

```bash
# Generate JWT secret (save to environment variable)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate API key for external use
python -c "from src.security import generate_api_key; print(generate_api_key())"

# Example output:
# JR0S_rNg4vZ2bK8mP9qX5wY1L3c6D7e... (for JWT)
# ck_live_51H2Y3Z4x5w6v7u8t9s0r1q2p3o4... (for API key)
```

### 2. Method 1: Environment Variables (Recommended)

```bash
# Set in your shell environment or hosting platform
export SECRET_KEY="your-generated-secret-key-here"
export VALID_API_KEYS="key1,key2,key3"
export DATABASE_URL="postgresql://user:pass@host/dbname"

# Then run the app
python -m src.main
```

### 3. Method 2: .env File (Development Only)

Create `.env` file (git automatically ignores it):

```env
# Application
APP_ENV=development
DEBUG=true

# Security
SECRET_KEY=your-generated-secret-key-here
VALID_API_KEYS=key1,key2,key3
API_KEY_REQUIRED=false

# Database
DATABASE_URL=sqlite:////full/path/to/charlottesweb.db

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

### 4. Method 3: Encrypted .env File (Additional Protection)

For extra security of local `.env` files:

```python
# Install cryptography
pip install cryptography

# Encrypt your .env file
from src.encryption import encrypt_env_file
encrypt_env_file('.env', '.env.encrypted', password='your-master-password')

# Load encrypted file
from src.encryption import load_encrypted_env
load_encrypted_env('.env.encrypted', password='your-master-password')
```

## Environment Variables Reference

| Variable | Purpose | Example | Production |
|----------|---------|---------|-----------|
| `APP_ENV` | Environment type | `production` | **Required** |
| `SECRET_KEY` | JWT signing secret | SHA256 hash | **Required** (32+ char) |
| `VALID_API_KEYS` | Comma-separated API keys | `key1,key2` | **Required** |
| `API_KEY_REQUIRED` | Enforce API key auth | `true` | `true` |
| `DATABASE_URL` | Database connection | `postgresql://...` | **Required** |
| `CORS_ORIGINS` | Allowed client origins | `https://app.example.com` | **Whitelist only** |
| `DEBUG` | Debug mode | `false` | `false` |

## Hosting Platform Examples

### AWS Lambda / API Gateway
Use AWS Secrets Manager:
```python
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='charlottesweb/prod')
```

### Heroku
```bash
heroku config:set SECRET_KEY="your-secret-key"
heroku config:set VALID_API_KEYS="key1,key2"
```

### Docker / Docker Compose
```yaml
services:
app:
environment:
SECRET_KEY: ${SECRET_KEY}
VALID_API_KEYS: ${VALID_API_KEYS}
DATABASE_URL: ${DATABASE_URL}
```

### Cloudflare Pages / Workers
```toml
# wrangler.toml
[env.production]
vars = { APP_ENV = "production", DEBUG = "false" }
secrets = ["SECRET_KEY", "VALID_API_KEYS"]
```

### Google Cloud Run
```bash
gcloud run deploy charlottesweb \
--set-env-vars APP_ENV=production,DEBUG=false \
--set-secrets SECRET_KEY=secret-manager-secret-version,VALID_API_KEYS=secret-manager-secret-version
```

## Rotation & Revocation

### When to Rotate Secrets
- Quarterly (policy)
- After suspected compromise
- After employee departure
- After code disclosure
- When logs show suspicious activity

### How to Rotate
1. Generate new secret
2. Add to environment (keep old one temporarily)
3. Update code to accept both (if token-based)
4. Wait 24 hours for in-flight requests to complete
5. Remove old secret from environment
6. Monitor logs for failures

## Auditing & Monitoring

### What to Log
- API key creation/deletion (with owner)
- Authentication failures (rate limit if >5 failures)
- Key rotation events
- Unauthorized access attempts

### What NOT to Log
- Secret key values (ever)
- API keys (ever)
- Database passwords (ever)
- Session tokens (only hash if necessary)

## Compliance Checklist

- [ ] No `.env` file in git (check `.gitignore`)
- [ ] All secrets in environment variables or encrypted
- [ ] `DEBUG=false` in production
- [ ] `API_KEY_REQUIRED=true` in production
- [ ] `CORS_ORIGINS` explicitly whitelisted (no `*`)
- [ ] Database uses strong password
- [ ] Secret rotation policy documented
- [ ] Audit logging enabled
- [ ] No hardcoded secrets in Python files
- [ ] `.env.example` exists showing required variables (no values)

## File Encryption (Optional)

For development environments where a `.env` file must exist, CharlottesWeb provides optional encryption:

```python
# src/encryption.py - helpers for encrypted key storage
encrypt_env_file('.env', '.env.encrypted', master_password='secure-password')
load_encrypted_env('.env.encrypted', master_password='secure-password')
```

This uses Fernet (symmetric encryption) from `cryptography` library.

## See Also

- [OWASP: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [12 Factor App: Config](https://12factor.net/config)
- [Python-dotenv Documentation](https://saurabh-kumar.com/python-dotenv/)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
