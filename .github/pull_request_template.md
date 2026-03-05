# Pull Request

## Description
<!-- Brief summary of what this PR accomplishes -->


## Type of Change
<!-- Mark the relevant option with an "x" -->
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Security improvement
- [ ] Documentation update
- [ ] Dependency update

---

## Security Checklist
<!-- REQUIRED for all PRs touching security code -->

### Authentication & Authorization
- [ ] No hardcoded credentials, API keys, or secrets in code
- [ ] API key validation added/updated if needed
- [ ] JWT token handling verified if changed
- [ ] Password hashing used (never plain text)

### Security Headers & CORS
- [ ] CSP policy reviewed (especially for /docs endpoints)
- [ ] CORS origins validated for production
- [ ] X-Frame-Options, X-Content-Type-Options, other headers checked

### Data & Encryption
- [ ] No PHI (Protected Health Information) logged or exposed
- [ ] Database queries use parameterized statements (SQLAlchemy ORM)
- [ ] TLS/HTTPS enforced for external API calls
- [ ] Sensitive data fields marked in audit logs as MASKED

### Audit Logging
- [ ] Audit logging added for new data operations (CREATE, UPDATE, DELETE)
- [ ] Audit action enum updated if new action type
- [ ] User ID and API key (masked) captured correctly
- [ ] No sensitive data (passwords, PII) in audit log details

### Rate Limiting & DoS
- [ ] Rate limiter applied to new endpoints
- [ ] Rate limit values appropriate for endpoint
- [ ] No bypass potential (e.g., through headers)

### Input Validation
- [ ] Pydantic schemas validate all user inputs
- [ ] File uploads (if any) validated for type and size
- [ ] SQL injection prevention verified (using ORM)

### Error Handling
- [ ] Sensitive error details not exposed to clients
- [ ] 500 errors logged for debugging (not visible to user)
- [ ] HTTPException messages generic (no stack traces)

### Testing
- [ ] New security features have test coverage
- [ ] Security edge cases tested (rate limit bypass, auth bypass, etc.)
- [ ] Tests pass locally: `pytest` or equivalent

### Type Safety
- [ ] Pylance errors checked: `get_errors` on modified files
- [ ] No new type: ignore comments without explanation
- [ ] Type hints added to new functions when possible

### Dependencies
- [ ] No new dependencies without security review
- [ ] Dependencies scanned: `pip-audit -r requirements.txt` (zero vulnerabilities required)
- [ ] requirements.txt pinned to specific versions

---

## Code Quality Checklist

- [ ] Code follows project style (PEP 8 for Python)
- [ ] Comments added for non-obvious logic
- [ ] Dead code removed
- [ ] Imports organized and unused imports removed
- [ ] No debug print() statements left in code
- [ ] Database migrations (if any) are reversible

---

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] E2E scenarios tested (if applicable)
- [ ] Manual testing completed locally

### Test Results
```
[Paste test output or link to CI results]
```

---

## Documentation

- [ ] README.md updated (if needed)
- [ ] Docstrings added to new functions/classes
- [ ] SECURITY.md updated (if security-related)
- [ ] SECURITY_FEATURES.md updated (if feature impact)
- [ ] API documentation updated (if endpoints changed)

---

## Migration/Deployment Notes

<!-- If this PR requires deployment steps, mention them here -->

- [ ] Database migrations required (and documented)
- [ ] Environment variables added (documented in .env.example)
- [ ] Breaking changes documented
- [ ] Backward compatibility verified

---

## Reviewer Notes

<!-- Anything specific you want reviewers to focus on? -->


---

## Related Issues

<!-- Link to related issues: Closes #123, Relates to #456 -->

Closes #
Relates to #

---

## Screenshots (if applicable)

<!-- For UI changes or important features -->


---

**Before submitting**:
- [ ] Ran type checker: `python3 -m pylance --version && ...`
- [ ] Checked for secrets: `grep -r "password\|api_key\|secret" src/`
- [ ] Verified audit logs captured: search for `log_audit_event` calls
- [ ] All tests pass locally
