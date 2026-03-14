# Python Antipatterns Guide
**Practical code review and engineering reference**

---

## 1. Bare Except Clause

**What:** Catching all exceptions without specifying type
```python
# BAD
try:
    risky_operation()
except:  # NEVER DO THIS
    pass
```

**Why Bad:**
- Catches SystemExit, KeyboardInterrupt (Ctrl+C won't work!)
- Hides unexpected bugs
- Makes debugging impossible
- Violates "explicit is better than implicit"

**Fix:**
```python
# GOOD
try:
    risky_operation()
except ValueError as e:
    logger.error(f"Invalid value: {e}")
except KeyError as e:
    logger.error(f"Missing key: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    raise  # Re-raise if truly unexpected
```

**Key Review Notes:**
- "Always catch specific exceptions you expect"
- "At minimum, use `except Exception` to allow system signals"
- "Bare except is only acceptable for logging-then-reraise patterns"
- "Python's exception hierarchy: BaseException → SystemExit/KeyboardInterrupt/Exception"

---

## 2. Overly Broad Exception Catching

**What:** Catching `Exception` when you should catch specific types

**Context Matters:**
```python
# BAD - In business logic
def process_user_data(data):
    try:
        return calculate_score(data)
    except Exception:  # Too broad!
        return 0

# OK - At API boundaries
@app.post("/users")
def create_user(data):
    try:
        user = service.create(data)
        return {"id": user.id}
    except Exception as e:
        logger.error(f"Failed: {e}", exc_info=True)
        raise HTTPException(500, "Server error")
```

**Fix for Business Logic:**
```python
# GOOD - Specific exceptions
def process_user_data(data):
    try:
        return calculate_score(data)
    except ValueError as e:
        logger.warning(f"Invalid data: {e}")
        return 0
    except ZeroDivisionError:
        return 0
```

**Key Review Notes:**
- "Catch specific exceptions in business logic"
- "Broad catching OK at API/system boundaries for converting to responses"
- "Always log full traceback with `exc_info=True`"
- "Ask yourself: what specific errors do I expect here?"

---

## 3. God Function / Long Method

**What:** One function doing too much (>50-100 lines)

**Signs:**
- Function over 50 lines
- Multiple levels of nesting
- Many responsibilities
- Hard to name descriptively
- Difficult to test

**Example:**
```python
# BAD - 600 line function!
def seed_database():
    # Create tables...
    # Seed organizations...
    # Seed controls...
    # Seed assessments...
    # Seed findings...
    # Seed evidence...
    # 590 more lines...
```

**Fix: Extract Functions:**
```python
# GOOD
def seed_database():
    """Main seeding orchestration."""
    db = get_session()
    _seed_organizations(db)
    _seed_controls(db)
    _seed_assessments(db)
    _seed_findings(db)
    _seed_evidence(db)
    db.close()

def _seed_organizations(db: Session) -> None:
    """Create sample organizations."""
    # 20 focused lines

def _seed_controls(db: Session) -> None:
    """Create HIPAA controls."""
    # 30 focused lines
```

**Key Review Notes:**
- "Functions should do ONE thing well (Single Responsibility Principle)"
- "Rule of thumb: functions over 50 lines are code smells"
- "Extract helpers with descriptive names"
- "Easier to test, maintain, and understand"
- "Reduces cognitive load for readers"

---

## 4. Mutable Default Arguments

**What:** Using mutable objects (list, dict, set) as default parameters

**The Bug:**
```python
# BAD - Shared state bug!
def add_item(item, items=[]):
    items.append(item)
    return items

# This breaks:
print(add_item("a"))  # ['a']
print(add_item("b"))  # ['a', 'b']  <- WTF?!
print(add_item("c"))  # ['a', 'b', 'c']
```

**Why:** Default arguments evaluated ONCE at function definition time, not each call.

**Fix:**
```python
# GOOD - Use None sentinel
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items

# Or even better - don't mutate!
def add_item(item, items=None):
    items = items or []
    return items + [item]
```

**NOT This Antipattern:**
```python
# This is FINE - not a default argument
def process():
    results = []  # New list each call
    for x in data:
        results.append(x)
    return results
```

**Using `or []` Pattern:**
```python
# GOOD - Defensive against None from database
metadata_payload = {
    "phi_types": metadata.phi_types or [],
    "infrastructure": metadata.infrastructure or {},
}
```

**Key Review Notes:**
- "Mutable defaults create shared state bugs"
- "Use `None` as sentinel, create new object in function body"
- "Only immutable defaults are safe: integers, strings, None, tuples"
- "The `or []` pattern is for None-handling, not defaults"
- "Problem is specific to function PARAMETERS"

---

## 5. Magic Strings / Magic Numbers

**What:** Hardcoded string/number literals repeated throughout code

**Bad:**
```python
# Repeated everywhere
if status == "completed":
    ...
elif status == "running":
    ...
elif status == "failed":
    ...

# Typo = runtime bug!
assessment.status = "complted"  # No error until too late
```

**Good:**
```python
# Constants file
class AssessmentStatus:
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

# Usage - autocomplete + refactoring safety
if status == AssessmentStatus.COMPLETED:
    ...
assessment.status = AssessmentStatus.RUNNING
```

**Even Better, Enums:**
```python
from enum import Enum

class Status(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

# Type-safe, exhaustive matching
status: Status = Status.RUNNING
```

**Key Review Notes:**
- "Magic values = no autocomplete, no type safety, no compile-time checks"
- "Typos caught at import time vs runtime"
- "Single source of truth for refactoring"
- "Use class constants or Enums"
- "Extract to constants module for shared values"

---

## 6. Duplicated Code / Violation of DRY

**What:** Same logic repeated with minor variations

**When It's a Problem:**
```python
# BAD - Same structure, different values
def check_access():
    if not mfa_enabled:
        return Finding(
            title="MFA Not Enabled",
            description="Long description...",
            severity="high",
            # 10 more fields...
        )

def check_encryption():
    if not encrypted:
        return Finding(
            title="Encryption Disabled",
            description="Another long description...",
            severity="high",
            # Same 10 fields...
        )
# ...repeated 10 more times
```

**Fix:**
```python
# GOOD - Extract helper
def _create_security_finding(
    self,
    title: str,
    description: str,
    severity: str,
    cwe_ids: list[str],
) -> Finding:
    return Finding(
        assessment_id=self.assessment.id,
        title=title,
        description=description,
        severity=severity,
        cve_ids=[],
        cwe_ids=cwe_ids,
        priority_window="immediate" if severity in ["critical", "high"] else "30_days",
        owner="Security",
    )

def check_access():
    if not mfa_enabled:
        return self._create_security_finding(
            title="MFA Not Enabled",
            description="...",
            severity="high",
            cwe_ids=["CWE-308"],
        )
```

**When Duplication is OK:**
```python
# ACCEPTABLE - Clear and explicit
def validate_email(email: str) -> bool:
    return "@" in email and "." in email

def validate_phone(phone: str) -> bool:
    return len(phone) == 10 and phone.isdigit()
```

**Key Review Notes:**
- "DRY (Don't Repeat Yourself), but clarity matters more"
- "Extract when: logic complex, repeated 3+ times, likely to change together"
- "Keep duplication when: extraction makes code harder to read"
- "Rule of Three: duplicate twice, extract on third occurrence"
- "Judgement call: maintainability vs readability"

---

## 7. Nested Conditionals (Arrow Anti-Pattern)

**What:** Deep nesting of if statements

**Bad:**
```python
def process(data):
    if data:
        if data.valid:
            if data.user:
                if data.user.active:
                    if data.user.verified:
                        return process_user(data.user)
                    else:
                        return "Not verified"
                else:
                    return "Inactive"
            else:
                return "No user"
        else:
            return "Invalid"
    else:
        return "No data"
```

**Good: Guard Clauses:**
```python
def process(data):
    if not data:
        return "No data"
    if not data.valid:
        return "Invalid"
    if not data.user:
        return "No user"
    if not data.user.active:
        return "Inactive"
    if not data.user.verified:
        return "Not verified"

    return process_user(data.user)
```

**Key Review Notes:**
- "Use guard clauses; return early"
- "Fail fast principle"
- "Reduces cognitive load: flat is better than nested"
- "Easier to test each condition independently"

---

## Quick Reference Table

| Antipattern | Danger Level | Fix |
|-------------|--------------|-----|
| Bare `except:` | CRITICAL | Catch specific exceptions |
| Mutable defaults | CRITICAL | Use `None` sentinel |
| God function (>100 lines) | MEDIUM | Extract smaller functions |
| Magic strings/numbers | MEDIUM | Use constants/enums |
| Overly broad `except Exception` | CONTEXT | OK at API boundaries, bad in business logic |
| Code duplication | LOW | Extract if repeated 3+ times AND complex |
| Deep nesting | MEDIUM | Use guard clauses |

---

## Applying This Guide in Reviews

**When Reviewing Code Quality:**
1. **Mention testability**: "This antipattern makes unit testing difficult because..."
2. **Reference principles**: "Violates Single Responsibility / DRY / SOLID"
3. **Show impact**: "This causes bugs when..." or "Makes refactoring dangerous"
4. **Provide example**: "For instance, bare except catches SystemExit..."
5. **Know the tradeoffs**: "Sometimes duplication is better than wrong abstraction"

**Useful Review Heuristics:**
- "I look for functions over 50 lines, then extract helpers"
- "I avoid bare except because it catches system signals"
- "I use constants for repeated strings; it makes refactoring safe"
- "I catch specific exceptions in business logic, broader at API boundaries"
- "I apply the Rule of Three before extracting duplication"

**Common Misconceptions to Avoid:**
- "I never use exceptions" (exceptions are Pythonic!)
- "All duplication is bad" (nuance matters)
- "Lines of code don't matter" (long functions are real issues)
- "Magic strings are fine for performance" (not true)

---

## Further Study

**Python-Specific:**
- PEP 8 (Style Guide)
- "Fluent Python" by Luciano Ramalho
- "Effective Python" by Brett Slatkin

**General Patterns:**
- "Refactoring" by Martin Fowler
- "Clean Code" by Robert Martin
- SOLID Principles

**Practice:**
- Code review your old projects
- Refactor antipatterns you find
- Explain why the change improves correctness, readability, or maintainability.
