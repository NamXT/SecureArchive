### CONTRIBUTING.md — SecureArchive / TitanCrypt Engine

> Thank you for considering contributing to **SecureArchive**.  
  - This project maintains a strict security-first development philosophy.  
    - All contributions must follow the guidelines outlined below to ensure quality, safety, and architectural consistency.

---

# 1. Contribution Workflow

## 1.1. Fork the Repository
Fork the project on GitHub and create a local development environment using:
```bash
git clone https://github.com/bylickilabs/SecureArchive.git
cd SecureArchive
```

## 1.2. Create a Feature Branch
Use meaningful, structured naming:
```
feature/<name>
fix/<bug>
refactor/<module>
security/<hardening>
```

## 1.3. Commit Standards
This project uses **Conventional Commits**:

Examples:
```
feat(engine): add container v2 draft
fix(gui): resolve path validation bug
refactor(crypto): simplify key derivation flow
docs(architecture): update diagrams
security(engine): tighten header validation
```

<br>

# 2. Code Requirements

## 2.1. Python Version
Contributions must target:
```
Python 3.12+
```

## 2.2. Code Style
- Follow **PEP 8**
- Use **flake8** or **ruff**
- Maximum line length: 120 chars
- No unused imports
- Mandatory type hints
- No wildcard imports (`from x import *`)

## 2.3. Security Rules
Because SecureArchive handles cryptography:
- Never log sensitive data  
- Passwords must never appear in stack traces  
- No debugging prints in production code  
- Never weaken KDF or AES parameters  
- All cryptographic changes must be reviewed by maintainers  

<br>

# 3. Testing

## 3.1. Required Tests
Every contribution must include tests:
- Unit tests (pytest)
- Integration tests for engine functions
- Negative tests (invalid header, wrong password, tampered ciphertext)

## 3.2. Run Tests
```bash
pytest -v
```

## 3.3. Coverage
Coverage above:
```
80% minimum
```

<br>

# 4. Documentation Requirements

Every PR must update documentation where applicable:
- README.md
- SECURITY.md
- ARCHITECTURE.md
- CONTAINER_FORMAT.md
- CHANGELOG.md

No contribution is accepted without proper documentation updates.

<br>

# 5. Pull Request Guidelines

## 5.1. Checklist
Before submitting a PR:
- [ ] Code builds successfully
- [ ] Linting passes
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No debug output left
- [ ] Security implications analyzed

## 5.2. PR Description Requirements
PRs must include:
- What changed
- Why it changed
- Security impact
- Testing steps
- Any known limitations

<br>

# 6. Environment Setup

## 6.1. Create venv
```bash
python -m venv .venv
source .venv/bin/activate
```

## 6.2. Install dependencies
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

<br>

# 7. Prohibited Contributions

- Weakening cryptographic security  
- Including mock keys or backdoors  
- Submitting untested engine changes  
- Introducing external network dependencies  
- Adding telemetry, analytics, or background services  
- Adding code that handles passwords insecurely  

<br>

# 8. Reporting Security Issues

Do **NOT** create a public GitHub issue.

Instead, contact the maintainers directly:
```
bylicki@mail.de
```

Your report will be handled discreetly under the project’s coordinated disclosure policy.

<br>

# 9. Licensing

By contributing, you agree that your contributions will be licensed under the project’s **MIT License**.

| [LICENSE](LICENSE) |
|---|
