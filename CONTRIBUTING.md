# Contributing to Cloud Security Posture Dashboard

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## 🤝 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## 🐛 Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, cloud provider)
- **Relevant logs or screenshots**

## 💡 Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Use case**: Why is this enhancement needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: What other solutions did you think about?

## 🔧 Pull Request Process

1. **Fork the repo** and create your branch from `main`
2. **Follow coding standards**:
   - Python: Follow PEP 8, use Black for formatting
   - Terraform: Use `terraform fmt`
   - Add comments for complex logic
3. **Add tests** for new functionality
4. **Update documentation**:
   - Update README.md if needed
   - Add docstrings to functions
   - Update relevant docs/ files
5. **Run tests** before submitting:
   ```bash
   pytest tests/
   black scripts/
   flake8 scripts/
   ```
6. **Create Pull Request** with clear description

### PR Title Convention
```
[Type] Brief description

Types: Feature, Fix, Docs, Refactor, Test, Chore
Examples:
- [Feature] Add GCP support for security scanning
- [Fix] Resolve Prowler scan timeout issue
- [Docs] Update deployment guide for Azure
```

## 📝 Coding Standards

### Python
- Follow PEP 8 style guide
- Use type hints where applicable
- Write docstrings for all functions
- Keep functions focused and modular
- Maximum line length: 100 characters

### Terraform
- Use descriptive resource names
- Include comments for complex configurations
- Use variables for reusable values
- Tag all resources appropriately

### Git Commits
- Use clear, descriptive commit messages
- Reference issue numbers when applicable
- Keep commits atomic (one logical change per commit)

Example:
```
Add Azure Storage Account scanning (#12)

- Implement ScoutSuite integration for Azure
- Add storage account misconfiguration detection
- Update dashboard to display Azure findings
```

## 🧪 Testing Guidelines

- Write unit tests for all new functions
- Ensure test coverage remains above 80%
- Test both success and failure scenarios
- Use mocking for external API calls

## 📋 Development Workflow

1. Check existing issues or create a new one
2. Comment on the issue to indicate you're working on it
3. Fork and create a feature branch
4. Implement changes with tests
5. Submit pull request
6. Respond to review feedback
7. Celebrate when merged! 🎉

## 🏗️ Adding New Features

When adding new cloud provider support or scanning tools:

1. Create feature branch: `feature/add-gcp-support`
2. Add Terraform configurations in new directory
3. Create scanning scripts following existing patterns
4. Update aggregation logic to handle new findings
5. Update dashboard to display new data
6. Add tests and documentation
7. Submit PR with examples

## 🔐 Security

- **Never commit credentials** or API keys
- Use environment variables for sensitive data
- Review .gitignore before committing
- Report security vulnerabilities privately via email

## 📚 Documentation

- Keep README.md up to date
- Document all configuration options
- Provide usage examples
- Update architecture diagrams when structure changes

## ❓ Questions?

Feel free to open an issue with the `question` label or reach out to the maintainer.

---

**Thank you for contributing to making cloud security better!** 🛡️
