# 🤝 Contributing to InMyMine7

Thank you for your interest in contributing to InMyMine7! This document provides guidelines and instructions for contributing to the project.

## ⚠️ Legal & Ethical Guidelines

**IMPORTANT:** This tool is intended **ONLY** for authorized penetration testing and security research.

By contributing to this project, you agree that:

1. ✅ You understand this tool is for authorized testing only
2. ✅ You will not use or contribute code that enables unauthorized access
3. ✅ You will respect laws and regulations in your jurisdiction
4. ✅ You will not help others misuse this tool
5. ✅ You understand the author assumes no liability for misuse

## 🐛 Reporting Bugs

### Before Reporting

1. Check the [README](../README.md) for common issues
2. Search [existing issues](https://github.com/InMyMine7/InMyMine7/issues)
3. Check [Discussions](https://github.com/InMyMine7/InMyMine7/discussions)

### How to Report

1. Use the [Bug Report template](ISSUE_TEMPLATE/bug_report.md)
2. Include as much detail as possible:
   - Operating system and version
   - Python version
   - Tool version
   - Steps to reproduce
   - Expected vs actual behavior
   - Error logs/screenshots

### For Security Vulnerabilities

**DO NOT** create a public issue for security vulnerabilities!

Instead:
- Contact [@InMyMineee](https://t.me/InMyMineee) on Telegram
- Email: [if email is provided]
- Use the private security advisory feature on GitHub

## ✨ Suggesting Features

### Before Suggesting

1. Check [existing feature requests](https://github.com/InMyMine7/InMyMine7/issues?q=label%3Aenhancement)
2. Ensure the feature aligns with the project's purpose

### How to Suggest

1. Use the [Feature Request template](ISSUE_TEMPLATE/feature_request.md)
2. Describe:
   - What problem does this solve?
   - How would users interact with this feature?
   - Are there alternatives?
   - Any examples or mockups?

## 💻 Code Contributions

### Getting Started

1. **Fork** the repository
2. **Clone** your fork:
```bash
git clone https://github.com/YOUR-USERNAME/Mephisto.git
cd Mephisto
```

3. **Create a virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. **Install dependencies:**
```bash
pip install -r requirements.txt
```

5. **Create a feature branch:**
```bash
git checkout -b feature/your-feature-name
```

### Coding Standards

#### Code Style
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use 4 spaces for indentation
- Keep lines under 100 characters when possible
- Use meaningful variable and function names

#### Documentation
- Add docstrings to all functions and classes
- Include comments for complex logic
- Update README if adding new features

#### Example:
```python
def check_file(self, filename):
    """
    Check if a required file exists in the configured directory.
    
    Args:
        filename (str): Name of the file to check
        
    Returns:
        bool: True if file exists, False otherwise
    """
    file_path = os.path.join(self.CONFIG['FILES_DIR'], filename)
    if not os.path.exists(file_path):
        self.log_message(f"File {filename} not found", error=True)
        return False
    return True
```

#### Error Handling
- Always handle exceptions appropriately
- Log errors with meaningful messages
- Don't silently fail

### Adding New Exploits

Full contract and rationale: [docs/ADDING_CVE.md](../docs/ADDING_CVE.md).

#### File Structure
```
exploits/cve_<year>_<number>.py
```

The filename determines the CVE id (`cve_2026_0920.py` → `CVE-2026-0920`).
Modules are discovered automatically — there is no registry to edit.

#### Template
Start from [`exploits/_template.py`](../exploits/_template.py). The entry point
takes the single `Exploit` instance and must not escape with an exception:

```python
"""CVE-XXXX-NNNN - Vulnerability type (component)."""

import requests
from colorama import Fore

META = {
    "type": "Arbitrary File Upload",
    "component": "example-plugin",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-NNNN"],
}


def exploit_cve_xxxx_nnnn(exploit_instance):
    try:
        response = exploit_instance.session.post(
            f"{exploit_instance.url}wp-admin/admin-ajax.php",
            data={"action": "example_action"},
            headers=exploit_instance.headers,
            proxies=exploit_instance.proxy,
            verify=False,
            timeout=exploit_instance.CONFIG["TIMEOUT"],
        )

        if response.status_code == 200 and "expected-marker" in response.text:
            exploit_instance.log_message(f"{Fore.GREEN}[CVE-XXXX-NNNN] [VULN]{Fore.RESET}", success=True)
            exploit_instance.record("shell", f"{exploit_instance.url}uploaded.php")
        else:
            exploit_instance.log_message(f"{Fore.RED}[CVE-XXXX-NNNN] [NO]{Fore.RESET}")
    except requests.RequestException as exc:
        exploit_instance.log_message(f"[CVE-XXXX-NNNN Error: {exc}]", error=True)
```

#### Recording Findings
Use `exploit_instance.record(kind, value)`; the engine compares result-file line
counts to decide whether the target is vulnerable.

| kind | Destination (`config.json` key) |
|---|---|
| `shell` | `SHELLS_FILE` |
| `admin` | `ADMINS_FILE` |
| `password` | `PASSWORDS_FILE` |
| `register` | `REGISTER_FILE` |

Do not open result files directly — `record` owns the layout.

#### Registration
None. `mephisto.registry.discover()` imports every `exploits/cve_*.py` on start.
If a module exports several `exploit_*` functions, set `EXPLOIT_ENTRY` to name
the right one.

### Testing Your Changes

1. **Self-checks (no network needed):**
```bash
python -m unittest discover -s tests -t .
```

2. **Compile check:**
```bash
python -m compileall -q mephisto exploits main.py
```

3. **Test on different platforms:**
   - Windows
   - Linux (Ubuntu, Fedora, Arch)
   - macOS

### Submitting Changes

1. **Commit with Clear Messages:**
```bash
git commit -m "Add feature: brief description"
```

2. **Push to Your Fork:**
```bash
git push origin feature/your-feature-name
```

3. **Create a Pull Request:**
   - Use the [PR template](PULL_REQUEST_TEMPLATE.md)
   - Link related issues
   - Describe changes clearly
   - Include testing information

## 📚 Documentation Contributions

### Improving Documentation

1. Check the [Documentation template](ISSUE_TEMPLATE/documentation.md)
2. Focus areas:
   - README improvements
   - Installation guide clarifications
   - Usage examples
   - Troubleshooting guides
   - Comments in code

### Writing Good Documentation

- Use clear, simple language
- Include examples
- Add step-by-step instructions
- Provide expected outputs
- Include troubleshooting tips

## 🚀 Pull Request Process

1. **Ensure your PR:**
   - ✅ Passes all checks
   - ✅ Follows code style
   - ✅ Includes tests
   - ✅ Updates documentation
   - ✅ Uses the PR template

2. **Wait for review:**
   - Be responsive to feedback
   - Make requested changes
   - Re-request review when ready

3. **Merge:**
   - PR will be merged by maintainer
   - Your contribution will be credited

## 💬 Communication

### Where to Discuss

- **Issues:** Bug reports and feature requests
- **Discussions:** Questions and general chat
- **Telegram:** Quick questions and support
- **Email:** For sensitive matters

### Be Respectful

- Use respectful language
- Assume good intentions
- Help others learn
- Don't spam or promote unrelated content

## 🏆 Recognition

Contributors will be recognized in:
- Pull request comments
- Release notes
- Contributors list (if applicable)

## 📋 Checklist Before Submitting

- [ ] Code follows PEP 8 style guide
- [ ] Changes are tested
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] No sensitive information included
- [ ] Changes align with project goals
- [ ] PR description is complete
- [ ] Related issues are linked

## ❓ Questions?

- Open a [Discussion](https://github.com/InMyMine7/InMyMine7/discussions)
- Message [@InMyMineee](https://t.me/InMyMineee) on Telegram
- Check the [README](../README.md)

---

**Thank you for contributing to InMyMine7!** 🙏

Your contributions help make this tool better for the security community while maintaining ethical standards.

**Remember:** This tool is only for authorized penetration testing. Use it responsibly and legally.
