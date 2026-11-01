# Adding a CVE

Mephisto discovers exploit modules automatically. Adding a CVE is one file plus
one test run — no registry edit, no `main.py` change.

## 1. Create the module

Copy `exploits/_template.py` to `exploits/cve_<year>_<number>.py`:

```bash
cp exploits/_template.py exploits/cve_2026_4444.py
```

The filename drives the CVE id: `cve_2026_4444.py` becomes `CVE-2026-4444`.
Leading-zero forms are preserved (`cve_2026_0920.py` → `CVE-2026-0920`).

## 2. Implement the entry point

```python
def exploit_cve_2026_4444(exploit_instance):
    ...
```

- The function receives one `mephisto.client.Exploit` instance.
- Name it `exploit_*`. If the module exports several such functions, the
  registry picks the one whose name carries CVE digits; if that guess is wrong,
  declare it explicitly:

  ```python
  EXPLOIT_ENTRY = "exploit_cve_2026_4444"
  ```

- Record findings through `exploit_instance.record(kind, value)`:

  | kind | destination key in `config.json` |
  |---|---|
  | `shell` | `SHELLS_FILE` |
  | `admin` | `ADMINS_FILE` |
  | `password` | `PASSWORDS_FILE` |
  | `register` | `REGISTER_FILE` |

  Recording a line is what makes the engine report the target as vulnerable,
  so do not write the files yourself.

## 3. Declare metadata (optional but encouraged)

```python
META = {
    "type": "Arbitrary File Upload",
    "component": "example-plugin",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-4444"],
}
```

`type` and `component` are shown in the `CHECK ALL EXPLOITS` menu.

## 4. Verify

```bash
python -m unittest discover -s tests -t .
```

The registry test asserts that every `cve_*.py` module exposes a callable entry
point, so a syntax error or a bad `EXPLOIT_ENTRY` fails here instead of at
runtime.

## Disabling a module

Add the CVE id to `DISABLED_EXPLOITS` in `config.json`; discovery skips it
without deleting the file:

```json
"DISABLED_EXPLOITS": ["CVE-2024-2667"]
```

## Module conventions

- Catch `requests.RequestException` before the generic `except Exception`.
- Read timeouts from `exploit_instance.CONFIG["TIMEOUT"]` /
  `["UPLOAD_TIMEOUT"]`; never hardcode seconds.
- Load payloads through `exploit_instance.payload_path(name)` rather than
  joining paths by hand.
- Keep the `[CVE-YYYY-NNNNN] [VULN]` / `[NO]` log markers — the scan summary and
  the troubleshooting docs rely on them.
