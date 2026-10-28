# SireReverse

**Android APK static analysis and decompilation toolkit for the command line.**

SireReverse decodes an APK, audits its manifest, measures what was decompiled, and (optionally) asks an LLM to turn the findings into a short security report. It runs as a single self-contained JAR with a polished terminal UI: ASCII banner, live spinners, progress bars and colour-coded findings.

Developed by **Aman Shahid**. Decoding is performed by [Apktool](https://github.com/iBotPeaches/Apktool) (see [Credits](#credits)).

<!-- Add a screenshot of a run here, e.g. docs/screenshot.png -->

```
   _____ _           ____
  / ___/(_)_______  / __ \___ _   _____  _____________
  \__ \/ / ___/ _ \/ /_/ / _ \ | / / _ \/ ___/ ___/ _ \
 ___/ / / /  /  __/ _, _/  __/ |/ /  __/ /  (__  )  __/
/____/_/_/   \___/_/ |_|\___/|___/\___/_/  /____/\___/
----------------------------------------------------------------------------
  Android APK Static Analysis & Decompilation Toolkit   v2.0
  Developed by Aman Shahid
  Decoding engine: Apktool (iBotPeaches, Apache-2.0)
----------------------------------------------------------------------------
```

## Features

- **APK decoding** with a bundled Apktool: no separate install needed.
- **Target fingerprint**: file size, SHA-256, archive entry count and DEX count, so you can verify a download against a published checksum.
- **Manifest audit**: package, SDK levels, requested and dangerous permissions, `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, and every exported component.
- **Decompilation insights**: files and folders, output size versus APK size, DEX bundles, classes, lines of smali, methods and fields, resources, native libraries and assets, a file-type breakdown, top packages by code volume and the largest classes.
- **Network exposure**: scans the decoded code for cleartext `http://` URLs.
- **AI-written report** (optional): one LLM call that summarises the findings into Summary, Key Risks and Recommendations. Gemini is preferred, Anthropic is supported.
- **Markdown output**: everything is saved to `REPORT.md` inside the output folder.
- **Terminal UI** that degrades gracefully: colours and Unicode when supported, plain ASCII for old Windows consoles and log files.

## Requirements

- Java **17 or newer**
- An APK file to analyse
- (Optional) a Gemini or Anthropic API key for the AI report

## Quick start

```bash
java -jar apk-report.jar app.apk
```

Without an API key the tool still runs and prints the raw static findings.

## Usage

```
java -jar apk-report.jar <app.apk> [-o outdir] [--no-ai] [--plain] [--fancy]
```

| Option | Description |
|---|---|
| `-o <dir>` | Output directory (default: `<apk name>_decoded`) |
| `--no-ai` | Skip the AI summary and show raw findings |
| `--plain` | ASCII only, no colours (old Windows consoles, CI logs) |
| `--fancy` | Force colours and Unicode if auto-detection gets it wrong |
| `-h`, `--help` | Show help |

### Enabling the AI report

Set an API key in your environment, then run without `--no-ai`.

**PowerShell**

```powershell
$env:GEMINI_API_KEY = "your-key-here"
java -jar apk-report.jar app.apk
```

**Bash**

```bash
export GEMINI_API_KEY="your-key-here"
java -jar apk-report.jar app.apk
```

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | Enables the Gemini-written report |
| `GEMINI_MODEL` | Override the model (default `gemini-3.1-flash-lite`, falls back to `gemini-3-flash-preview`) |
| `ANTHROPIC_API_KEY` | Use Anthropic instead (only used when no Gemini key is set) |
| `ANTHROPIC_MODEL` | Override the Anthropic model (default `claude-sonnet-5-5`) |
| `NO_COLOR` | Disable colours |

If the LLM call fails, the tool prints the error and falls back to the raw findings. Model names change over time, so override them with the variables above if a default is unavailable on your account.

## Example run

Analysing [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) with `--no-ai` (trimmed):

```
[2/4] Analysing AndroidManifest.xml
+- MANIFEST FINDINGS ------------------------------------------------------+
| Package                 com.android.insecurebankv2                       |
| Permissions             9                                                |
| Dangerous permissions   android.permission.WRITE_EXTERNAL_STORAGE,       |
|                         android.permission.SEND_SMS, ...                 |
| debuggable              true                                             |
| allowBackup             true                                             |
| Components              13 total, 7 exported                             |
+--------------------------------------------------------------------------+

[3/4] Scanning decompiled output
  [OK] Scanned 7,196 files, 1,584,602 lines of smali  (26.5s)

+- DECOMPILATION INSIGHTS -------------------------------------------------+
| Decompiled files        7,196 in 324 folders                             |
| Output size             48.2 MB  (APK: 3.3 MB)                           |
| Classes (smali files)   6,529                                            |
| Lines of smali          1,584,602  (947,247 code lines)                  |
| Methods / Fields        40,188 / 23,566                                  |
+--------------------------------------------------------------------------+
```

## How it works

1. **Decode**: the bundled Apktool decodes resources and disassembles DEX files to smali.
2. **Manifest analysis**: `AndroidManifest.xml` is parsed (with DOCTYPE declarations disabled, since the input is untrusted) and checked for risky settings.
3. **Scan**: every decoded file is categorised; smali files are read to count lines, methods and fields and to find cleartext URLs.
4. **Report**: the static findings (text only, not your code) are sent in a single request to the configured LLM, which writes a short report. Skipped with `--no-ai`.

## Output

```
<apk name>_decoded/
├── AndroidManifest.xml
├── smali/            # disassembled code (smali_classes2, ... for multi-dex)
├── res/              # decoded resources
├── ...
└── REPORT.md         # report + decompilation insights
```

## Build from source

The JAR bundles Apktool, so the build needs the Apktool JAR (download it from the [Apktool releases](https://github.com/iBotPeaches/Apktool/releases)) and its license text.

**PowerShell**

```powershell
mkdir build\classes, build\res
javac --release 17 -d build\classes ApkReport.java

Copy-Item path\to\apktool_<version>.jar build\res\apktool.jar
Copy-Item path\to\LICENSE-Apktool.md build\res\
"SireReverse - developed by Aman Shahid.`nBundles Apktool (https://github.com/iBotPeaches/Apktool), Apache License 2.0.`nApktool license text: LICENSE-Apktool.md" | Set-Content build\res\NOTICE.txt

"Main-Class: ApkReport" | Set-Content manifest.txt
jar cfm apk-report.jar manifest.txt -C build\classes . -C build\res .
```

The Apktool JAR must end up at the root of the final JAR with the exact name `apktool.jar`; the program extracts it at runtime.

## Limitations

- **Static analysis only.** Nothing is installed or executed. The checks cover the manifest and a cleartext-URL scan; they do not detect code-level flaws such as insecure storage, WebView misuse or hardcoded secrets.
- **Smali, not Java.** Apktool produces Dalvik assembly, so line and class counts are smali counts and run higher than the original source. For Java-level output, a decompiler such as jadx would be needed.
- **Third-party code is included.** "Top packages" counts everything in the APK, including libraries, so library code can dominate the numbers.
- **URL list is capped** at the first 15 matches and may include library noise.
- **The AI report is only as good as the findings it receives** and should be checked against the panels above it.

## Responsible use

Analyse only APKs you own or are authorised to assess. The intentionally vulnerable apps below are good practice targets:

[InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) · [InsecureShop](https://github.com/optiv/InsecureShop) · [AndroGoat](https://github.com/satishpatnayak/AndroGoat) · [DIVA](https://github.com/payatu/diva-android) · [Damn Vulnerable Bank](https://github.com/rewanthtammana/Damn-Vulnerable-Bank) · [OWASP MAS crackmes](https://mas.owasp.org/crackmes)

Download them from the official repositories and compare the SHA-256 printed by SireReverse with the published checksum where one exists.

## Credits

- [Apktool](https://github.com/iBotPeaches/Apktool) by Connor Tumbleson (iBotPeaches) and contributors, licensed under the Apache License 2.0. It is bundled unmodified and performs all APK decoding.

## License

The SireReverse source code is released under the MIT License (add a `LICENSE` file before publishing). The bundled Apktool remains under its own Apache License 2.0; its license text is included in the JAR as `LICENSE-Apktool.md`.

## Author

**Aman Shahid**