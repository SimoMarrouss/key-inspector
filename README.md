the `publishPlugin` Gradle task provided by
the [intellij-platform-gradle-plugin][gh:intellij-platform-gradle-plugin-docs].
# Key Inspector

Key Inspector is an IntelliJ Platform plugin for inspecting keystores, certificates, keys, CSRs, and CRLs directly inside the IDE.

## Features

- Open supported files in the **Key Inspector** tool window or dedicated file editor
- Inspect keystore entries, certificate chains, CSRs, public/private keys, and CRLs
- Switch between structured **Inspector** and **Raw** views
- Import certificates or key pairs into existing keystores
- Export entries as PEM, DER, certificate chains, or PKCS#12
- Generate self-signed certificates from a guided wizard
- Change or remove keystore passwords
- Reveal entered passwords with **Show passwords** checkboxes in password dialogs

## Supported formats

### Keystores

- JKS
- JCEKS
- BKS
- PKCS#12 (`.p12`, `.pfx`)
- UBER
- BCFKS

### Certificates / keys / related files

- PEM
- DER certificates (`.cer`, `.crt`)
- PKCS#7 (`.p7`, `.p7b`)
- PKCS#8
- PKCS#10 / CSR (`.csr`, `.p10`)
- Public keys (`.pub`)
- Private keys (`.key`)
- PKIPath
- SPC
- SPKAC
- PVK
- CRL

## Password UX

Password entry surfaces support a **Show passwords** checkbox in:

- keystore password change / removal
- PKCS#12 export
- certificate / key import
- self-signed certificate generation output step

The inline unlock prompt inside the viewer also supports password visibility.

## Development

This project targets IntelliJ IDEA `2025.2.4` and Java `21` for compilation.

### Common tasks

```bash
./gradlew build
./gradlew runIde
./gradlew verifyPlugin
./gradlew buildPlugin
```

> Gradle itself must be launched with Java 17+.

## Release checklist

- Ensure Gradle is running on Java 17+ and the Java 21 toolchain is available
- Run `build`, `verifyPlugin`, and `buildPlugin`
- Smoke-test open/import/export/generate/change-password flows in `runIde`
- Confirm plugin metadata, description, vendor, and change notes are current
- Upload the generated ZIP from `build/distributions/`

## Source layout

- `src/main/kotlin` — plugin source code
- `src/main/resources/META-INF/plugin.xml` — plugin manifest
- `src/main/resources/messages` — bundled strings
