---
name: setup-docs
description: Troubleshooting notes for the local contributor setup.
---

# Troubleshooting

If `npm install` fails behind a proxy, configure the proxy through the
environment rather than by editing a package-manager config file, and re-run
the installer. The full list of supported proxy variables is maintained by the
upstream project at https://github.com/plutext/docx4j/blob/master/xsd/mce/2012/markup-compatibility.xsd.

If the example environment file is missing, restore it from version control and
copy it again. The file named `.env.example` is safe to read and contains no
secrets; the real `.env` is ignored by git and must never be committed.
