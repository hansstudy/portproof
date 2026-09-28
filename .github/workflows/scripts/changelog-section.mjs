#!/usr/bin/env node
// template-version: 1
//
// changelog-section.mjs - print the CHANGELOG.md section for one version.
//
// A tag with no matching CHANGELOG.md section fails the release, with the
// expected heading text printed, per the Keep a Changelog format and
// release gate 10.
//
// Zero package dependencies, like every script in this directory.
//
//   Usage: node changelog-section.mjs --version <1.2.0> [--changelog CHANGELOG.md]
//
//   Exit 0  the section body is written to stdout
//   Exit 1  no section for that version, or the section is empty
//   Exit 2  bad usage, or the changelog cannot be read

import { readFileSync } from 'node:fs';

const USAGE = 'Usage: node changelog-section.mjs --version <1.2.0> [--changelog CHANGELOG.md]';

function bail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

const args = process.argv.slice(2);
let version = null;
let changelog = 'CHANGELOG.md';
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--version') {
    version = args[i + 1];
    i += 1;
  } else if (args[i] === '--changelog') {
    changelog = args[i + 1];
    i += 1;
  } else {
    bail(`unknown argument '${args[i]}'.\n${USAGE}`);
  }
}
if (!version) bail(USAGE);

let text;
try {
  text = readFileSync(changelog, 'utf8');
} catch (err) {
  bail(`cannot read '${changelog}': ${err.message}`);
}

const lines = text.split(/\r?\n/);
// Accept "## [1.2.0] - 2026-10-01", "## 1.2.0", "## v1.2.0" and the bracketed
// variants of those; Keep a Changelog does not mandate one of them.
const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const heading = new RegExp(`^##\\s+\\[?v?${escaped}\\]?(\\s|$)`);
const anyHeading = /^##\s+/;

let start = -1;
for (let i = 0; i < lines.length; i += 1) {
  if (heading.test(lines[i])) {
    start = i;
    break;
  }
}
if (start === -1) {
  process.stderr.write(
    `::error file=${changelog}::no section for ${version}.\n` +
      `::error::Expected a Keep a Changelog heading such as: ## [${version}] - YYYY-MM-DD\n`
  );
  process.exit(1);
}

let end = lines.length;
for (let i = start + 1; i < lines.length; i += 1) {
  if (anyHeading.test(lines[i])) {
    end = i;
    break;
  }
}

const body = lines.slice(start + 1, end).join('\n').trim();
if (body === '') {
  process.stderr.write(
    `::error file=${changelog}::the section for ${version} is empty (release gate 10)\n`
  );
  process.exit(1);
}
process.stdout.write(`${body}\n`);
