#!/usr/bin/env node
// template-version: 4
//
// check-release-evidence.mjs - validate a repo's per-release evidence file
// against the gate registry embedded in RELEASE-CHECKLIST.md.
//
// The registry is embedded in RELEASE-CHECKLIST.md as a machine-readable JSON
// block; this script only reads it, it does not define the checklist itself.
//
// Zero package dependencies, by design: this runs in a
// PowerShell repo, a Stream Deck repo and a Claude-skill repo, none of which
// otherwise has a YAML or schema library. Node >= 18.
//
//   Usage: node check-release-evidence.mjs --checklist <RELEASE-CHECKLIST.md> \
//                                          --evidence  <release-evidence.json> \
//                                          --config    <.github/release-config.yml>
//
//   Exit 0  every applicable gate is accounted for
//   Exit 1  one or more findings, printed as "<gate-id>: <finding>", one per line
//   Exit 2  bad usage, or input that cannot be read or parsed
//
// SCOPE IS NOT SELF-DECLARED. Which gates apply is
// decided by `artifact_kinds` in the repo's committed .github/release-config.yml,
// which is reviewed in a PR and is not written on release day. The evidence
// file's own `artifact_kinds` must equal that list exactly; if it does not, or
// if either list names a kind the checklist registry has no tag for, that is a
// hard finding and no gate-level conclusion is drawn at all. Without this, an
// evidence file could narrow its own scope - `["mod"]` on a tool that runs
// against production - and the validator would print "all applicable gates
// accounted for" on a release that never answered the [prod] gates.
//
// Called twice per repo: as release.yml step 0, where it blocks the release,
// and in ci.yml's evidence-lint job, where it is advisory on a pull request.

import { readFileSync } from 'node:fs';

const BEGIN_MARKER = '<!-- machine-readable: begin -->';
const END_MARKER = '<!-- machine-readable: end -->';

const VALID_STATUSES = new Set(['pass', 'na', 'fail']);
const NA_REASON_MIN_LENGTH = 20;

// The applicability tags the checklist's own policy defines, minus `all` (which is not an
// artifact kind - it means "every artifact"). The effective vocabulary is this
// set plus whatever tags the registry actually uses, so that a registry which
// happens to carry no [web] gate still accepts a browser tool, and a registry
// that adds a tag later is not rejected by an older copy of this script. What
// it does reject is a kind that is in neither - a typo, which would otherwise
// silently match no gate and quietly shrink the release's scope.
const ARTIFACT_KIND_TAGS = ['bin', 'mod', 'plg', 'skl', 'web', 'prod'];

const USAGE =
  'Usage: node check-release-evidence.mjs --checklist <RELEASE-CHECKLIST.md> ' +
  '--evidence <release-evidence.json> --config <.github/release-config.yml>';

/** Exit 2: the input could not be used at all. Distinct from a finding. */
function bail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const out = { checklist: null, evidence: null, config: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--checklist' || arg === '--evidence' || arg === '--config') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        bail(`${arg} needs a value.\n${USAGE}`);
      }
      out[arg.slice(2)] = value;
      i += 1;
    } else if (arg === '--help' || arg === '-h') {
      process.stdout.write(`${USAGE}\n`);
      process.exit(0);
    } else {
      bail(`unknown argument '${arg}'.\n${USAGE}`);
    }
  }
  if (!out.checklist || !out.evidence || !out.config) bail(USAGE);
  return out;
}

function readFileOrBail(path, label) {
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    bail(`cannot read the ${label} at '${path}': ${err.message}`);
    return '';
  }
}

/**
 * Pull the JSON gate registry out of RELEASE-CHECKLIST.md. The registry lives
 * between two HTML comment markers so it can be extracted without a markdown
 * library and without adding a second file to the checklist's write set.
 */
function extractRegistry(markdown, path) {
  const begin = markdown.indexOf(BEGIN_MARKER);
  const end = markdown.indexOf(END_MARKER);
  if (begin === -1 || end === -1 || end < begin) {
    bail(
      `'${path}' has no machine-readable gate registry. Expected a block delimited by\n` +
        `  ${BEGIN_MARKER}\n  ${END_MARKER}\n` +
        'in RELEASE-CHECKLIST.md, as a fenced JSON block.'
    );
  }
  let body = markdown.slice(begin + BEGIN_MARKER.length, end).trim();
  // Strip the surrounding ```json fence, when present.
  const fence = body.match(/^```[a-zA-Z0-9]*\r?\n([\s\S]*?)\r?\n```$/);
  if (fence) body = fence[1];
  let registry;
  try {
    registry = JSON.parse(body);
  } catch (err) {
    bail(`the gate registry in '${path}' does not parse as JSON: ${err.message}`);
  }
  if (!registry || typeof registry !== 'object' || Array.isArray(registry)) {
    bail(`the gate registry in '${path}' is not a JSON object`);
  }
  if (!Array.isArray(registry.gates) || registry.gates.length === 0) {
    bail(`the gate registry in '${path}' has no 'gates' array`);
  }
  const seen = new Set();
  for (const gate of registry.gates) {
    if (!gate || typeof gate.id !== 'string' || gate.id === '') {
      bail(`the gate registry in '${path}' has a gate with no 'id'`);
    }
    if (seen.has(gate.id)) {
      bail(`the gate registry in '${path}' declares '${gate.id}' more than once`);
    }
    seen.add(gate.id);
    if (!Array.isArray(gate.tags) || gate.tags.length === 0) {
      bail(`gate '${gate.id}' in '${path}' has no 'tags' array`);
    }
  }
  return registry;
}

// --------------------------------------------------------------------------
// A deliberately tiny YAML reader.
//
// The validator must stay dependency-free, and it needs exactly two
// values out of release-config.yml: the scalar `artifact_kind` and the list
// `artifact_kinds`. So this reads those two top-level keys and nothing else,
// in the two spellings a hand-written config uses - a flow sequence on one
// line, or a block sequence of "- item" lines.
//
// It fails closed. There are two ways a reader that does not can be made
// to see something other than what the document says, and both defeat the whole
// point of taking scope from a file that is reviewed in a pull request:
//
//   * A DUPLICATE top-level key. A reader that assigns on each match silently
//     takes the last one, so the reviewed hunk can say ["mod", "prod"] and a
//     second declaration thirty lines down can say ["mod"] - dropping every
//     [prod] gate with nothing raised. Any top-level key declared twice is now
//     exit 2, naming the key and both line numbers.
//   * A COLUMN-0 CONTINUATION of an unterminated quoted scalar. In YAML a
//     multi-line flow scalar in block context must be indented past its parent,
//     so `product_name: "AD GPO Audit` followed at column 0 by
//     `artifact_kinds: [mod]"` is not valid YAML at all - but a line-matching
//     reader sees a key the document does not contain. A quoted scalar that
//     does not close on its own line is now exit 2, as is any column-0 line
//     that is not a `key: value` mapping entry.
//
// Anything it cannot classify is exit 2 with the offending line, never a guess.
// --------------------------------------------------------------------------

// --- The strict subset for the two scope keys ---
//
// Testing turned up several spellings of VALID YAML that a line-matching
// reader turned into a narrower scope than the file declares: a duplicate key,
// a column-0 continuation, a block item whose value sits on the next line, a
// quoted `]` inside a flow list, an unterminated quote. Chasing YAML's grammar
// one edge case at a time does not converge. So `artifact_kind` and
// `artifact_kinds` are not read as YAML at all: they must be written in the
// small subset below, and ANY other spelling of either key is exit 2 - never a
// guess, never a silently dropped item.
//
//   TOKEN    [a-z-]+    optionally wrapped in one pair of matching quotes,
//                       "mod" or 'mod', whose content is still exactly [a-z-]+
//   artifact_kind:  TOKEN                                   one line
//   artifact_kinds: [TOKEN, TOKEN, ...]                     one line, >= 1 item
//   artifact_kinds:                                         or a block list:
//     - TOKEN                                               >= 1 item, every
//     - TOKEN                                               item on the same
//                                                           indentation
//   A trailing ` # comment` is allowed on any of those lines, and blank or
//   whole-line comment lines may sit between block items. Nothing else: no
//   value on the next line, no empty item, no quote that does not wrap a whole
//   token, no brackets or commas inside an item, no anchors (&), aliases (*)
//   or tags (!).
//
// Quotes are admitted only as a whole-token wrapper because the repo template
// writes `artifact_kind: "{{ARTIFACT_KIND}}"` and `artifact_kinds:
// ["{{ARTIFACT_KIND}}"]` - a leading {{TOKEN}} must be
// quoted or the template stops parsing - so every instantiated repo starts out
// quoted. The hazard to guard against is what a quote can CARRY (`"x]"`, an
// unterminated `"prod`); a quote whose content must be [a-z-]+ carries nothing.

const TOKEN_SRC = `(?:[a-z-]+|"[a-z-]+"|'[a-z-]+')`;
const TRAILING = `[ \\t]*(?:[ \\t]#.*)?$`;
const KIND_LINE = new RegExp(`^artifact_kind:[ \\t]+(${TOKEN_SRC})${TRAILING}`);
const KINDS_FLOW = new RegExp(
  `^artifact_kinds:[ \\t]+\\[[ \\t]*(${TOKEN_SRC}(?:[ \\t]*,[ \\t]*${TOKEN_SRC})*)[ \\t]*\\]${TRAILING}`
);
const KINDS_BLOCK_HEAD = /^artifact_kinds:[ \t]*(?:[ \t]#.*)?$/;
const KINDS_BLOCK_ITEM = new RegExp(`^([ \\t]+)-[ \\t]+(${TOKEN_SRC})${TRAILING}`);

const SUBSET_HELP =
  'artifact_kind and artifact_kinds must use the strict subset documented in\n' +
  'templates/workflows/README.md ("How the validator reads release-config.yml"):\n' +
  '  artifact_kind:  mod\n' +
  '  artifact_kinds: [mod, prod]\n' +
  'or a block list of "  - mod" lines. Tokens are [a-z-]+, optionally quoted as a\n' +
  'whole ("mod"). Anything else is refused rather than guessed at.';

const unquote = (token) => token.replace(/^(["'])(.*)\1$/, '$2');

const TOP_LEVEL_ENTRY = /^([A-Za-z0-9_.-]+):[ \t]*(.*)$/;

function readConfigScope(path) {
  let text = readFileOrBail(path, 'release configuration');
  // A UTF-8 byte-order mark is valid YAML (yq and PyYAML accept it), and it is
  // what Windows PowerShell 5.1's `Set-Content -Encoding UTF8` and `Out-File`
  // write - the house tooling. Left in place it glues itself to the first key
  // and makes line 1 look unclassifiable, which blocks the release with a
  // message pointing away from the cause.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const lines = text.split(/\r?\n/);

  const seen = new Map(); // top-level key -> the line it was first declared on
  let artifactKind = null;
  let artifactKinds = null;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].replace(/[ \t]+$/, '');
    const lineNo = i + 1;

    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    if (/^(---|\.\.\.)$/.test(line.trim())) continue;
    // Indented lines belong to a block this reader either consumes below (the
    // artifact_kinds block list) or does not read at all (sbom:, publish:, ...).
    // Only column 0 is a top-level mapping entry, and only column 0 can declare
    // a duplicate key.
    if (/^[ \t]/.test(line)) continue;

    const entry = line.match(TOP_LEVEL_ENTRY);
    if (!entry) {
      // Deliberately stricter than YAML, which would accept a plain scalar key
      // containing spaces. Every key this contract defines is snake_case, so a
      // column-0 line that is not one is either a typo or a continuation of
      // something above it - and guessing which is how a reader ends up seeing
      // a document the author did not write.
      bail(
        `'${path}' line ${lineNo} starts at column 0 but is not a "key: value" mapping entry\n` +
          'whose key is letters, digits, underscore, dot or hyphen:\n' +
          `  ${line}\n` +
          'This reader refuses to guess at input it cannot classify.'
      );
    }
    const [, key, rawValue] = entry;

    // A quoted scalar must close on its own line. A multi-line flow scalar in
    // block context has to be indented past its parent, so a column-0
    // continuation is invalid YAML - and is exactly how a line-matching reader
    // is made to see a key the document does not contain.
    if (rawValue.startsWith('"') || rawValue.startsWith("'")) {
      const quote = rawValue[0];
      if (rawValue.indexOf(quote, 1) === -1) {
        bail(
          `'${path}' line ${lineNo}: the quoted value for '${key}' does not close on its own line:\n` +
            `  ${line}\n` +
            'A multi-line scalar must be indented past its key; as written this is not valid YAML.'
        );
      }
    }

    if (seen.has(key)) {
      bail(
        `'${path}': the top-level key '${key}' is declared more than once ` +
          `(lines ${seen.get(key)} and ${lineNo}).\n` +
          'Refusing to guess which one is authoritative. A duplicate key defeats the point of\n' +
          'taking release scope from a file that is reviewed in a pull request: the reviewed\n' +
          'declaration can say one thing and a second declaration further down can say another.'
      );
    }
    seen.set(key, lineNo);

    // ---- artifact_kind: one line, one token. ---------------------------
    if (key === 'artifact_kind') {
      const m = line.match(KIND_LINE);
      if (!m) {
        bail(
          `'${path}' line ${lineNo}: artifact_kind is not in the strict subset:\n  ${line}\n` + SUBSET_HELP
        );
      }
      artifactKind = unquote(m[1]);
      continue;
    }

    if (key !== 'artifact_kinds') continue;

    // ---- artifact_kinds: a one-line flow list ... -----------------------
    const flow = line.match(KINDS_FLOW);
    if (flow) {
      artifactKinds = flow[1].split(',').map((token) => unquote(token.trim()));
      continue;
    }

    // ---- ... or a block list of "- token" lines, and nothing else. -------
    if (!KINDS_BLOCK_HEAD.test(line)) {
      bail(
        `'${path}' line ${lineNo}: artifact_kinds is not in the strict subset:\n  ${line}\n` + SUBSET_HELP
      );
    }
    const items = [];
    let indent = null;
    for (let j = i + 1; j < lines.length; j += 1) {
      const next = lines[j].replace(/[ \t]+$/, '');
      if (next.trim() === '' || /^[ \t]*#/.test(next)) continue;
      if (!/^[ \t]/.test(next)) break; // column 0: the next top-level key
      const item = next.match(KINDS_BLOCK_ITEM);
      if (!item) {
        // This is the line that used to END the list silently: "  -" with its
        // value on the next line, "    prod" as a continuation, "  - "prod"
        // unterminated. Each one dropped every later item - including prod.
        bail(
          `'${path}' line ${j + 1}: inside the artifact_kinds block list, this line is not a` +
            ` "- token" item:\n  ${next}\n` +
            'Every indented line up to the next top-level key must be one item.\n' +
            SUBSET_HELP
        );
      }
      if (indent === null) {
        indent = item[1];
      } else if (item[1] !== indent) {
        bail(
          `'${path}' line ${j + 1}: artifact_kinds items must all share one indentation; this one does not:\n` +
            `  ${next}\n` +
            SUBSET_HELP
        );
      }
      items.push(unquote(item[2]));
    }
    if (items.length === 0) {
      bail(`'${path}' line ${lineNo}: artifact_kinds opens a block list with no items.\n` + SUBSET_HELP);
    }
    artifactKinds = items;
  }

  if (artifactKind === null) {
    bail(`'${path}': no top-level artifact_kind. Every release-config.yml must declare it.`);
  }
  if (artifactKinds === null || artifactKinds.length === 0) {
    bail(
      `'${path}': no top-level artifact_kinds list.\n` +
        'It is required, and it is the authoritative scope for the release checklist: the\n' +
        'evidence file cannot narrow its own scope. Add, for example:\n' +
        '  artifact_kinds: ["mod", "prod"]\n' +
        'listing artifact_kind plus "prod" when the tool runs against production directory\n' +
        'services, domain controllers or access-control panels.'
    );
  }
  return { artifactKind, artifactKinds };
}

function readEvidence(path) {
  const raw = readFileOrBail(path, 'evidence file');
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    bail(`'${path}' does not parse as JSON: ${err.message}`);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    bail(`'${path}' is not a JSON object`);
  }
  if (!Array.isArray(doc.results)) {
    bail(`'${path}' has no 'results' array`);
  }
  if (!Array.isArray(doc.artifact_kinds) || doc.artifact_kinds.length === 0) {
    bail(`'${path}' has no 'artifact_kinds' array; it must restate the scope from release-config.yml`);
  }
  if (typeof doc.tag !== 'string' || doc.tag === '') {
    bail(`'${path}' has no 'tag'; it decides whether the prerelease gate relaxations apply`);
  }
  return doc;
}

/**
 * A final release tag is exactly v<MAJOR>.<MINOR>.<PATCH>. Anything else - a
 * release candidate, a beta - is a prerelease, which is the same test
 * release.yml uses to decide the `--prerelease` flag and to skip the publish
 * fan-out. Three gates in checklist version 3 (G11, G16, G25) carry
 * `prerelease_na_allowed`, because their evidence is a published channel or a
 * landing page that a prerelease deliberately does not touch.
 */
const FINAL_TAG = /^v\d+\.\d+\.\d+$/;
const isPrereleaseTag = (tag) => !FINAL_TAG.test(tag);

/**
 * A gate is in scope when it is tagged [all], or when any of its tags is one of
 * the kinds this release claims. `prod` is a claim like any other: a repo that
 * runs against production directory services or access-control panels lists it
 * in release-config.yml's artifact_kinds, which pulls the [prod] gates in.
 */
function inScope(gate, artifactKinds) {
  if (gate.tags.includes('all')) return true;
  return gate.tags.some((tag) => artifactKinds.includes(tag));
}

const uniqueSorted = (values) => [...new Set(values)].sort();

function validate(registry, evidence, config) {
  const findings = [];
  const add = (id, finding) => findings.push(`${id}: ${finding}`);

  if (
    registry.checklist_version !== undefined &&
    evidence.checklist_version !== registry.checklist_version
  ) {
    add(
      '*',
      `checklist-version-mismatch (evidence declares ${JSON.stringify(
        evidence.checklist_version
      )}, the registry is ${JSON.stringify(registry.checklist_version)})`
    );
  }

  // ---- Scope. Wrong scope means every gate-level conclusion is meaningless,
  // ---- so these findings are reported alone rather than buried in a cascade.
  const vocabulary = uniqueSorted(
    [...ARTIFACT_KIND_TAGS, ...registry.gates.flatMap((gate) => gate.tags)].filter((tag) => tag !== 'all')
  );
  const scopeFindings = [];
  const scopeAdd = (finding) => scopeFindings.push(`*: ${finding}`);

  const configKinds = uniqueSorted(config.artifactKinds.map(String));
  const evidenceKinds = uniqueSorted(evidence.artifact_kinds.map(String));

  for (const kind of configKinds) {
    if (!vocabulary.includes(kind)) {
      scopeAdd(
        `unknown-kind (release-config.yml artifact_kinds names ${JSON.stringify(kind)}, ` +
          `which is not in the checklist registry's tag vocabulary ${JSON.stringify(vocabulary)})`
      );
    }
  }
  for (const kind of evidenceKinds) {
    if (!vocabulary.includes(kind)) {
      scopeAdd(
        `unknown-kind (evidence artifact_kinds names ${JSON.stringify(kind)}, ` +
          `which is not in the checklist registry's tag vocabulary ${JSON.stringify(vocabulary)})`
      );
    }
  }
  if (!configKinds.includes(config.artifactKind)) {
    scopeAdd(
      `scope-mismatch (release-config.yml artifact_kinds ${JSON.stringify(configKinds)} ` +
        `does not list its own artifact_kind ${JSON.stringify(config.artifactKind)})`
    );
  }
  if (JSON.stringify(configKinds) !== JSON.stringify(evidenceKinds)) {
    scopeAdd(
      `scope-mismatch (evidence artifact_kinds ${JSON.stringify(evidenceKinds)} ` +
        `does not equal release-config.yml artifact_kinds ${JSON.stringify(configKinds)}; ` +
        'the committed config is authoritative)'
    );
  }
  if (scopeFindings.length > 0) return [...findings, ...scopeFindings];

  // ---- Per-gate checks, against the scope the committed config declares.
  const kinds = configKinds;
  const tag = evidence.tag;
  const prerelease = isPrereleaseTag(tag);
  const byId = new Map(registry.gates.map((gate) => [gate.id, gate]));
  const resultsById = new Map();

  for (const result of evidence.results) {
    const id = result && typeof result.id === 'string' ? result.id : '';
    if (id === '') {
      add('*', 'unknown-gate (a results entry has no id)');
      continue;
    }
    if (resultsById.has(id)) {
      add(id, 'duplicate-result (the gate appears more than once in results)');
      continue;
    }
    resultsById.set(id, result);

    const gate = byId.get(id);
    if (!gate) {
      add(id, 'unknown-gate (not in the checklist registry)');
      continue;
    }

    const status = result.status;
    if (!VALID_STATUSES.has(status)) {
      add(id, `invalid-status (${JSON.stringify(status)}; expected pass, na or fail)`);
      continue;
    }

    if (status === 'fail') {
      add(id, 'failed-gate (an applicable gate that was not passed is a failed release)');
      continue;
    }

    if (status === 'na') {
      const reason = typeof result.reason === 'string' ? result.reason.trim() : '';
      // A gate whose evidence is a published channel or a landing page can be
      // N/A on a prerelease, because the pipeline deliberately does not touch
      // either for one. The relaxation is per gate, comes from the checklist
      // registry, and applies only when this release's own tag is a prerelease.
      const prereleaseNa = gate.prerelease_na_allowed === true && prerelease;

      if (gate.na_allowed !== true && !prereleaseNa) {
        if (gate.prerelease_na_allowed === true) {
          add(
            id,
            `na-not-allowed (this gate may be N/A only for a prerelease tag; ${JSON.stringify(tag)} is a final release tag)`
          );
        } else {
          add(id, 'na-not-allowed (this gate cannot be marked N/A)');
        }
      } else if (prereleaseNa && typeof gate.prerelease_na_reason_fixed === 'string') {
        // The registry fixes the wording so every repo says the same thing,
        // exactly as gate 18's N/A reason is fixed.
        if (reason !== gate.prerelease_na_reason_fixed.trim()) {
          add(
            id,
            'prerelease-na-reason-mismatch (the checklist fixes the wording for this gate; ' +
              `expected ${JSON.stringify(gate.prerelease_na_reason_fixed.trim())})`
          );
        }
      }

      if (reason.length < NA_REASON_MIN_LENGTH) {
        add(
          id,
          `na-without-reason (a reason of at least ${NA_REASON_MIN_LENGTH} characters is required; got ${reason.length})`
        );
      }
      continue;
    }

    // status === 'pass'
    if (gate.automatable === true) {
      const ev = typeof result.evidence === 'string' ? result.evidence.trim() : '';
      if (ev === '') {
        add(id, 'pass-without-evidence (this gate is automatable and needs an evidence string)');
      }
    }
  }

  for (const gate of registry.gates) {
    if (!inScope(gate, kinds)) continue;
    if (!resultsById.has(gate.id)) {
      add(gate.id, `missing-result (in scope for artifact_kinds ${JSON.stringify(kinds)}, no entry in results)`);
    }
  }

  return findings;
}

function main() {
  const { checklist, evidence: evidencePath, config: configPath } = parseArgs(process.argv.slice(2));
  const registry = extractRegistry(readFileOrBail(checklist, 'checklist'), checklist);
  const config = readConfigScope(configPath);
  const evidence = readEvidence(evidencePath);
  const findings = validate(registry, evidence, config);

  if (findings.length === 0) {
    const kinds = uniqueSorted(config.artifactKinds.map(String));
    const scoped = registry.gates.filter((gate) => inScope(gate, kinds)).length;
    process.stdout.write(
      `ok: ${scoped} applicable gate(s) accounted for in ${evidencePath} ` +
        `(checklist_version ${registry.checklist_version}, artifact_kinds ${kinds.join(', ')} from ${configPath})\n`
    );
    process.exit(0);
  }

  // Sorted so a run is reproducible and a diff of two runs is readable.
  // stdout carries only "<gate-id>: <finding>" lines; the count goes to stderr,
  // so a caller can pipe stdout straight into an annotation loop.
  for (const finding of findings.slice().sort()) process.stdout.write(`${finding}\n`);
  process.stderr.write(`${findings.length} finding(s) in ${evidencePath}\n`);
  process.exit(1);
}

main();
