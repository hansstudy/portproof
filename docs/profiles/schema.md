# PortProof profile schema

A profile declares the firewall paths PortProof should try to prove open. It is data, never code:
PortProof never executes, evaluates, or templates anything read from a profile. A profile is
either a CSV file or a JSON file; both formats carry the same rows, in the same order, and are
validated against the same closed domains. This page documents both formats, the column/key
domains, group syntax, the `Required` semantics, the unknown-input policy, and the row-number
convention used by the provenance sidecars and by error messages.

## 1. CSV format

Plain RFC 4180 CSV, comma-separated, CRLF or LF line endings, UTF-8 (default) or UTF-16
(with a byte-order mark; PowerShell's own `Out-File` writes this in Windows PowerShell 5.1).
No other encoding is accepted, and a decode failure or an embedded NUL byte is refused rather
than silently mis-read.

Header row, column names compared case-insensitively:

| Column | Required | Meaning |
|---|---|---|
| `Source` | yes | The label for where the probe is said to originate (see "Source is a label" below). |
| `Target` | yes | The host or address PortProof connects to. |
| `Port` | yes | The TCP/UDP port number. |
| `Protocol` | yes | `TCP` or `UDP`. |
| `Required` | yes | `yes` or `no` - whether a non-`Pass` outcome on this row fails the run. |
| `Service` | no | Free-text label shown in reports (for example `LDAP`, `SQL Server Browser service`). |
| `Notes` | no | Free-text explanation shown in reports. |

Any other column name is **not** an error: it is ignored, listed in the run header's
`IgnoredColumns`, and its values are never read, stored, or rendered. If an ignored column's name
looks like a credential field (matches `pass|pwd|secret|token|cred|apikey|api_key|private`,
case-insensitive), the ignore warning says so explicitly, so nobody assumes a `Password` column
silently made it into a report. A duplicate column name (after case-folding) is refused
(`Profile.DuplicateColumn`); a missing required column is refused (`Profile.MissingColumn`).

A record must have exactly as many fields as the header (a short or long row is a syntax error,
not silently padded or truncated). A record whose every field is empty is a syntax error, not a
silently-skipped blank line; a genuinely blank trailing line at end of file is ignored. A file with
zero data rows is refused (`Profile.Empty`).

## 2. JSON format

Strict RFC 8259 JSON: no comments, no trailing commas, no single-quoted strings, no `NaN`/`Infinity`.
Object keys are matched case-insensitively, and a duplicate key in one object (including a
case-variant duplicate, e.g. `"Port"` and `"port"` in the same row) is refused
(`Profile.JsonDuplicateKey`), because the parser cannot pick a winner safely. Depth beyond 8 levels
is refused (`Profile.JsonDepth`) - there is no legitimate reason for a profile to nest that deep.

Top-level shape (exactly these keys; any other top-level key is refused, `Profile.UnknownKey`):

```json
{
  "schema":  "portproof-profile/1",
  "name":    "ad-dc",
  "version": "2026-09-25",
  "groups":  { "DIRECTORY": "10.10.5.20,dc02.corp.example" },
  "rows": [
    { "source": "%CLIENT%", "target": "%DIRECTORY%", "port": 389, "protocol": "TCP",
      "required": "yes", "service": "LDAP", "notes": "" }
  ]
}
```

| Key | Required | Meaning |
|---|---|---|
| `schema` | yes | Must equal `portproof-profile/1` exactly. |
| `name` | yes | 1-128 characters, no control characters. |
| `version` | no | 0-64 characters, no control characters. Free text (bundled profiles use the authoring/retrieval date). |
| `groups` | no | An object mapping an UPPERCASE group name to a group-grammar string (section 4). Bundled profiles ship **without** a `groups` block: group values are site-specific and are bound by the operator at run time. |
| `rows` | yes | An array of at least one row object. |

Row keys (matched case-insensitively): `source`, `target`, `port`, `protocol`, `required` are
required; `service`, `notes` are optional. Any other row key is refused (`Profile.UnknownKey`).
`port` must be a bare JSON integer - no quotes, no fraction, no exponent, no sign, no leading zero
(`"389"` or `389.0` is `Profile.Domain`). `required` must be the JSON string `"yes"` or `"no"`; the
JSON boolean `true`/`false` is `Profile.Domain`, not an accepted spelling.

## 3. Closed domains (both formats)

Every value below is checked against a fixed set; there is no "extend the list yourself" escape
hatch, on purpose - an unrecognised value is a mistake to fix, not a new case to silently accept.

| Field | Domain | Notes |
|---|---|---|
| `Protocol` | `TCP` \| `UDP` | Case-insensitive on input, stored upper-case. |
| `Port` | integer 1-65535 | CSV: digits only, no leading zero (`^[1-9]\d{0,4}$`); a range, list, wildcard, or leading-zero form is refused with a "no ranges" message - v1 has no port-range syntax at all. |
| `Required` | `yes` \| `no` | Case-insensitive on input, stored lower-case. Empty is an error, not a default. |
| `Source` / `Target` | non-empty; not the `Invalid` target-grammar class | A group placeholder (`%NAME%`), a literal IPv4/IPv6 address, or a hostname - anything else (malformed literal, refused address class as a *literal* target/source, control characters, etc.) is refused. `Source` is never resolved or probed from directly: it is a label recorded in the report so a reader knows which side of the connection is being described; PortProof always connects **from** the operator host. |
| `Service` | free text, <= 128 characters | Rendered as-is (through the same output-encoding rules as every other field). |
| `Notes` | free text, <= 1024 characters | Same. |

A duplicate row - the same `(Source, Target, Port, Protocol)` tuple compared case-insensitively as
written, even if `Required` differs - is refused (`Profile.DuplicateRow`): two rows that describe
the same probe with different `Required` values is a contradiction in the profile, not a
"last one wins" situation. A profile may declare at most 8192 data rows before any expansion; more
is refused (`Profile.TooLarge`), counted while reading so an oversized file cannot even be fully
parsed into memory first.

## 4. Group grammar and `-Set` / `groups` binding

A group is written as `%NAME%` (uppercase letters, digits, underscore) in `Source` or `Target`.
It is bound to a real value either by the JSON profile's own `groups` block or by the operator's
`-Set` argument at run time; a `-Set` binding for a name that also appears in the profile's
`groups` block overrides the profile's value (recorded in the run header as a `GroupOverride`, not
silently swallowed). An unused group (bound but never referenced by a row) is a warning, not an
error.

`-Set` takes one or more `NAME=VALUE` pieces. Multiple bindings on one `-Set` argument (for
example when invoking from a `.cmd`/`-File` context that only accepts one string) are separated by
`;`: `-Set "CLIENT=10.10.1.0/24;DC=dc01.corp.example,dc02.corp.example"`. Passing `-Set` more than
once is also accepted; the pieces accumulate. A binding name is
`^[A-Za-z][A-Za-z0-9_]{0,31}=.+$`; names are compared case-insensitively and must be unique across
all `-Set` arguments combined.

A bound group's value is **either**:
- a comma-separated list of items, each item a literal IPv4 address, a literal IPv6 address, or a
  hostname (as classified by the target-grammar rules), with no whitespace, no empty items, and no
  nested `%NAME%` reference (nesting is refused, `Group.Nested`); **or**
- exactly one IPv4 CIDR block, `<IPv4-address>/<prefix>`.

CIDR groups require the `-AllowCidr` switch (refused as `Group.CidrNotAllowed` otherwise); v1
supports any IPv4 prefix from **/8 to /32 inclusive** (VLSM: a narrow point-to-point prefix and a
wide LAN block are both legal in the same profile). Anything outside that range (`/0`-`/7`) is
refused as too large, `Group.CidrTooWide`. A prefix with host bits set in the network address is
refused (`Group.CidrNotAligned`) at every prefix length, `/31` and `/32` included. Expansion within
the accepted range follows one of three rules depending on the prefix:

| Prefix | Expands to |
|---|---|
| `/8`-`/30` | every host address between the network and broadcast address, **exclusive** (both endpoints excluded) |
| `/31` | **both** addresses (RFC 3021 point-to-point convention: no network/broadcast address exists at `/31`) |
| `/32` | the one address itself (a single host route) |

An IPv6 CIDR is refused (`Group.CidrIPv6` - v1 supports IPv4 CIDR only). A CIDR group used as a
`Source` is refused (`Group.CidrInSource`): it would multiply report rows without adding any
additional probe, so it serves no purpose there.

A CIDR's item count is computed arithmetically, without enumerating any address, so a wide prefix
(a `/16` or `/8`, say) is refused as soon as its count is known. Group items and expanded rows are
counted **before** any row object is built, and a profile whose total expansion would exceed the
operator's effective cap **x 8** is refused (`CapExceeded.Expansion`) before any resolution or
probing work happens - see the exit-code and cap documentation, not this page, for the exact
arithmetic. In practice this means a wide CIDR (or a profile with several moderately wide ones)
must either be split into narrower prefixes, bound to fewer targets, or run with `-AllowLarge`
(which raises the absolute cap to 8192, still subject to the same **x 8** expansion check) - it
does not raise `MaxGroupItems`, which applies only to comma-separated list groups, never to a
CIDR's arithmetic count.

**Worked example - a `/27` bound at the command line:**

```powershell
.\PortProof.ps1 -Profile .\profile.csv -Set "BRANCH=10.10.5.0/27" -AllowCidr -Out .\out
```

`10.10.5.0/27` is a 32-host block; excluding the network address (`10.10.5.0`) and the broadcast
address (`10.10.5.31`), this expands `%BRANCH%` to the 30 usable host addresses `10.10.5.1`
through `10.10.5.30`. Every `Target` (or `Source`) row that references `%BRANCH%` is expanded once
per address, so a profile with two rows referencing `%BRANCH%` produces 60 probe targets from this
one binding, counted against the cap exactly like any other expansion.

## 5. `Required` semantics and the exit rule

`Required: yes` means: if this row's probe does not come back `Pass`, the whole run exits non-zero.
`Required: no` means the row is still probed and still reported, but its outcome never fails the
run. This matters most for UDP: because a UDP probe can only be closed off (an ICMP port-unreachable
comes back) or left in doubt (silence, which PortProof reports as `Open|Filtered` rather than
guessing `Open`), a "silent" UDP row is classified `Inconclusive`, and **`Inconclusive` on a
required row still fails the run** - PortProof will not report success on a promise it cannot
verify. Every bundled UDP row is therefore `Required: no`, with a `Notes` value saying so, so an
operator who wants a UDP row to gate the exit code makes that choice explicitly rather than
inheriting a bundled default that can never pass on a strict reading.

## 6. The row-number convention

CSV and JSON number rows **differently**, and both a profile's own error messages and its
provenance sidecar follow the CSV convention. This section states both, because a reader moving
between a CSV error, a JSON error, and a sidecar entry for the same logical row needs the mapping.

- **CSV convention:** the header line counts as row 1, so the file's first
  data row is row 2, its second data row is row 3, and so on - "the record number counting the
  header as row 1, so it matches Excel" (where row 1 in the spreadsheet view is also the header).
  Every `Profile.*`/`Group.*`/`RefusedTargetClass` error raised while reading a CSV profile names
  a row number in this convention.
- **JSON convention:** there is no header line, so JSON rows are numbered by
  a plain 1-based index into the `rows` array: the first element (`rows[0]`) is row 1, printed in
  error messages as `row <n> (rows[<n-1>])`.

**The two numbers differ by exactly one for the same logical data row** (CSV row *k* <-> JSON row
*k-1*, both naming the same tuple), because a bundled profile's CSV and JSON files carry identical
rows in identical order (section "CSV and JSON" above) but only the CSV file has a header line to
offset against.

**Provenance sidecars use the CSV convention.** Every `profiles/<name>.provenance.json`'s
`rows[].row` value is a CSV row number (header = row 1, first data row = row 2; `"row": 2` for a
profile's first data row) and each sidecar's
`row_numbering` field states this explicitly. To find the sidecar entry for a **JSON** parse
error reporting `row <n> (rows[<n-1>])`, look up sidecar row `<n+1>`.

## 7. Encodings accepted

No byte-order mark: UTF-8. `EF BB BF`: UTF-8 (mark present but redundant). `FF FE`: UTF-16LE.
`FE FF`: UTF-16BE. `FF FE 00 00` or `00 00 FE FF`: UTF-32 - refused outright
(`Profile.Encoding`) rather than decoded, since it is never PortProof's own output and is very
rarely a profile author's intent. A decode failure under strict (`throwOnInvalidBytes`) decoding,
or a decoded U+0000 anywhere in the text (the signature of UTF-16 text read as if it were UTF-8),
is refused with the same id and a "save the profile as UTF-8" message.

## 8. Unknown-column / unknown-key policy, summarised

The policy is deliberately asymmetric between "shape" and "content":

- An unrecognised **top-level JSON key**, an unrecognised **JSON row key**, or a **duplicate CSV
  column name** is a hard error (`Profile.UnknownKey` / `Profile.DuplicateColumn`): these change
  the shape of the document, and a silent guess about what they meant would be worse than refusing.
- An unrecognised **CSV column** is not an error: CSV has no equivalent of a nested/typed key, and
  operators routinely export profiles from a spreadsheet that carries extra columns (an internal
  ticket number, a change-window reference). Those columns are preserved in nothing, are never
  rendered, and are named back to the operator via `IgnoredColumns` in the run header so their
  absence from the report is not a silent surprise; a column whose name looks like a secret is
  flagged in that same warning.
