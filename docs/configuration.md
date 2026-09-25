<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Configuration: `nikasha.toml`

Nikasha runs with no configuration at all. A `nikasha.toml` lets a project pin what it
already knows about itself (name, clone URL, aliases, sandbox recipe, HackerOne program),
tune the verdict thresholds and the prior, replace the wording of questions to reporters,
exclude paths from judgement, and switch the optional LLM on. Every key is optional. The
default listed for each key below is what the tool uses when the key is absent, and a file
with no keys at all is a complete, working configuration.

A commented copy to start from is in [`examples/nikasha.toml`](https://github.com/rakshit-737/nikasha/blob/main/examples/nikasha.toml).

## Where the file is looked for

Three files are read, lowest precedence first, and merged key by key:

| Layer | Location | Typical use |
|---|---|---|
| user | `<config dir>/nikasha.toml`: `~/.config/nikasha/` on Linux, `~/Library/Application Support/nikasha/` on macOS, `%LOCALAPPDATA%\nikasha\` on Windows | personal defaults such as a local LLM |
| repository | the nearest `nikasha.toml` found by walking up from the working directory, stopping after the first directory that contains `.git` | the project's own settings, committed next to its code |
| explicit | `--config PATH` | a one-off override; the file must exist |

A key set in a later layer replaces the same key from an earlier one, and keys the later
file does not mention are kept. Tables merge (`[thresholds]` from two files combine), arrays
replace (`ignore.paths` in the repository file replaces the user's list rather than
extending it), and `[questions]` overrides from every layer are kept; when two layers name
the same key, the later layer's template wins. Inside one file, writing the same key both
ways (`"C03.a" = "..."` and `[questions.C03]` with `a = "..."`) is an error, because TOML
treats them as different keys and would otherwise let the last one win silently.

The `.git` boundary is what keeps a `nikasha.toml` in a parent checkout, or in the home
directory, from applying to an unrelated repository below it. A `.git` *file* (a worktree)
is a boundary too, and the directory holding it is still searched.

## Trust model

The repository-level file is trusted exactly like a `Makefile` in that checkout: whoever can
commit to the repository you run Nikasha *in* can set its thresholds, its prior, its
question wording and its LLM switch, and a pull request that edits `nikasha.toml` deserves
the same review as one that edits the build. The search only ever looks at the working
directory's ancestors, the user directory and `--config`, and it always starts from a
directory, never from the report being checked.
Configuration is never taken from report input: a `nikasha.toml` unpacked next to a report, inside an attachment archive, or inside
a repository that Nikasha cloned to check a report is never read, because all of those are
chosen by the report (P7). Passing a file as the start directory is refused outright.

Even a trusted file is not code: values are validated against a closed schema, and a
`[questions]` template runs in a sandbox (below). What a hostile file *can* do is loosen
the verdict ladder, which is why the thresholds and the prior are recorded in every result.

## Strictness

- **Unknown keys are errors.** A typo cannot silently do nothing:

  ```text
  /home/me/libhdr/nikasha.toml: unknown key thresholds.grounded
  /home/me/libhdr/nikasha.toml: unknown key prior (sections: project, thresholds, scoring, questions, ignore, llm, hackerone)
  ```

- **Every error names the file and the key**, including type errors and out-of-range values
  (`nikasha.toml: scoring.prior: Input should be a finite number`). A conflict that only
  appears once files are combined, each valid on its own, names every file involved.
- The file must be UTF-8 (a byte-order mark is tolerated), at most 1 MiB, and nested no
  deeper than the schema. A file that breaks any of these is refused with a plain message,
  never a traceback.
- **The environment never sets a value in this file and can never enable a cloud LLM**
  (P3, below). The only environment influence is `platformdirs` choosing the user
  configuration directory (`XDG_CONFIG_HOME` on Linux), so the file read there is still one
  the user wrote; `NIKASHA_CACHE_DIR` moves the cache and nothing else.
- **Free text is plain text.** `project.name`, `project.aliases`, `project.repo` and
  `ignore.paths` refuse control characters and the invisible or direction-changing code
  points (zero-width joiners, bidirectional overrides and isolates, the byte-order mark)
  that could visually reorder a question sent to a reporter or a rendered report.

## `[project]`

What the repository this file lives in is called and where it is. With `name` set, the
section acts like an entry in `known_projects.yaml` for this one project.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | none | The product name reports use, and what questions call it. 1 to 100 printable characters. |
| `repo` | string | none | Where to clone from when a report does not say: an `https://`, `http://`, `ssh://` or `git+ssh://` URL, an scp-style `user@host:path`, or a local path (`/srv/x`, `./x`, `C:\x`). No whitespace, and it cannot start with `-`. `file://`, `git://` and git's `<helper>::` transports (`ext::`, `fd::`) are refused here, before git sees them. |
| `aliases` | array of strings | `[]` | Other names reports use for the product. `name` itself is always included. At most 64. |
| `recipe` | string | none | The sandbox recipe used with `--repro` (see `nikasha recipes list`). Letters, digits, `.`, `_` and `-`. |

## `[thresholds]`

Every number the verdict ladder (SPEC §14.3) makes configurable. The defaults are the
calibrated ones and are read from `nikasha.fuse.verdict.Thresholds`, so this table and the
code cannot drift apart. Raising an `ungrounded_*` score makes the hardest verdict easier to
reach: the false-UNGROUNDED rate behind P4 was measured with the defaults, not with a
loosened file, so change them with the bench in hand.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ungrounded_score` | integer 0 to 100 | `15` | Rule 3a: UNGROUNDED needs a grounding score below this, plus a core locus that never existed, corroborated across groups. |
| `ungrounded_score_strict` | integer 0 to 100 | `10` | Rule 3b: UNGROUNDED from strong refutations alone needs a score below this. Must not exceed `ungrounded_score`. |
| `ungrounded_core_strength` | number, at most 0 | `-2.0` | A "never existed" finding counts as core only at or below this strength. |
| `ungrounded_core_groups` | integer, at least 1 | `2` | Rule 3a needs refutations from at least this many independent evidence groups. |
| `ungrounded_strong_strength` | number, at most 0 | `-1.5` | A refutation counts as strong at or below this strength. |
| `ungrounded_strong_groups` | integer, at least 1 | `3` | Rule 3b needs strong refutations from at least this many groups. |
| `grounded_score` | integer 0 to 100 | `75` | Rule 5: GROUNDED needs at least this score. Must be above `ungrounded_score`. |
| `grounded_max_refutation` | number, at most 0 | `-1.2` | Rule 5: GROUNDED also needs every piece of evidence to be *above* this strength. |
| `min_checkable_claims` | integer, at least 0 | `2` | Rule 2: fewer checkable claims than this, with no trace, snippet, patch or PoC, is INSUFFICIENT. |
| `insufficient_total` | number, at least 0 | `1.5` | Rule 6: a total absolute evidence weight below this is INSUFFICIENT rather than MIXED. |

`nan` and `inf` are refused everywhere: nothing that feeds a verdict may be undefined.

## `[scoring]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `prior` | number, -10 to 10 | `0.0` | The log-odds the score starts from before any evidence. `0.0` is "no opinion"; a program whose reports are usually valid might use a small positive number. Recorded in every result's ledger. |
| `calibration` | path | none (the bundled `lr_defaults.yaml`) | A calibrated strengths table (SPEC §14.2): a YAML file with `version` and `checks`. Relative paths are resolved against the file that names it, and the file must exist. The table's name is recorded in every result. |

## `[questions]`

Replaces the wording of a question to the reporter. Keys are `"<check>.<outcome>"`, the
same names as the bundled templates in `src/nikasha/fuse/questions/` (for example
`"C03.never_in_history_core"`). A key that names no bundled question is an error, so a
misspelt outcome cannot become an override that never applies. Quote the key, or write it
as a sub-table: `[questions.C03]` with `never_in_history_core = "..."` means the same thing.
Using both spellings for one key in one file is an error ("given twice"), because TOML
would otherwise let one of them win silently.

The value is a Jinja template with the same variables as the bundled one (`where`,
`target`, `path`, `symbol`, `permalink` and whatever the check recorded) and the same
filters (`ranged`, `listed`, `short`). The closing line ("Thanks for the report...") is
added for you. A template that does not compile is an error, and so is one longer than
2000 characters.

An override is compiled, and rendered, in a **sandbox** (`jinja2`'s
`ImmutableSandboxedEnvironment`, via `nikasha.settings.override_environment()`), not in
the plain environment the bundled templates use. The sandbox refuses attribute access into
Python internals and any mutation of its inputs, so a template cannot become code. Two
further rules apply when the file is loaded, because the sandbox only acts when a template
is rendered: a template containing `__` anywhere is refused ("template uses a restricted
attribute"), and a template must be self-contained, with no `include`, `extends` or
`import`.

The tone rules for questions (SPEC §14.4) apply to overrides exactly as they apply to the
bundled text: name the file, the symbol or the release, and ask about *that*. A template
containing one of the words the bundled templates are tested against, words that describe
the author rather than the claim, is refused, and the error names the word (P1).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `"<check>.<outcome>"` | string | none | The template for that check outcome. At most 256 overrides. |

## `[ignore]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `paths` | array of globs | `[]` | Repository paths that are never judged, matched against repo-relative paths with the same dialect as `known_projects.yaml`: `*` stays inside one path component, `**` crosses components, `?` is one character, and a glob without a slash matches the file name anywhere (`config.h` also covers `build/config.h`). Forward slashes only. At most 512. Matching takes time linear in the glob and the path, whatever the glob. |

An ignored path is treated like a generated file: a claim about it is neither confirmed nor
refuted (P4).

## `[llm]`

The optional assistant (SPEC §16.6). It is off unless a provider is named, it is never
decisive, and every verdict is reproducible without it (P2).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `provider` | string | `"none"` | One of `none`, `ollama`, `anthropic`, `openai`, optionally followed by `:MODEL` (`"ollama:llama3.1:8b"`). |
| `allow_cloud` | boolean | `false` | Whether `anthropic` and `openai`, which send report text off this machine, may be used at all. |
| `model` | string | none | The model, when it is not given after the colon in `provider`. When both are given, `model` wins. |

**`allow_cloud` is the P3 switch.** It is a strict boolean: only a literal `true` in one of
the three files turns it on. `"true"` and `1` are refused, a `--llm` flag cannot set it,
and the environment never sets a value in this file and can never enable a cloud LLM (the
only environment influence is `platformdirs` choosing the user configuration directory), so
a report under embargo cannot reach a cloud provider by accident. When it is on, every run
prints a confidentiality warning.

## `[hackerone]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `program` | string | none | The program handle whose reports `nikasha h1` checks against this repository. Letters, digits, `_` and `-`. |

API credentials are not configuration and never go in this file.

## Using the settings from Python

```python
from pathlib import Path

from nikasha.settings import config_files, load_settings

settings = load_settings()                                  # working directory, user file
settings = load_settings(Path("/srv/libhdr"), Path("custom.toml"))  # start dir, --config
config_files()                                              # the files that would be read

settings.thresholds()          # nikasha.fuse.verdict.Thresholds, for decide()
settings.prior()               # float, for fuse()
settings.strengths()           # nikasha.checks.strengths.Strengths (bundled or calibrated)
settings.project_entry()       # nikasha.resolve.products.KnownProject, or None without a name
settings.is_ignored("vendor/zlib/inflate.c")
settings.question_overrides()  # {"C03.never_in_history_core": "..."}, sorted by key
settings.llm.provider_name, settings.llm.model_name, settings.llm.is_cloud
```

`start` is always a directory (the working directory when omitted); a report file, or its
directory, is never passed there. `Settings` is a frozen, hashable pydantic model with
`extra="forbid"`. The `[thresholds]` table is the `limits` attribute (an alias), because
`thresholds()` is the method that returns the dataclass the fusion layer takes;
`model_dump(by_alias=True)` gives the file's own key names back. `[questions]` is stored as
`questions`, a tuple of `(key, template)` pairs sorted by key; `question_overrides()` is the
dictionary view, and whatever renders one of those templates must do so in
`override_environment()`. Every failure raises `nikasha.settings.SettingsError`, a
`NikashaError`, which the CLI turns into exit code 1 with the message and nothing else.
