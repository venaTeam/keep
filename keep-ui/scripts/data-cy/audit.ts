/// <reference types="node" />
/**
 * data-cy audit script.
 *
 * Walks the keep-ui source tree, extracts every `data-cy` attribute (literal
 * or templated), enriches the entries from a sidecar YAML, and writes a
 * manifest JSON plus a regenerated markdown summary.
 *
 * Modes:
 *   --write          (default) regenerate manifest.json + docs/data-cy-selectors.md
 *   --check          exit 1 if running --write would change the manifest
 *   --check-mirror   warn (do not fail) about data-testid / data-cy mismatches
 *
 * Run with:
 *   npm run audit:data-cy
 *   npm run audit:data-cy -- --check
 *   npm run audit:data-cy -- --check-mirror
 */

import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import * as yaml from "yaml";

// Resolve project root (keep-ui/) regardless of where ts-node is invoked from.
const ROOT = path.resolve(__dirname, "..", "..");
const MANIFEST_PATH = path.join(ROOT, "scripts", "data-cy", "manifest.json");
const DESCRIPTIONS_PATH = path.join(
  ROOT,
  "scripts",
  "data-cy",
  "manifest.descriptions.yaml"
);
const SELECTORS_DOC_PATH = path.join(ROOT, "docs", "data-cy-selectors.md");

const SOURCE_DIRS = ["app", "components", "widgets", "features", "shared"];
const SOURCE_EXTENSIONS = new Set([".tsx", ".jsx"]);

interface SidecarEntry {
  description?: string;
  idSource?: string;
  resolvedExample?: string;
}

type SidecarMap = Record<string, SidecarEntry>;

interface SelectorEntry {
  selector: string;
  resolvedExample?: string;
  area: string;
  role: string;
  dynamic: boolean;
  idSource?: string;
  file: string;
  line: number;
  description: string;
  mirrorsDataTestId: boolean;
}

interface Manifest {
  version: string;
  generatedAt: string;
  totalSelectors: number;
  byArea: Record<string, number>;
  selectors: SelectorEntry[];
}

interface MirrorWarning {
  file: string;
  line: number;
  kind: "missing-cy" | "value-mismatch";
  testId?: string;
  cy?: string;
}

// -----------------------------------------------------------------------------
// CLI argument parsing
// -----------------------------------------------------------------------------

function parseArgs(argv: string[]): {
  write: boolean;
  check: boolean;
  checkMirror: boolean;
} {
  const flags = new Set(argv.slice(2));
  const check = flags.has("--check");
  const checkMirror = flags.has("--check-mirror");
  // --write is the default. --check implies "do not write".
  const write = !check;
  return { write, check, checkMirror };
}

// -----------------------------------------------------------------------------
// File walking
// -----------------------------------------------------------------------------

function walk(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SOURCE_EXTENSIONS.has(ext)) out.push(full);
    }
  }
}

function listSourceFiles(): string[] {
  const out: string[] = [];
  for (const sub of SOURCE_DIRS) {
    walk(path.join(ROOT, sub), out);
  }
  return out;
}

// -----------------------------------------------------------------------------
// Selector extraction
// -----------------------------------------------------------------------------

// Match `data-cy="literal"` and `data-cy={'literal'}` and `data-cy={"literal"}`.
const LITERAL_RE = /data-cy=(?:"([^"]+)"|\{\s*['"]([^'"]+)['"]\s*\})/g;
// Match `data-cy={`...${expr}...`}` (template literal).
const TEMPLATE_RE = /data-cy=\{\s*`([^`]+)`\s*\}/g;
// Match `data-testid` in any of the same forms (used for mirror checks).
const TESTID_RE =
  /data-testid=(?:"([^"]+)"|\{\s*['"]([^'"]+)['"]\s*\}|\{\s*`([^`]+)`\s*\})/g;

function lineFromIndex(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === "\n") line++;
  }
  return line;
}

/**
 * Determine whether the byte at `index` falls inside a single-line `//` or a
 * `/* ... *\/` block comment. We use a coarse but cheap heuristic: scan the
 * surrounding line for `//` before the index, and walk backward for an
 * unclosed `/*`. Good enough to drop placeholder matches in author comments.
 */
function isInsideComment(source: string, index: number): boolean {
  // // line comment: walk back to start of line, look for "//" before index.
  let lineStart = index;
  while (lineStart > 0 && source[lineStart - 1] !== "\n") lineStart--;
  const line = source.slice(lineStart, index);
  if (line.includes("//")) return true;

  // /* block comment: find last "/*" before index, see if "*/" closes it.
  const openIdx = source.lastIndexOf("/*", index);
  if (openIdx !== -1) {
    const closeIdx = source.indexOf("*/", openIdx + 2);
    if (closeIdx === -1 || closeIdx > index) return true;
  }
  return false;
}

function relPath(absolutePath: string): string {
  return path.relative(ROOT, absolutePath).split(path.sep).join("/");
}

interface RawMatch {
  selector: string;
  dynamic: boolean;
  file: string; // relative to keep-ui
  line: number;
  index: number;
  testIdOnSameLine?: string;
}

function extractMatches(): RawMatch[] {
  const files = listSourceFiles();
  const matches: RawMatch[] = [];

  for (const file of files) {
    let source: string;
    try {
      source = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relPath(file);

    // Literal matches.
    let m: RegExpExecArray | null;
    LITERAL_RE.lastIndex = 0;
    while ((m = LITERAL_RE.exec(source)) !== null) {
      const value = m[1] ?? m[2];
      if (!value) continue;
      if (isInsideComment(source, m.index)) continue;
      matches.push({
        selector: value,
        dynamic: false,
        file: rel,
        line: lineFromIndex(source, m.index),
        index: m.index,
        testIdOnSameLine: findNearbyTestId(source, m.index),
      });
    }

    // Template-literal matches (treated as dynamic).
    TEMPLATE_RE.lastIndex = 0;
    while ((m = TEMPLATE_RE.exec(source)) !== null) {
      const raw = m[1];
      if (!raw) continue;
      if (isInsideComment(source, m.index)) continue;
      matches.push({
        selector: raw,
        dynamic: raw.includes("${"),
        file: rel,
        line: lineFromIndex(source, m.index),
        index: m.index,
        testIdOnSameLine: findNearbyTestId(source, m.index),
      });
    }
  }

  return matches;
}

function findNearbyTestId(source: string, cyIndex: number): string | undefined {
  // Look at the surrounding "JSX element" by scanning a small window around
  // the data-cy attribute. We pick the closest data-testid within 400 chars
  // before or after on the same element opening.
  const WINDOW = 400;
  const start = Math.max(0, cyIndex - WINDOW);
  const end = Math.min(source.length, cyIndex + WINDOW);
  const slice = source.slice(start, end);
  TESTID_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  let best: { value: string; distance: number } | undefined;
  const localCyIndex = cyIndex - start;
  while ((m = TESTID_RE.exec(slice)) !== null) {
    const value = m[1] ?? m[2] ?? m[3];
    if (!value) continue;
    const distance = Math.abs(m.index - localCyIndex);
    if (!best || distance < best.distance) {
      best = { value, distance };
    }
  }
  return best?.value;
}

// -----------------------------------------------------------------------------
// Sidecar loading
// -----------------------------------------------------------------------------

function loadSidecar(): SidecarMap {
  if (!fs.existsSync(DESCRIPTIONS_PATH)) return {};
  const text = fs.readFileSync(DESCRIPTIONS_PATH, "utf8");
  const parsed = yaml.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const map: SidecarMap = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      map[key] = value as SidecarEntry;
    }
  }
  return map;
}

// -----------------------------------------------------------------------------
// Selector parsing helpers
// -----------------------------------------------------------------------------

function parseAreaAndRole(selector: string): { area: string; role: string } {
  // If the leading segment is itself a template expression (e.g.
  // "${cyPrefix}-prev"), the area is consumer-supplied at runtime. Mark it
  // as "(dynamic)" so it doesn't pollute the byArea histogram.
  if (/^\$\{[^}]*\}/.test(selector)) {
    const tail = selector.replace(/^\$\{[^}]*\}-?/, "");
    const parts = tail.split("-").filter(Boolean);
    return { area: "(dynamic)", role: parts[0] ?? "" };
  }
  // For dynamic selectors like "wf-tile-${id}", strip the trailing template
  // expression for parsing purposes.
  const cleaned = selector.replace(/\$\{[^}]*\}/g, "").replace(/-+$/g, "");
  const parts = cleaned.split("-").filter(Boolean);
  const area = parts[0] ?? "";
  const role = parts[1] ?? "";
  return { area, role };
}

// -----------------------------------------------------------------------------
// Manifest building
// -----------------------------------------------------------------------------

function gitSha(): string {
  try {
    const sha = execSync("git rev-parse HEAD", {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    return sha || "dev";
  } catch {
    return "dev";
  }
}

function buildManifest(
  matches: RawMatch[],
  sidecar: SidecarMap,
  generatedAt: string,
  version: string
): Manifest {
  const selectors: SelectorEntry[] = matches.map((m) => {
    const { area, role } = parseAreaAndRole(m.selector);
    const sideKey = m.selector;
    const side = sidecar[sideKey] ?? {};
    const mirrors =
      m.testIdOnSameLine !== undefined && m.testIdOnSameLine === m.selector;
    const entry: SelectorEntry = {
      selector: m.selector,
      area,
      role,
      dynamic: m.dynamic,
      file: m.file,
      line: m.line,
      description: side.description ?? "",
      mirrorsDataTestId: mirrors,
    };
    if (m.dynamic && side.idSource) entry.idSource = side.idSource;
    if (m.dynamic && side.resolvedExample) {
      entry.resolvedExample = side.resolvedExample;
    }
    return entry;
  });

  // Stable order: by area, then by file, then by line, then by selector.
  selectors.sort((a, b) => {
    if (a.area !== b.area) return a.area.localeCompare(b.area);
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if (a.line !== b.line) return a.line - b.line;
    return a.selector.localeCompare(b.selector);
  });

  const byArea: Record<string, number> = {};
  for (const s of selectors) {
    if (!s.area) continue;
    byArea[s.area] = (byArea[s.area] ?? 0) + 1;
  }

  return {
    version,
    generatedAt,
    totalSelectors: selectors.length,
    byArea,
    selectors,
  };
}

// -----------------------------------------------------------------------------
// Markdown rendering
// -----------------------------------------------------------------------------

function renderMarkdown(manifest: Manifest): string {
  const lines: string[] = [];
  lines.push("# data-cy selectors");
  lines.push("");
  lines.push(
    "This file is auto-generated by `scripts/data-cy/audit.ts` from the"
  );
  lines.push(
    "`scripts/data-cy/manifest.json` artifact. Do not edit by hand."
  );
  lines.push("");
  lines.push(`Manifest version: \`${manifest.version}\``);
  lines.push(`Total selectors: ${manifest.totalSelectors}`);
  lines.push("");
  lines.push("To regenerate locally:");
  lines.push("");
  lines.push("```");
  lines.push("npm run audit:data-cy");
  lines.push("```");
  lines.push("");
  lines.push("To verify the manifest is up to date in CI:");
  lines.push("");
  lines.push("```");
  lines.push("npm run audit:data-cy -- --check");
  lines.push("```");
  lines.push("");
  lines.push("## Selectors by area");
  lines.push("");

  if (manifest.totalSelectors === 0) {
    lines.push("_(Empty. Populated by PRs 1-8.)_");
    lines.push("");
    return lines.join("\n");
  }

  // Group by area.
  const byArea = new Map<string, SelectorEntry[]>();
  for (const s of manifest.selectors) {
    const key = s.area || "(unknown)";
    if (!byArea.has(key)) byArea.set(key, []);
    byArea.get(key)!.push(s);
  }
  const areas = Array.from(byArea.keys()).sort();
  for (const area of areas) {
    const entries = byArea.get(area)!;
    lines.push(`### ${area} (${entries.length})`);
    lines.push("");
    lines.push("| Selector | Role | Dynamic | File:Line | Description |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const s of entries) {
      const selector = s.dynamic
        ? "`" + s.selector + "`" + (s.resolvedExample ? ` (e.g. \`${s.resolvedExample}\`)` : "")
        : "`" + s.selector + "`";
      const desc = s.description.replace(/\|/g, "\\|");
      lines.push(
        `| ${selector} | ${s.role || "-"} | ${s.dynamic ? "yes" : "no"} | ${s.file}:${s.line} | ${desc} |`
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

// -----------------------------------------------------------------------------
// Mirror warnings
// -----------------------------------------------------------------------------

function collectMirrorWarnings(matches: RawMatch[]): MirrorWarning[] {
  const warnings: MirrorWarning[] = [];
  // For each match, if data-testid was found nearby and is different from
  // data-cy, warn. We don't here detect "data-testid without data-cy" because
  // that would require a second walk; we do that in scanMissingMirrors.
  for (const m of matches) {
    if (m.testIdOnSameLine && m.testIdOnSameLine !== m.selector) {
      warnings.push({
        file: m.file,
        line: m.line,
        kind: "value-mismatch",
        testId: m.testIdOnSameLine,
        cy: m.selector,
      });
    }
  }
  return warnings;
}

function scanMissingMirrors(): MirrorWarning[] {
  const warnings: MirrorWarning[] = [];
  const files = listSourceFiles();
  for (const file of files) {
    let source: string;
    try {
      source = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relPath(file);
    TESTID_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TESTID_RE.exec(source)) !== null) {
      const testId = m[1] ?? m[2] ?? m[3];
      if (!testId) continue;
      const nearbyCy = findNearbyDataCy(source, m.index);
      if (!nearbyCy) {
        warnings.push({
          file: rel,
          line: lineFromIndex(source, m.index),
          kind: "missing-cy",
          testId,
        });
      }
    }
  }
  return warnings;
}

function findNearbyDataCy(source: string, testIdIndex: number): string | undefined {
  const WINDOW = 400;
  const start = Math.max(0, testIdIndex - WINDOW);
  const end = Math.min(source.length, testIdIndex + WINDOW);
  const slice = source.slice(start, end);
  LITERAL_RE.lastIndex = 0;
  if (LITERAL_RE.exec(slice)) return "1";
  TEMPLATE_RE.lastIndex = 0;
  if (TEMPLATE_RE.exec(slice)) return "1";
  return undefined;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

function main(): void {
  const { write, check, checkMirror } = parseArgs(process.argv);

  const matches = extractMatches();
  const sidecar = loadSidecar();
  const generatedAt = new Date().toISOString();
  const version = gitSha();

  const manifest = buildManifest(matches, sidecar, generatedAt, version);
  const newManifestJson = JSON.stringify(manifest, null, 2) + "\n";
  const newMarkdown = renderMarkdown(manifest);

  if (check) {
    // Compare to existing files but ignore the volatile `generatedAt` and
    // `version` fields so a clean tree on a fresh sha doesn't fail.
    const existing = fs.existsSync(MANIFEST_PATH)
      ? (JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8")) as Manifest)
      : null;
    const existingNormalised = existing
      ? { ...existing, generatedAt: "<n>", version: "<v>" }
      : null;
    const candidateNormalised = { ...manifest, generatedAt: "<n>", version: "<v>" };

    const existingDoc = fs.existsSync(SELECTORS_DOC_PATH)
      ? fs.readFileSync(SELECTORS_DOC_PATH, "utf8")
      : "";
    const docMatches = stripVolatile(existingDoc) === stripVolatile(newMarkdown);

    if (
      JSON.stringify(existingNormalised) === JSON.stringify(candidateNormalised) &&
      docMatches
    ) {
      console.log(`audit:data-cy ok (${manifest.totalSelectors} selectors)`);
    } else {
      console.error(
        "audit:data-cy --check FAILED: manifest or selectors doc is out of date."
      );
      console.error(
        "Run `npm run audit:data-cy` to regenerate, then commit the result."
      );
      process.exit(1);
    }
  }

  if (write) {
    fs.mkdirSync(path.dirname(MANIFEST_PATH), { recursive: true });
    fs.writeFileSync(MANIFEST_PATH, newManifestJson, "utf8");
    fs.mkdirSync(path.dirname(SELECTORS_DOC_PATH), { recursive: true });
    fs.writeFileSync(SELECTORS_DOC_PATH, newMarkdown, "utf8");
    console.log(
      `audit:data-cy wrote ${manifest.totalSelectors} selectors across ${
        Object.keys(manifest.byArea).length
      } area(s)`
    );
  }

  if (checkMirror) {
    const inline = collectMirrorWarnings(matches);
    const missing = scanMissingMirrors();
    const all = [...inline, ...missing];
    if (all.length === 0) {
      console.log("audit:data-cy --check-mirror: no mirror issues found.");
    } else {
      console.warn(`audit:data-cy --check-mirror: ${all.length} warning(s)`);
      for (const w of all) {
        if (w.kind === "missing-cy") {
          console.warn(
            `  [missing-cy] ${w.file}:${w.line} data-testid="${w.testId}" has no nearby data-cy`
          );
        } else {
          console.warn(
            `  [mismatch]   ${w.file}:${w.line} data-testid="${w.testId}" vs data-cy="${w.cy}"`
          );
        }
      }
      // PR 0 policy: do not fail on mirror warnings, just report.
    }
  }
}

function stripVolatile(text: string): string {
  return text.replace(/Manifest version: `[^`]+`\n/, "");
}

main();
