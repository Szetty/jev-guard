// The user's own permission settings for the agent that is about to make a call. Jev judges risk better when
// it knows the user has already reviewed and pre-approved a command ("Bash(bin/deploy.sh *)") or has
// deliberately set it to ask or deny. Each agent keeps these rules in its own format and matches them its own
// way; this reads them, matches the call with that agent's semantics, and summarizes the result for Jev:
//
//   Claude Code  ~/.claude/settings.json, <root>/.claude/settings.json, <root>/.claude/settings.local.json
//                permissions.{allow,ask,deny}: "Bash(npm run *)", "Bash(git log:*)", "Edit(src/**)", "Read"
//                precedence: deny > ask > allow
//   OpenCode     ~/.config/opencode/opencode.json[c], opencode.json[c] and .opencode/opencode.json[c] from the
//                project root down to cwd; permission.<tool> = action | {pattern: action}; last match wins
//   Codex        ~/.codex/rules/*.rules, <root>/.codex/rules/*.rules: prefix_rule(pattern=[...], decision=...)
//                precedence: the most restrictive matching rule
//   Cursor CLI   ~/.cursor/cli-config.json, <root>/.cursor/cli.json: permissions.{allow,deny}: "Shell(git)",
//                "Shell(curl:*)"; deny wins
//   Gemini CLI   ~/.gemini/settings.json, <root>/.gemini/settings.json: tools.allowed "run_shell_command(git)",
//                tools.exclude; ~/.gemini/policies/*.toml [[rule]] commandPrefix/decision (workspace policies are
//                ignored by Gemini itself, so they are skipped here too)
//
// Copilot CLI keeps approvals only in ~/.copilot/permissions-config.json, in an undocumented format; not read.
// Reading never throws: a missing or malformed file contributes no rules.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const AGENTS = ["claude", "opencode", "codex", "cursor", "gemini"];
const SHELL_TOOLS = new Set(["bash", "shell", "run_shell_command", "run_terminal_cmd", "exec_command", "execute_command",
  "local_shell", "terminal", "beforeshellexecution", "container.exec", "shell_command"]);
const MAX_CONFIGURED = 20;
// Command substitution or process substitution can run a second command inside one that looks allowed.
const HIDDEN_COMMAND = /\$\(|`|<\(|>\(/;
const MAX_RULE = 160;

/** The shell command a tool call would run, or undefined for non-shell calls. */
export function shellCommand(tool, input) {
  const name = String(tool ?? "").toLowerCase();
  const raw = input?.command ?? input?.cmd ?? (SHELL_TOOLS.has(name) ? input?.script : undefined);
  if (Array.isArray(raw)) {  // Codex: ["bash", "-lc", "<script>"]
    const [sh, flag, script] = raw;
    if (raw.length === 3 && /(^|\/)(ba|z|da)?sh$/.test(String(sh)) && /^-l?c$/.test(String(flag))) return String(script);
    return raw.map(String).join(" ");
  }
  if (typeof raw === "string" && (SHELL_TOOLS.has(name) || input?.command !== undefined)) return raw;
  return undefined;
}

/**
 * Permission context for one call. `agent` picks which agent's settings apply; unknown or adapter-only agents
 * (acp, pi, agy, the `check` CLI) get every agent's rules, labelled per agent.
 * @returns {undefined | {agent: string, command?: string, effective: Record<string,string>, matched: object[], configured: string[]}}
 */
export function agentPermissions({ agent, tool, input, cwd }, { home = homedir() } = {}) {
  const agents = AGENTS.includes(agent) ? [agent] : AGENTS;
  const command = shellCommand(tool, input);
  const roots = projectDirs(cwd ?? process.cwd());
  const effective = {};
  const matched = [];
  const configured = [];
  for (const a of agents) {
    const rules = readRules(a, roots, home);
    const relevant = rules.filter((r) => (command !== undefined ? r.kind === "shell" : r.kind === "tool" && toolMatches(r.tool, tool)));
    if (!relevant.length) continue;
    // A rule covers a chained command only if it covers every part ("a && b", "a; b", "a | b"), as Claude Code and Codex do.
    const parts = command !== undefined ? splitCompound(command) : [];
    const hits = relevant.filter((r) => (command !== undefined ? parts.length > 0 && parts.every((c) => !HIDDEN_COMMAND.test(c) && r.match(c)) : true));
    effective[a] = combine(a, hits);
    for (const r of hits) matched.push({ agent: a, rule: clip(r.rule), decision: r.decision, broad: r.broad, file: tilde(r.file, home) });
    for (const r of relevant) configured.push(`${a}: ${r.decision} ${clip(r.rule)}${r.broad ? " (broad)" : ""} [${tilde(r.file, home)}]`);
  }
  // Only a specific rule covering this call says anything about it. Broad rules ("*", bare "Bash", "bash": "ask")
  // apply to every command alike; showing them nudged Jev's scores for unrelated commands, so they stay out.
  if (!matched.some((m) => !m.broad)) return undefined;
  return {
    agent: agents.length === 1 ? agents[0] : "unknown (all agents shown)",
    ...(command !== undefined ? { command: clip(command, 400) } : {}),
    effective,
    matched,
    configured: configured.slice(-MAX_CONFIGURED),
  };
}

// ── precedence ──────────────────────────────────────────────────────────────────────────────────────────────
const RANK = { deny: 3, ask: 2, allow: 1 };
function combine(agent, hits) {
  if (!hits.length) return "none";
  if (agent === "opencode") return hits.at(-1).decision;  // last matching rule wins
  return hits.reduce((a, r) => (RANK[r.decision] > RANK[a] ? r.decision : a), "allow");  // most restrictive
}

// ── per-agent readers: each returns [{kind, tool?, rule, decision, broad, file, match(cmd)}] in file order ──
function readRules(agent, roots, home) {
  const top = roots.at(-1);  // project root (git root, or cwd)
  switch (agent) {
    case "claude": return [join(home, ".claude/settings.json"), join(top, ".claude/settings.json"), join(top, ".claude/settings.local.json")].flatMap(claudeRules);
    case "opencode": return [
      ...jsonc(join(home, ".config/opencode"), "opencode"),
      ...[...roots].reverse().flatMap((d) => [...jsonc(d, "opencode"), ...jsonc(join(d, ".opencode"), "opencode")]),
    ].flatMap(opencodeRules);
    case "codex": return [join(home, ".codex/rules"), join(top, ".codex/rules")].flatMap((d) => listFiles(d, ".rules")).flatMap(codexRules);
    case "cursor": return [join(home, ".cursor/cli-config.json"), join(top, ".cursor/cli.json")].flatMap(cursorRules);
    case "gemini": return [
      ...[join(home, ".gemini/settings.json"), join(top, ".gemini/settings.json")].flatMap(geminiSettingsRules),
      ...listFiles(join(home, ".gemini/policies"), ".toml").flatMap(geminiPolicyRules),
    ];
    default: return [];
  }
}

function claudeRules(file) {
  const perms = readJson(file)?.permissions;
  if (!perms) return [];
  const out = [];
  for (const decision of ["allow", "ask", "deny"]) {
    for (const rule of Array.isArray(perms[decision]) ? perms[decision] : []) {
      const m = /^([^(]+?)(?:\((.*)\))?$/s.exec(String(rule).trim());
      if (!m) continue;
      const [, toolName, spec] = m;
      if (/^bash$/i.test(toolName)) {
        out.push({ kind: "shell", rule, decision, file, broad: spec === undefined || /^\*?$/.test(spec.trim()), match: spec === undefined ? () => true : claudeBash(spec) });
      } else {
        out.push({ kind: "tool", tool: toolName, rule, decision, file, broad: spec === undefined, match: () => true });
      }
    }
  }
  return out;
}

// "npm run test:*" (legacy prefix), "ls *" (word boundary: "ls", "ls -la", not "lsof"), "git * main" (glob)
function claudeBash(spec) {
  const s = spec.trim();
  if (s.endsWith(":*")) { const p = s.slice(0, -2); return (c) => c === p || c.startsWith(p); }
  if (s.endsWith(" *") && !s.slice(0, -2).includes("*")) { const p = s.slice(0, -2); return (c) => c === p || c.startsWith(p + " "); }
  return globMatcher(s);
}

function opencodeRules(file) {
  const perm = readJsonc(file)?.permission;
  if (!perm) return [];
  const out = [];
  if (typeof perm === "string") return [{ kind: "shell", rule: `permission: ${perm}`, decision: action(perm), file, broad: true, match: () => true },
    { kind: "tool", tool: "*", rule: `permission: ${perm}`, decision: action(perm), file, broad: true, match: () => true }];
  for (const [toolName, v] of Object.entries(perm)) {
    const shell = toolName === "bash";
    const entries = typeof v === "string" ? [["*", v]] : v && typeof v === "object" ? Object.entries(v) : [];
    for (const [pattern, act] of entries) {
      if (!action(act)) continue;
      const rule = typeof v === "string" ? `${toolName}: ${act}` : `${toolName} "${pattern}": ${act}`;
      out.push(shell
        ? { kind: "shell", rule, decision: action(act), file, broad: pattern.trim() === "*", match: globMatcher(pattern) }
        : { kind: "tool", tool: toolName, rule, decision: action(act), file, broad: pattern.trim() === "*", match: () => true });
    }
  }
  return out;
}

function codexRules(file) {
  const text = readText(file);
  if (!text) return [];
  const out = [];
  for (const block of calls(text, "prefix_rule")) {
    const pattern = starlarkList(field(block, "pattern"));
    if (!Array.isArray(pattern) || !pattern.length) continue;
    const dec = /decision\s*=\s*["'](\w+)["']/.exec(block)?.[1] ?? "allow";
    const decision = dec === "forbidden" ? "deny" : dec === "prompt" ? "ask" : dec === "allow" ? "allow" : null;
    if (!decision) continue;
    const rule = `prefix_rule(${JSON.stringify(pattern)}, ${dec})`;
    out.push({ kind: "shell", rule, decision, file, broad: false, match: (c) => tokenPrefix(splitArgs(c), pattern) });
  }
  return out;
}

function cursorRules(file) {
  const perms = readJson(file)?.permissions;
  if (!perms) return [];
  const out = [];
  for (const decision of ["allow", "deny"]) {
    for (const rule of Array.isArray(perms[decision]) ? perms[decision] : []) {
      const m = /^([^(]+?)\((.*)\)$/s.exec(String(rule).trim());
      if (!m) continue;
      const [, toolName, spec] = m;
      if (/^shell$/i.test(toolName)) {
        const [base, args] = spec.includes(":") ? [spec.slice(0, spec.indexOf(":")), spec.slice(spec.indexOf(":") + 1)] : [spec, "*"];
        const baseOk = globMatcher(base), argsOk = globMatcher(args);
        out.push({ kind: "shell", rule, decision, file, broad: base.trim() === "*", match: (c) => {
          const [first = "", ...rest] = splitArgs(c);
          return baseOk(first) && argsOk(rest.join(" "));
        } });
      } else {
        out.push({ kind: "tool", tool: toolName, rule, decision, file, broad: false, match: () => true });
      }
    }
  }
  return out;
}

function geminiSettingsRules(file) {
  const tools = readJson(file)?.tools;
  if (!tools) return [];
  const out = [];
  const add = (list, decision) => {
    for (const rule of Array.isArray(list) ? list : []) {
      const m = /^([^(]+?)(?:\((.*)\))?$/s.exec(String(rule).trim());
      if (!m) continue;
      const [, toolName, spec] = m;
      if (toolName === "run_shell_command" || toolName === "ShellTool") {
        out.push({ kind: "shell", rule, decision, file, broad: spec === undefined, match: spec === undefined ? () => true : wordPrefix(spec.trim()) });
      } else {
        out.push({ kind: "tool", tool: toolName, rule, decision, file, broad: spec === undefined, match: () => true });
      }
    }
  };
  add(tools.allowed, "allow");
  add(tools.exclude, "deny");
  return out;
}

function geminiPolicyRules(file) {
  const text = readText(file);
  if (!text) return [];
  const out = [];
  for (const block of text.split(/^\s*\[\[rule\]\]\s*$/m).slice(1)) {
    const val = (k) => new RegExp(`^\\s*${k}\\s*=\\s*"([^"]*)"`, "m").exec(block)?.[1];
    const dec = val("decision");
    const decision = dec === "allow" ? "allow" : dec === "deny" ? "deny" : dec === "ask_user" ? "ask" : null;
    if (!decision) continue;
    const prefix = val("commandPrefix");
    const toolName = val("toolName") ?? (prefix !== undefined ? "run_shell_command" : undefined);
    if (!toolName) continue;
    const rule = `[[rule]] ${toolName}${prefix !== undefined ? ` commandPrefix="${prefix}"` : ""} ${dec}`;
    out.push(toolName === "run_shell_command"
      ? { kind: "shell", rule, decision, file, broad: prefix === undefined, match: prefix === undefined ? () => true : wordPrefix(prefix) }
      : { kind: "tool", tool: toolName, rule, decision, file, broad: true, match: () => true });
  }
  return out;
}

// ── matching helpers ────────────────────────────────────────────────────────────────────────────────────────
const action = (v) => ({ allow: "allow", ask: "ask", deny: "deny" })[String(v).toLowerCase()];
const wordPrefix = (p) => (c) => c === p || c.startsWith(p + " ");
function globMatcher(pattern) {
  const re = new RegExp("^" + String(pattern).trim().replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "s");
  return (c) => re.test(c.trim());
}
function toolMatches(ruleTool, tool) {
  const a = String(ruleTool).toLowerCase(), b = String(tool ?? "").toLowerCase();
  return a === "*" || a === b || globMatcher(a)(b);
}
function tokenPrefix(tokens, pattern) {
  if (tokens.length < pattern.length) return false;
  return pattern.every((p, i) => (Array.isArray(p) ? p.map(String).includes(tokens[i]) : String(p) === tokens[i]));
}
/** Split a shell line on ;, &&, ||, |, & and newlines outside quotes; subshells and $(…) are kept whole in their part. */
export function splitCompound(cmd) {
  const parts = [];
  let cur = "", quote = null, depth = 0;
  const s = String(cmd);
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) { cur += ch; if (ch === "\\" && quote === '"') cur += s[++i] ?? ""; else if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === ";" || ch === "\n" || ch === "|" || ch === "&")) {
      if ((ch === "|" || ch === "&") && s[i + 1] === ch) i++;
      parts.push(cur); cur = ""; continue;
    }
    cur += ch;
  }
  parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** Whitespace split that keeps single/double-quoted words together; good enough for prefix matching. */
export function splitArgs(cmd) {
  const out = [];
  const re = /"((?:\\.|[^"\\])*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(String(cmd)))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

// ── tiny parsers ────────────────────────────────────────────────────────────────────────────────────────────
function calls(text, name) {  // bodies of name(...) with balanced parentheses, skipping strings and comments
  const out = [];
  let i = 0;
  while ((i = text.indexOf(name + "(", i)) !== -1) {
    let depth = 0, j = i + name.length, quote = null;
    for (; j < text.length; j++) {
      const ch = text[j];
      if (quote) { if (ch === "\\") j++; else if (ch === quote) quote = null; continue; }
      if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "#") { const nl = text.indexOf("\n", j); j = nl === -1 ? text.length : nl; }
      else if (ch === "(") depth++;
      else if (ch === ")" && --depth === 0) break;
    }
    out.push(text.slice(i + name.length + 1, j));
    i = j;
  }
  return out;
}
function field(block, key) {  // the bracketed value of key = [...]
  const m = new RegExp(`\\b${key}\\s*=\\s*\\[`).exec(block);
  if (!m) return undefined;
  let depth = 0, quote = null;
  for (let j = m.index + m[0].length - 1; j < block.length; j++) {
    const ch = block[j];
    if (quote) { if (ch === "\\") j++; else if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "[") depth++;
    else if (ch === "]" && --depth === 0) return block.slice(m.index + m[0].length - 1, j + 1);
  }
  return undefined;
}
function starlarkList(src) {  // ["gh", "pr", ["view", "list"]] with ' or " strings, trailing commas
  if (!src) return undefined;
  const json = src.replace(/"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g, (_, d, s) => JSON.stringify(d !== undefined ? JSON.parse(`"${d}"`) : s.replace(/\\'/g, "'")))
    .replace(/,\s*\]/g, "]");
  try { return JSON.parse(json); } catch { return undefined; }
}
function stripJsonc(text) {
  let out = "", quote = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) { out += ch; if (ch === "\\") out += text[++i] ?? ""; else if (ch === '"') quote = false; continue; }
    if (ch === '"') { quote = true; out += ch; continue; }
    if (ch === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; continue; }
    if (ch === "/" && text[i + 1] === "*") { i = text.indexOf("*/", i + 2); if (i === -1) break; i++; continue; }
    out += ch;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}
const readText = (file) => { try { return readFileSync(file, "utf8"); } catch { return undefined; } };
const readJson = (file) => { try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; } };
const readJsonc = (file) => { const t = readText(file); if (t === undefined) return undefined; try { return JSON.parse(stripJsonc(t)); } catch { return undefined; } };
const jsonc = (dir, base) => [join(dir, `${base}.json`), join(dir, `${base}.jsonc`)];
function listFiles(dir, ext) {
  try { return readdirSync(dir).filter((f) => f.endsWith(ext)).sort().map((f) => join(dir, f)); } catch { return []; }
}

/** cwd and its parents up to the nearest directory containing .git (cwd alone when there is none), cwd first. */
export function projectDirs(cwd) {
  const dirs = [];
  let d = resolve(cwd);
  for (;;) {
    dirs.push(d);
    try { statSync(join(d, ".git")); return dirs; } catch {}
    const up = dirname(d);
    if (up === d) return [resolve(cwd)];
    d = up;
  }
}

const clip = (s, n = MAX_RULE) => (String(s).length > n ? String(s).slice(0, n) + "…" : String(s));
const tilde = (file, home) => (file.startsWith(home + "/") ? "~" + file.slice(home.length) : file);
