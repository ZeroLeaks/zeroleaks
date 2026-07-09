# AGENTS.md

Instructions for AI agents working on the ZeroLeaks codebase.

## Project Overview

ZeroLeaks is a red-teaming tool for LLM system prompts and agent instructions, shipped as a CLI and a TypeScript library. It runs two kinds of scan:

- **Extraction** — can the target be talked into revealing its own system prompt? This uses an adaptive multi-agent attack loop.
- **Injection** — can it be made to follow instructions hidden in content, obey fake authority, or misuse a tool? This fires a fixed corpus of behavioral probes and grades compliance (full / partial / refused) with an LLM judge.

Both can run at once (`dual` mode).

**Tech Stack:**
- Runtime: Bun
- Language: TypeScript (ES2022, ESNext modules)
- LLM Provider: OpenRouter via Vercel AI SDK
- Linting/Formatting: Biome

## Development Setup

```bash
# Install dependencies
bun install

# Build the project
bun run build

# Run linting
bun run lint

# Run type checking
bun run typecheck

# Run tests
bun test
```

## Environment Variables

Copy `.env.example` to `.env` and set:
- `OPENROUTER_API_KEY` - Required for LLM API calls

## Project Architecture

### Core Directories

```
src/
├── agents/       # Multi-agent system components
├── bin/          # CLI entry point
├── knowledge/    # Attack techniques & bypass methods
├── probes/       # Attack probes (injection corpus + extraction arsenal)
├── index.ts      # Main exports (public API)
├── types.ts      # TypeScript type definitions
├── ui.ts         # Terminal output helpers (colors, score bar, boxes)
└── utils.ts      # Utility functions
```

### Agent System (`src/agents/`)

The scanner uses a multi-agent architecture:

| Agent | File | Purpose |
|-------|------|---------|
| **Engine** | `engine.ts` | Orchestrates the scan, manages the attack tree, runs both scan modes |
| **Strategist** | `strategist.ts` | Selects attack strategies based on the defense profile |
| **Attacker** | `attacker.ts` | Generates attack prompts |
| **Evaluator** | `evaluator.ts` | Analyzes responses for prompt leaks (extraction) |
| **Mutator** | `mutator.ts` | Creates variations of successful attacks |
| **Inspector** | `inspector.ts` | Fingerprints defenses and finds weaknesses to exploit |
| **Orchestrator** | `orchestrator.ts` | Runs multi-turn sequences (Siren, Echo Chamber, TombRaider) |
| **Injection evaluator** | `injection-evaluator.ts` | LLM-as-judge compliance grading for the injection scan |
| **Target** | `target.ts` | Wrapper for the system being tested |

### Probes (`src/probes/`)

There are two probe systems here; don't confuse them.

**Behavioral injection corpus** — what the injection scan fires:
- `injections.ts` - the behavioral probe corpus. Each `InjectionProbe` has a `category` (extraction, tool_hijacking, indirect_injection, authority_exploit, multi_turn, protocol_exploit), a `severity`, an `intent`, and `successIndicators`. Optional `multiTurn` for grooming sequences. Also has `generateDynamicProbes()` for tool-tailored probes.
- `redteam-corpus.ts` - benchmark-derived attack seeds (AgentDojo, InjecAgent, JailbreakBench, HarmBench, garak, promptfoo, OWASP) that get folded into the corpus.

**Extraction attacker arsenal** — the technique library the multi-agent extraction loop and the `probes` command draw from:
- `direct.ts` - Straightforward extraction attempts
- `encoding.ts` - Base64, ROT13, Unicode obfuscation
- `personas.ts` - DAN, roleplay, persona-based attacks
- `social.ts` - Social engineering techniques
- `technical.ts` - Format injection, context manipulation
- `modern.ts` - Crescendo, CoT hijacking, policy puppetry
- `advanced.ts` - Sophisticated multi-turn attacks
- `hybrid.ts`, `tool-exploits.ts`, `garak-inspired.ts` - hybrid/XSS-style, tool/MCP, and garak-inspired probes
- `jailbreak-techniques.ts` - skeleton key, echo chamber, promptware, role hijack, etc. (this was the old `injection.ts`; its type is `JailbreakProbe`)
- `index.ts` - barrel; `getAllProbes`, `getProbesByCategory`, plus the injection-corpus re-exports

### Knowledge Base (`src/knowledge/`)

Research-backed attack information:
- `techniques.ts` - Documented attack techniques (including CVEs)
- `payloads.ts` - Payload templates for various attacks
- `exfiltration.ts` - Data exfiltration vectors
- `defense-bypass.ts` - Methods to bypass common defenses

## Code Style

### Formatting
- Use 2-space indentation
- Run `bun run format` before committing
- Biome handles formatting automatically

### TypeScript Conventions
- All types are defined in `src/types.ts`
- Use interfaces over type aliases for object shapes
- Export types explicitly from module index files
- Avoid `any` where possible, but it's allowed when needed

### Linting Rules
- Biome is configured in `biome.jsonc`
- Some rules are relaxed (see config):
  - `noExplicitAny`: off
  - `noNonNullAssertion`: off
  - `useNodejsImportProtocol`: off

## Key Types

Important types defined in `src/types.ts`:

```typescript
// Attack categories for the extraction arsenal (src/types.ts)
type AttackCategory = "direct" | "encoding" | "persona" | "social" |
  "technical" | "crescendo" | "many_shot" | "ascii_art" | "cot_hijack" |
  "semantic_shift" | "policy_puppetry" | "context_overflow" |
  "reasoning_exploit" | "hybrid" | "tool_exploit" | "siren" |
  "echo_chamber" | "injection"

// Categories for the behavioral injection corpus (src/probes/injections.ts)
type InjectionCategory = "extraction" | "tool_hijacking" |
  "indirect_injection" | "authority_exploit" | "multi_turn" | "protocol_exploit"

// Attack phases in a scan
type AttackPhase = "reconnaissance" | "profiling" | "soft_probe" |
  "escalation" | "exploitation" | "persistence"

// Leak detection status (extraction)
type LeakStatus = "none" | "hint" | "fragment" | "substantial" | "complete"

// Injection compliance verdict (injection)
type ComplianceLevel = "full" | "partial" | "refused"

// Defense assessment
type DefenseLevel = "none" | "weak" | "moderate" | "strong" | "hardened"
```

## Common Tasks

### Adding a New Probe

For an **injection-scan** probe (the common case): add an `InjectionProbe` object to the right category array in `src/probes/injections.ts`. Give it a `category`, `severity`, `intent`, and `successIndicators` (add `multiTurn` for a grooming sequence). It gets picked up automatically — no wiring needed.

For an **extraction attacker** technique:
1. Add it to the appropriate file in `src/probes/` implementing the `Probe` interface from `src/types.ts`
2. Export it from `src/probes/index.ts`
3. Add tests if applicable

### Adding a New Attack Technique

1. Document the technique in `src/knowledge/techniques.ts`
2. Create corresponding payloads in `src/knowledge/payloads.ts`
3. Add bypass methods if applicable in `src/knowledge/defense-bypass.ts`

### Modifying Agent Behavior

1. Agent configs are defined in their respective files in `src/agents/`
2. The `ScanEngine` in `engine.ts` orchestrates all agents
3. Update types in `src/types.ts` if changing interfaces

## Build & Publish

```bash
# Build for distribution
bun run build

# Output goes to dist/
# - dist/index.js - Main library
# - dist/bin/cli.js - CLI executable
# - dist/*.d.ts - Type declarations
```

On a published GitHub release, `.github/workflows/publish.yml` publishes to GitHub Packages. The public npm package (`zeroleaks`) is published manually with `npm publish` — `prepublishOnly` runs `bun run build` first, so `dist/` is always fresh.

Default models live in `DEFAULT_CONFIG` in `src/agents/engine.ts`: attacker `anthropic/claude-opus-4.8`, target/evaluator/judge `anthropic/claude-sonnet-5`. All are overridable per scan.

## Testing

```bash
# Run all tests
bun test

# Tests use Bun's built-in test runner
```

## CLI Usage

The CLI is defined in `src/bin/cli.ts`:

```bash
# After building
./dist/bin/cli.js scan --prompt "Your system prompt..."          # dual mode (default)
./dist/bin/cli.js scan --file ./prompt.txt --mode injection \
  --severity critical,high --max-probes 40 --output report.json
./dist/bin/cli.js scan --file ./prompt.txt --mode extraction --turns 20
./dist/bin/cli.js probes --category tool_hijacking
./dist/bin/cli.js categories            # behavioral injection categories + counts
./dist/bin/cli.js techniques
```

Scan flags of note: `--mode` (extraction|injection|dual), `--injection-category`,
`--severity`, `--max-probes`, `--no-multi-turn`, `--injection-model`,
`-o/--output`, `--json`, `--no-color`, `-q/--quiet`.

## API Entry Points

Main exports from `src/index.ts`:
- `runSecurityScan()` - High-level scan (extraction, injection, or dual)
- `createScanEngine()` - Configurable engine for advanced use
- `INJECTION_PROBES`, `INJECTION_CATEGORIES`, `getInjectionProbesByCategory()`, `getInjectionProbesBySeverity()`, `getMultiTurnProbes()`, `countProbesByCategory()`, `generateDynamicProbes()` - behavioral injection corpus
- `getAllProbes()`, `getProbesByCategory()`, `getProbesForPhase()` - extraction arsenal
- Knowledge base exports (`allDocumentedTechniques`, `getCVETechniques()`, ...)
- Type exports

## Notes for AI Agents

1. **Always run linting** after making changes: `bun run lint`
2. **Always run type checking** after modifying types: `bun run typecheck`
3. **Keep types in sync** - If changing interfaces, update `src/types.ts` first
4. **Follow existing patterns** - Look at similar code in the codebase
5. **Test locally** when possible before committing
6. **Preserve exports** - The `src/index.ts` file is the public API; be careful when modifying exports
