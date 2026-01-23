# AGENTS.md

Instructions for AI agents working on the ZeroLeaks codebase.

## Project Overview

ZeroLeaks is an autonomous AI security scanner that tests LLM systems for prompt injection vulnerabilities. It uses a multi-agent architecture to systematically probe target systems and identify security weaknesses.

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
├── probes/       # Prompt injection attack templates
├── index.ts      # Main exports
├── types.ts      # TypeScript type definitions
└── utils.ts      # Utility functions
```

### Agent System (`src/agents/`)

The scanner uses a multi-agent architecture:

| Agent | File | Purpose |
|-------|------|---------|
| **Engine** | `engine.ts` | Orchestrates the scan, manages attack tree |
| **Strategist** | `strategist.ts` | Selects attack strategies based on defense profile |
| **Attacker** | `attacker.ts` | Generates attack prompts |
| **Evaluator** | `evaluator.ts` | Analyzes responses for leaks |
| **Mutator** | `mutator.ts` | Creates variations of successful attacks |
| **Target** | `target.ts` | Wrapper for the system being tested |

### Probes (`src/probes/`)

Attack templates organized by category:
- `direct.ts` - Straightforward extraction attempts
- `encoding.ts` - Base64, ROT13, Unicode obfuscation
- `personas.ts` - DAN, roleplay, persona-based attacks
- `social.ts` - Social engineering techniques
- `technical.ts` - Format injection, context manipulation
- `modern.ts` - Crescendo, CoT hijacking, policy puppetry
- `advanced.ts` - Sophisticated multi-turn attacks

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
// Attack categories for probes
type AttackCategory = "direct" | "encoding" | "persona" | "social" | 
  "technical" | "crescendo" | "many_shot" | "ascii_art" | "cot_hijack" | 
  "semantic_shift" | "policy_puppetry" | "context_overflow" | "reasoning_exploit"

// Attack phases in a scan
type AttackPhase = "reconnaissance" | "profiling" | "soft_probe" | 
  "escalation" | "exploitation" | "persistence"

// Leak detection status
type LeakStatus = "none" | "hint" | "fragment" | "substantial" | "complete"

// Vulnerability assessment
type DefenseLevel = "none" | "weak" | "moderate" | "strong" | "hardened"
```

## Common Tasks

### Adding a New Probe

1. Add the probe to the appropriate file in `src/probes/`
2. Ensure it implements the `Probe` interface from `src/types.ts`
3. Export it from `src/probes/index.ts`
4. Add tests if applicable

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

The package publishes to GitHub Packages via the workflow in `.github/workflows/publish.yml`.

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
./dist/bin/cli.js scan --prompt "Your system prompt..."
./dist/bin/cli.js scan --file ./prompt.txt --turns 20
./dist/bin/cli.js probes
./dist/bin/cli.js techniques
```

## API Entry Points

Main exports from `src/index.ts`:
- `runSecurityScan()` - High-level scan function
- `createScanEngine()` - Create configurable engine
- Probe collections and utilities
- Knowledge base exports
- Type exports

## Notes for AI Agents

1. **Always run linting** after making changes: `bun run lint`
2. **Always run type checking** after modifying types: `bun run typecheck`
3. **Keep types in sync** - If changing interfaces, update `src/types.ts` first
4. **Follow existing patterns** - Look at similar code in the codebase
5. **Test locally** when possible before committing
6. **Preserve exports** - The `src/index.ts` file is the public API; be careful when modifying exports
