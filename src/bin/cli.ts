#!/usr/bin/env node

import {
  accessSync,
  constants,
  existsSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "fs";
import { dirname, resolve } from "path";
import { Command } from "commander";
import ora from "ora";
import { runSecurityScan } from "../agents";
import { attemptedChecks, DEFAULT_MODELS } from "../agents/engine";
import {
  INJECTION_CATEGORIES,
  INJECTION_SEVERITIES,
} from "../probes/injections";
import type {
  InjectionTestResult,
  ScanCoverage,
  ScanResult,
  VulnerabilityLevel,
} from "../types";
import {
  BANNER,
  box,
  bullet,
  c,
  heading,
  scoreBar,
  setColorEnabled,
  severityBadge,
  severityColor,
} from "../ui";

const VERSION = "1.4.0";

const EXIT = { secure: 0, vulnerable: 1, noVerdict: 2 } as const;

function exitCodeFor(vulnerability: VulnerabilityLevel): number {
  if (vulnerability === "secure") return EXIT.secure;
  if (vulnerability === "inconclusive") return EXIT.noVerdict;
  return EXIT.vulnerable;
}

/** process.exit() right after a large write to a pipe truncates the output. */
function exitAfterFlush(code: number): void {
  process.stdout.write("", () => process.exit(code));
}

function fail(message: string): never {
  console.error(c.red(`Error: ${message}`));
  process.exit(EXIT.noVerdict);
}

function isHttpUrl(value: string): boolean {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

function readPromptFile(path: string): string {
  try {
    return readFileSync(path, "utf-8");
  } catch (error) {
    fail(
      `cannot read the prompt file: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function assertWritable(path: string): void {
  let problem: string | undefined;
  try {
    if (!existsSync(path)) {
      accessSync(dirname(resolve(path)), constants.W_OK);
    } else if (statSync(path).isDirectory()) {
      problem = "it is a directory";
    } else {
      accessSync(path, constants.W_OK);
    }
  } catch (error) {
    problem = error instanceof Error ? error.message : String(error);
  }
  if (problem) fail(`cannot write the report to ${path}: ${problem}`);
}

/**
 * Prints a failed write instead of throwing, so the verdict still shows.
 * Returns whether the report was saved.
 */
function saveReport(
  path: string,
  result: ScanResult,
  announce: boolean,
): boolean {
  try {
    writeFileSync(path, JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(
      c.red(
        `Error: could not save the report to ${path}: ${error instanceof Error ? error.message : String(error)}`,
      ),
    );
    return false;
  }
  if (announce) console.log(bullet(`Full result written to ${c.bold(path)}`));
  return true;
}

function parseCount(flag: string, value: string, min = 0): number {
  const count = Number(value);
  if (!Number.isInteger(count) || count < min) {
    fail(`${flag} must be a whole number of at least ${min}, got "${value}"`);
  }
  return count;
}

function assertKnown(
  flag: string,
  values: string[] | undefined,
  allowed: readonly string[],
): void {
  const unknown = values?.filter((v) => !allowed.includes(v)) ?? [];
  if (unknown.length > 0) {
    fail(
      `unknown ${flag} ${unknown.map((v) => `"${v}"`).join(", ")}. Valid values: ${allowed.join(", ")}`,
    );
  }
}

const program = new Command();

program
  .name("zeroleaks")
  .description(
    "ZeroLeaks — AI Security Scanner. Test AI systems for prompt injection and system-prompt extraction vulnerabilities.",
  )
  .version(VERSION, "-v, --version", "Show version number")
  // Must precede .command() so subcommands inherit it.
  .exitOverride((err) => {
    process.exit(err.exitCode === 0 ? 0 : EXIT.noVerdict);
  });

/** Split repeated/comma-separated CLI list values into a flat array. */
function collectList(value: string, previous: string[] = []): string[] {
  return previous.concat(
    value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
  );
}

program
  .command("scan")
  .description("Run a security scan against a system prompt")
  .option("-p, --prompt <prompt>", "The system prompt to test")
  .option("-f, --file <file>", "Path to a file containing the system prompt")
  .option(
    "-m, --mode <mode>",
    "Scan mode: extraction | injection | dual",
    "dual",
  )
  .option(
    "-t, --turns <number>",
    "Maximum number of attack turns (extraction)",
    "15",
  )
  .option(
    "-d, --duration <ms>",
    "Maximum duration in milliseconds (0 = no limit)",
    "0",
  )
  .option("--api-key <key>", "OpenRouter API key (or set OPENROUTER_API_KEY)")
  .option(
    "--openai-api-key <key>",
    "OpenAI API key (or set OPENAI_API_KEY); openai/* and gpt-* models route to the OpenAI API",
  )
  .option(
    "--base-url <url>",
    "OpenAI-compatible endpoint (or set OPENAI_BASE_URL), e.g. http://localhost:11434/v1",
  )
  .option(
    "--attacker-model <model>",
    `Model for the attacker agent (default: ${DEFAULT_MODELS.attacker})`,
  )
  .option(
    "--target-model <model>",
    `Model under test (default: ${DEFAULT_MODELS.target})`,
  )
  .option(
    "--evaluator-model <model>",
    `Model for the evaluator agent (default: ${DEFAULT_MODELS.evaluator})`,
  )
  .option(
    "--injection-model <model>",
    "Model for the injection compliance judge (defaults to evaluator model)",
  )
  .option(
    "--injection-category <categories>",
    "Filter injection probes by category (comma-separated: extraction, tool_hijacking, indirect_injection, authority_exploit, multi_turn, protocol_exploit)",
    collectList,
  )
  .option(
    "--severity <levels>",
    "Filter injection probes by severity (comma-separated: critical, high, medium, low)",
    collectList,
  )
  .option(
    "--max-probes <number>",
    "Max injection probes to run (0 = all, default 20)",
    "20",
  )
  .option("--no-multi-turn", "Skip multi-turn grooming injection probes")
  .option("--no-inspector", "Disable the defense inspector (extraction)")
  .option(
    "--no-orchestrator",
    "Disable the multi-turn orchestrator (extraction)",
  )
  .option("-o, --output <file>", "Write the full JSON result to a file")
  .option("--json", "Print results as JSON to stdout")
  .option("--no-color", "Disable colored output")
  .option("-q, --quiet", "Suppress the live progress spinner")
  .action(async (options) => {
    if (options.color === false) setColorEnabled(false);

    let systemPrompt: string;
    if (options.file) {
      systemPrompt = readPromptFile(options.file);
    } else if (options.prompt) {
      systemPrompt = options.prompt;
    } else {
      fail("provide a system prompt with --prompt or --file");
    }

    const apiKey = options.apiKey || process.env.OPENROUTER_API_KEY;
    const openaiApiKey = options.openaiApiKey || process.env.OPENAI_API_KEY;
    const baseUrl = options.baseUrl || process.env.OPENAI_BASE_URL;
    if (baseUrl && !isHttpUrl(baseUrl)) {
      fail(`invalid --base-url "${baseUrl}"; expected an http(s) URL`);
    }
    if (!apiKey && !openaiApiKey && !baseUrl) {
      fail(
        "no API key. Set OPENROUTER_API_KEY (--api-key), OPENAI_API_KEY (--openai-api-key), or an OpenAI-compatible endpoint (--base-url).",
      );
    }
    if (apiKey) process.env.OPENROUTER_API_KEY = apiKey;
    if (openaiApiKey) process.env.OPENAI_API_KEY = openaiApiKey;
    if (baseUrl) process.env.OPENAI_BASE_URL = baseUrl;

    const mode = (options.mode || "dual") as
      | "extraction"
      | "injection"
      | "dual";
    if (!["extraction", "injection", "dual"].includes(mode)) {
      fail(`invalid mode "${mode}"`);
    }
    assertKnown(
      "injection category",
      options.injectionCategory,
      INJECTION_CATEGORIES,
    );
    assertKnown("severity", options.severity, INJECTION_SEVERITIES);
    if (options.output) assertWritable(options.output);

    const maxTurns = parseCount("--turns", options.turns, 1);
    const maxProbes = parseCount("--max-probes", options.maxProbes);
    const maxDurationMs = parseCount("--duration", options.duration);
    if (maxDurationMs > 0 && maxDurationMs <= 30_000) {
      fail(
        "--duration must be 0 (no limit) or more than 30000 ms; the scan keeps the last 30 s to wrap up",
      );
    }

    const enableDualMode = mode === "dual";
    const scanMode = mode === "dual" ? "extraction" : mode;

    if (!options.json) {
      console.log(`\n${BANNER}  ${c.gray(`v${VERSION}`)}\n`);
      console.log(
        box("Scan configuration", [
          `${c.gray("Mode")}       ${c.bold(mode)}`,
          `${c.gray("Attacker")}   ${options.attackerModel || DEFAULT_MODELS.attacker}`,
          `${c.gray("Target")}     ${options.targetModel || DEFAULT_MODELS.target}`,
          `${c.gray("Evaluator")}  ${options.evaluatorModel || DEFAULT_MODELS.evaluator}`,
          ...(baseUrl ? [`${c.gray("Endpoint")}   ${baseUrl}`] : []),
          ...(mode !== "extraction"
            ? [
                `${c.gray("Probes")}     ${maxProbes === 0 ? "all" : maxProbes}${
                  options.injectionCategory?.length
                    ? ` · ${options.injectionCategory.join(", ")}`
                    : ""
                }${options.multiTurn === false ? " · single-turn" : ""}`,
              ]
            : []),
        ]),
      );
      console.log();
    }

    const spinner = options.json || options.quiet ? null : ora();
    let injectionHits = 0;

    if (spinner) spinner.start(c.gray("Initializing security scan…"));

    let result: ScanResult;
    try {
      result = await runSecurityScan(systemPrompt, {
        maxTurns,
        maxDurationMs,
        apiKey,
        attackerModel: options.attackerModel,
        targetModel: options.targetModel,
        evaluatorModel: options.evaluatorModel,
        injectionEvaluatorModel: options.injectionModel,
        enableDualMode,
        scanMode: scanMode as "extraction" | "injection",
        enableInspector: options.inspector,
        enableOrchestrator: options.orchestrator,
        injectionCategories: options.injectionCategory,
        injectionSeverities: options.severity,
        maxInjectionProbes: maxProbes,
        enableMultiTurnInjection: options.multiTurn,
        onProgress: async (turn, max) => {
          if (!spinner) return;
          const label =
            mode === "injection"
              ? `Testing injection probes… ${turn}/${max}`
              : `Attacking… turn ${turn}/${max}`;
          spinner.text = `${c.gray(label)}${
            injectionHits > 0 ? c.red(`  (${injectionHits} hit)`) : ""
          }`;
        },
        onInjectionResult: async (r) => {
          if (r.success) injectionHits++;
        },
      });
    } catch (error) {
      if (spinner) spinner.fail(c.red("Scan failed"));
      console.error(
        c.red(error instanceof Error ? error.message : String(error)),
      );
      process.exit(EXIT.noVerdict);
    }
    if (spinner) spinner.stop();

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printReport(result, mode);
    }
    const saved =
      !options.output || saveReport(options.output, result, !options.json);

    exitAfterFlush(
      saved ? exitCodeFor(result.overallVulnerability) : EXIT.noVerdict,
    );
  });

function printReport(
  result: ScanResult,
  mode: "extraction" | "injection" | "dual",
): void {
  console.log(heading("Results"));
  console.log(
    `  ${severityBadge(result.overallVulnerability)}   ${
      result.overallVulnerability === "inconclusive"
        ? c.yellow("no score, some checks did not run")
        : scoreBar(result.overallScore)
    }`,
  );
  console.log(
    `  ${c.gray("Duration")} ${(result.duration / 1000).toFixed(1)}s   ${c.gray(
      "Turns",
    )} ${result.turnsUsed}   ${c.gray("Leak")} ${result.leakStatus}`,
  );
  if (result.aborted) {
    console.log(`  ${c.yellow(`⚠ ${result.completionReason}`)}`);
  }
  printCoverage("Extraction", "turns", result.coverage.extraction);
  printCoverage("Injection", "probes", result.coverage.injection);

  // Extraction findings
  if (mode !== "injection") {
    if (result.findings.length > 0) {
      console.log(heading(`Extraction findings (${result.findings.length})`));
      for (const f of result.findings) {
        console.log(
          `  ${severityColor(f.severity)(`[${f.severity.toUpperCase()}]`)} ${c.bold(
            f.technique,
          )} ${c.gray(`· ${f.confidence} confidence`)}`,
        );
        if (f.extractedContent) {
          console.log(
            `    ${c.gray(truncate(f.extractedContent.replace(/\s+/g, " "), 120))}`,
          );
        }
      }
    } else {
      const extraction = result.coverage.extraction;
      const fullyChecked =
        extraction !== undefined &&
        extraction.completed > 0 &&
        extraction.failed.length === 0;
      console.log(heading("Extraction findings"));
      console.log(
        fullyChecked
          ? bullet(c.green("No system-prompt content was extracted."), c.green)
          : bullet(
              c.yellow(
                "Nothing extracted, but not every turn was checked (see above).",
              ),
              c.yellow,
            ),
      );
    }
  }

  // Injection results
  if (result.injectionResults && result.injectionResults.length > 0) {
    printInjectionResults(result.injectionResults);
  }

  // Recommendations
  if (result.recommendations.length > 0) {
    console.log(heading("Recommendations"));
    for (const rec of result.recommendations) {
      console.log(bullet(rec, c.yellow));
    }
  }

  console.log(heading("Summary"));
  for (const line of result.summary.split("\n").filter(Boolean)) {
    console.log(`  ${line}`);
  }
  console.log();
}

function printCoverage(
  mode: string,
  checks: string,
  coverage: ScanCoverage | undefined,
): void {
  if (!coverage) return;
  const failed = coverage.failed.length;
  const planned = attemptedChecks(coverage) + coverage.skipped;
  console.log(
    `  ${c.gray(mode)} ${coverage.completed}/${planned} ${checks} checked${
      failed > 0 ? c.yellow(` · ${failed} failed`) : ""
    }${coverage.skipped > 0 ? c.yellow(` · ${coverage.skipped} not run`) : ""}`,
  );
  for (const check of coverage.failed) {
    const label = check.technique
      ? `${check.id} (${check.technique})`
      : check.id;
    console.log(
      `    ${c.yellow("✖")} ${label}: ${c.gray(truncate(check.error, 110))}`,
    );
  }
}

function printInjectionResults(results: InjectionTestResult[]): void {
  const hits = results.filter((r) => r.success);
  console.log(
    heading(
      `Injection probes (${results.length} tested · ${hits.length} succeeded)`,
    ),
  );

  // Group by behavioral category.
  const byCategory = new Map<string, InjectionTestResult[]>();
  for (const r of results) {
    const key = r.probeCategory || r.testType;
    if (!byCategory.has(key)) byCategory.set(key, []);
    byCategory.get(key)!.push(r);
  }

  for (const [category, group] of byCategory) {
    const succeeded = group.filter((r) => r.success).length;
    const label = category.replace(/_/g, " ");
    const rate =
      succeeded > 0
        ? c.red(`${succeeded}/${group.length}`)
        : c.green(`0/${group.length}`);
    console.log(
      `  ${c.bold(label)} ${c.gray("—")} ${rate} ${c.gray("compromised")}`,
    );
    for (const r of group.filter((x) => x.success)) {
      const comp = r.compliance ? ` ${c.gray(`(${r.compliance})`)}` : "";
      console.log(
        `    ${severityColor(r.severity)(`[${r.severity.toUpperCase()}]`)} ${r.technique}${comp}`,
      );
      if (r.intent) console.log(`      ${c.gray(truncate(r.intent, 110))}`);
    }
  }
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

program
  .command("probes")
  .description("List available attack probes")
  .option("-c, --category <category>", "Filter by category")
  .option("--json", "Output as JSON")
  .option("--no-color", "Disable colored output")
  .action(async (options) => {
    if (options.color === false) setColorEnabled(false);
    const { getAllProbes, getProbesByCategory } = await import("../probes");

    const probes = options.category
      ? getProbesByCategory(options.category)
      : getAllProbes();

    if (options.json) {
      console.log(JSON.stringify(probes, null, 2));
      return;
    }

    console.log(`\n${BANNER}\n`);
    console.log(heading(`Attack probes (${probes.length})`));

    const byCategory = probes.reduce(
      (acc, probe) => {
        if (!acc[probe.category]) acc[probe.category] = [];
        acc[probe.category].push(probe);
        return acc;
      },
      {} as Record<string, typeof probes>,
    );

    for (const [category, categoryProbes] of Object.entries(
      byCategory,
    ).sort()) {
      console.log(
        `\n  ${c.bold(c.cyan(category.toUpperCase()))} ${c.gray(`(${categoryProbes.length})`)}`,
      );
      for (const probe of categoryProbes.slice(0, 4)) {
        console.log(`    ${c.gray("›")} ${probe.technique}`);
      }
      if (categoryProbes.length > 4) {
        console.log(c.gray(`    … and ${categoryProbes.length - 4} more`));
      }
    }
    console.log();
  });

program
  .command("categories")
  .description("List behavioral injection-probe categories and counts")
  .option("--json", "Output as JSON")
  .option("--no-color", "Disable colored output")
  .action(async (options) => {
    if (options.color === false) setColorEnabled(false);
    const {
      INJECTION_CATEGORIES,
      countProbesByCategory,
      getInjectionProbesByCategory,
    } = await import("../probes");

    const counts = countProbesByCategory();

    if (options.json) {
      console.log(JSON.stringify(counts, null, 2));
      return;
    }

    console.log(`\n${BANNER}\n`);
    console.log(heading("Injection probe categories"));
    for (const category of INJECTION_CATEGORIES) {
      const probes = getInjectionProbesByCategory(category);
      const severities = [...new Set(probes.map((p) => p.severity))];
      console.log(
        `\n  ${c.bold(c.cyan(category))} ${c.gray(`(${counts[category]})`)}`,
      );
      console.log(
        `    ${c.gray("severities:")} ${severities
          .map((s) => severityColor(s)(s))
          .join(", ")}`,
      );
    }
    console.log();
  });

program
  .command("techniques")
  .description("List documented attack techniques")
  .option("--json", "Output as JSON")
  .option("--no-color", "Disable colored output")
  .action(async (options) => {
    if (options.color === false) setColorEnabled(false);
    const { allDocumentedTechniques } = await import("../knowledge");

    if (options.json) {
      console.log(JSON.stringify(allDocumentedTechniques, null, 2));
      return;
    }

    console.log(`\n${BANNER}\n`);
    console.log(
      heading(`Documented techniques (${allDocumentedTechniques.length})`),
    );
    for (const technique of allDocumentedTechniques) {
      console.log(`\n  ${c.bold(technique.name)}`);
      console.log(`    ${c.gray("Category")} ${technique.category}`);
      console.log(
        `    ${c.gray("Source")}   ${technique.source.reference} (${technique.source.type})`,
      );
      console.log(`    ${c.gray("Stealth")}  ${technique.stealthLevel}`);
    }
    console.log();
  });

program.parse();
