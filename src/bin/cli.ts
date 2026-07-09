#!/usr/bin/env node

import { writeFileSync } from "fs";
import { Command } from "commander";
import ora from "ora";
import { runSecurityScan } from "../agents";
import type { InjectionTestResult, ScanResult } from "../types";
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

const VERSION = "1.3.0";

const DEFAULT_MODELS = {
  attacker: "anthropic/claude-opus-4.8",
  target: "anthropic/claude-sonnet-4.6",
  evaluator: "anthropic/claude-sonnet-4.6",
};

const program = new Command();

program
  .name("zeroleaks")
  .description(
    "ZeroLeaks — AI Security Scanner. Test AI systems for prompt injection and system-prompt extraction vulnerabilities.",
  )
  .version(VERSION, "-v, --version", "Show version number");

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
      const fs = await import("fs");
      systemPrompt = fs.readFileSync(options.file, "utf-8");
    } else if (options.prompt) {
      systemPrompt = options.prompt;
    } else {
      console.error(
        c.red("Error: provide a system prompt with --prompt or --file"),
      );
      process.exit(1);
    }

    const apiKey = options.apiKey || process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      console.error(
        c.red(
          "Error: OpenRouter API key required. Set OPENROUTER_API_KEY or use --api-key",
        ),
      );
      process.exit(1);
    }
    process.env.OPENROUTER_API_KEY = apiKey;

    const mode = (options.mode || "dual") as
      | "extraction"
      | "injection"
      | "dual";
    if (!["extraction", "injection", "dual"].includes(mode)) {
      console.error(c.red(`Error: invalid mode "${mode}"`));
      process.exit(1);
    }

    const enableDualMode = mode === "dual";
    const scanMode = mode === "dual" ? "extraction" : mode;
    const maxProbes = parseInt(options.maxProbes, 10);

    if (!options.json) {
      console.log(`\n${BANNER}  ${c.gray(`v${VERSION}`)}\n`);
      console.log(
        box("Scan configuration", [
          `${c.gray("Mode")}       ${c.bold(mode)}`,
          `${c.gray("Attacker")}   ${options.attackerModel || DEFAULT_MODELS.attacker}`,
          `${c.gray("Target")}     ${options.targetModel || DEFAULT_MODELS.target}`,
          `${c.gray("Evaluator")}  ${options.evaluatorModel || DEFAULT_MODELS.evaluator}`,
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

    try {
      const result = await runSecurityScan(systemPrompt, {
        maxTurns: parseInt(options.turns, 10),
        maxDurationMs: parseInt(options.duration, 10),
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
        maxInjectionProbes: Number.isNaN(maxProbes) ? 20 : maxProbes,
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

      if (spinner) spinner.stop();

      if (options.output) {
        writeFileSync(options.output, JSON.stringify(result, null, 2));
        if (!options.json) {
          console.log(
            bullet(`Full result written to ${c.bold(options.output)}`),
          );
        }
      }

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printReport(result, mode);
      }

      process.exit(result.overallVulnerability === "secure" ? 0 : 1);
    } catch (error) {
      if (spinner) spinner.fail(c.red("Scan failed"));
      console.error(
        c.red(error instanceof Error ? error.message : String(error)),
      );
      process.exit(1);
    }
  });

function printReport(
  result: ScanResult,
  mode: "extraction" | "injection" | "dual",
): void {
  console.log(heading("Results"));
  console.log(
    `  ${severityBadge(result.overallVulnerability)}   ${scoreBar(result.overallScore)}`,
  );
  console.log(
    `  ${c.gray("Duration")} ${(result.duration / 1000).toFixed(1)}s   ${c.gray(
      "Turns",
    )} ${result.turnsUsed}   ${c.gray("Leak")} ${result.leakStatus}`,
  );
  if (result.aborted) {
    console.log(`  ${c.yellow(`⚠ ${result.completionReason}`)}`);
  }

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
      console.log(heading("Extraction findings"));
      console.log(
        bullet(c.green("No system-prompt content was extracted."), c.green),
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
