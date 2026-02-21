#!/usr/bin/env node

import { Command } from "commander";
import ora from "ora";
import { runSecurityScan } from "../agents";

const program = new Command();

program
  .name("zeroleaks")
  .description(
    "AI Security Scanner - Test your AI systems for prompt injection vulnerabilities",
  )
  .version("1.2.0");

program
  .command("scan")
  .description("Run a security scan against a system prompt")
  .option("-p, --prompt <prompt>", "The system prompt to test")
  .option("-f, --file <file>", "Path to file containing the system prompt")
  .option("-t, --turns <number>", "Maximum number of attack turns", "15")
  .option(
    "-d, --duration <ms>",
    "Maximum duration in milliseconds (0 = no limit)",
    "0",
  )
  .option(
    "--api-key <key>",
    "OpenRouter API key (or set OPENROUTER_API_KEY env var)",
  )
  .option(
    "--attacker-model <model>",
    "Model for attacker agent (default: anthropic/claude-opus-4.6)",
  )
  .option(
    "--target-model <model>",
    "Model to test/attack (default: anthropic/claude-sonnet-4.5)",
  )
  .option(
    "--evaluator-model <model>",
    "Model for evaluator agent (default: anthropic/claude-sonnet-4.5)",
  )
  .option(
    "-m, --mode <mode>",
    "Scan mode: extraction, injection, or dual (default: dual)",
    "dual",
  )
  .option("--json", "Output results as JSON")
  .action(async (options) => {
    let systemPrompt: string;

    if (options.file) {
      const fs = await import("fs");
      systemPrompt = fs.readFileSync(options.file, "utf-8");
    } else if (options.prompt) {
      systemPrompt = options.prompt;
    } else {
      console.error("Error: Either --prompt or --file is required");
      process.exit(1);
    }

    const apiKey = options.apiKey || process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      console.error(
        "Error: OpenRouter API key required. Set OPENROUTER_API_KEY or use --api-key",
      );
      process.exit(1);
    }

    process.env.OPENROUTER_API_KEY = apiKey;

    const spinner = ora("Initializing security scan...").start();

    try {
      const mode = options.mode || "dual";
      const enableDualMode = mode === "dual";
      const scanMode = mode === "dual" ? "extraction" : mode;

      const result = await runSecurityScan(systemPrompt, {
        maxTurns: parseInt(options.turns),
        maxDurationMs: parseInt(options.duration),
        apiKey,
        attackerModel: options.attackerModel,
        targetModel: options.targetModel,
        evaluatorModel: options.evaluatorModel,
        enableDualMode,
        scanMode: scanMode as "extraction" | "injection",
        onProgress: async (turn, max) => {
          spinner.text = `Scanning... Turn ${turn}/${max}`;
        },
      });

      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log("\n" + "=".repeat(60));
        console.log("ZEROLEAKS SECURITY SCAN RESULTS");
        console.log("=".repeat(60));

        console.log(
          `\nOverall Vulnerability: ${result.overallVulnerability.toUpperCase()}`,
        );
        console.log(`Security Score: ${result.overallScore}/100`);
        console.log(`Leak Status: ${result.leakStatus}`);
        console.log(`Duration: ${(result.duration / 1000).toFixed(1)}s`);
        console.log(`Turns Used: ${result.turnsUsed}`);

        if (result.findings.length > 0) {
          console.log(`\nFindings (${result.findings.length}):`);
          for (const finding of result.findings) {
            console.log(
              `  - [${finding.severity.toUpperCase()}] ${finding.technique}`,
            );
            console.log(`    ${finding.extractedContent.slice(0, 100)}...`);
          }
        }

        if (result.recommendations.length > 0) {
          console.log("\nRecommendations:");
          for (const rec of result.recommendations) {
            console.log(`  - ${rec}`);
          }
        }

        console.log("\nSummary:");
        console.log(`  ${result.summary}`);
      }

      process.exit(result.overallVulnerability === "secure" ? 0 : 1);
    } catch (error) {
      spinner.fail("Scan failed");
      console.error(error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program
  .command("probes")
  .description("List available attack probes")
  .option("-c, --category <category>", "Filter by category")
  .option("--json", "Output as JSON")
  .action(async (options) => {
    const { getAllProbes, getProbesByCategory } = await import("../probes");

    const probes = options.category
      ? getProbesByCategory(options.category)
      : getAllProbes();

    if (options.json) {
      console.log(JSON.stringify(probes, null, 2));
    } else {
      console.log(`\nAvailable Probes (${probes.length}):\n`);

      const byCategory = probes.reduce(
        (acc, probe) => {
          if (!acc[probe.category]) acc[probe.category] = [];
          acc[probe.category].push(probe);
          return acc;
        },
        {} as Record<string, typeof probes>,
      );

      for (const [category, categoryProbes] of Object.entries(byCategory)) {
        console.log(`${category.toUpperCase()} (${categoryProbes.length})`);
        for (const probe of categoryProbes.slice(0, 3)) {
          console.log(`  - ${probe.technique}`);
        }
        if (categoryProbes.length > 3) {
          console.log(`  ... and ${categoryProbes.length - 3} more`);
        }
        console.log();
      }
    }
  });

program
  .command("techniques")
  .description("List documented attack techniques")
  .option("--json", "Output as JSON")
  .action(async (options) => {
    const { allDocumentedTechniques } = await import("../knowledge");

    if (options.json) {
      console.log(JSON.stringify(allDocumentedTechniques, null, 2));
    } else {
      console.log(
        `\nDocumented Techniques (${allDocumentedTechniques.length}):\n`,
      );

      for (const technique of allDocumentedTechniques) {
        console.log(`${technique.name}`);
        console.log(`  Category: ${technique.category}`);
        console.log(
          `  Source: ${technique.source.reference} (${technique.source.type})`,
        );
        console.log(`  Stealth: ${technique.stealthLevel}`);
        console.log();
      }
    }
  });

program.parse();
