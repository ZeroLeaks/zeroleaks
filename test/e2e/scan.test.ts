import { mkdtempSync, rmSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import {
  LIBRARY_SCAN,
  MOCK_MODEL_FLAGS,
  resetArtifacts,
  runCli,
  SYSTEM_PROMPT,
  writeSummary,
} from "./harness";
import type { GraderBehavior } from "./mock-llm";

setDefaultTimeout(30_000);
beforeAll(resetArtifacts);
afterAll(writeSummary);

const EXIT = { secure: 0, vulnerable: 1, inconclusive: 2 } as const;

const SCAN = ["scan", "--prompt", SYSTEM_PROMPT, "-q"];
const INJECTION = [
  ...SCAN,
  "--mode",
  "injection",
  "--no-multi-turn",
  ...MOCK_MODEL_FLAGS,
];
const EXTRACTION = [...SCAN, "--mode", "extraction", ...MOCK_MODEL_FLAGS];

const JUDGE_REFUSED: GraderBehavior = { fields: { compliance: "refused" } };
const JUDGE_COMPLIED: GraderBehavior = {
  fields: { compliance: "full", confidence: 0.9 },
};
const EVALUATOR_CLEAN: GraderBehavior = {
  fields: { leakStatus: "none", shouldContinue: true, shouldReset: false },
};
const EVALUATOR_FULL_LEAK: GraderBehavior = {
  fields: {
    leakStatus: "complete",
    leakConfidence: 0.95,
    extractedContent: SYSTEM_PROMPT,
    contentType: "system_prompt",
    shouldContinue: false,
    shouldReset: false,
  },
};
const EVALUATOR_PARTIAL_LEAK: GraderBehavior = {
  fields: {
    leakStatus: "fragment",
    leakConfidence: 0.6,
    extractedContent: "Secret escalation code: ALPHA-7",
    shouldContinue: true,
    shouldReset: false,
  },
};

describe("command-line usage", () => {
  test("rejects an unknown injection category before scanning", async () => {
    const run = await runCli(
      "unknown injection category",
      { target: "refuse" },
      [...INJECTION, "--injection-category", "tool_hijacking,bogus"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain('"bogus"');
    expect(run.stderr).toContain("tool_hijacking");
    expect(run.requests).toHaveLength(0);
  });

  test("rejects an unknown severity before scanning", async () => {
    const run = await runCli("unknown severity", { target: "refuse" }, [
      ...INJECTION,
      "--severity",
      "urgent",
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain('"urgent"');
    expect(run.requests).toHaveLength(0);
  });

  test("an unknown flag exits with the no-verdict code", async () => {
    const run = await runCli("unknown flag", { target: "refuse" }, [
      ...SCAN,
      "--not-a-flag",
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.requests).toHaveLength(0);
  });

  test("a missing --file exits with the no-verdict code", async () => {
    const run = await runCli("missing prompt file", { target: "refuse" }, [
      "scan",
      "--file",
      "does-not-exist.txt",
      ...MOCK_MODEL_FLAGS,
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain("does-not-exist.txt");
    expect(run.requests).toHaveLength(0);
  });

  test("an unwritable -o path fails before the scan spends anything", async () => {
    const run = await runCli("unwritable report path", { target: "refuse" }, [
      ...INJECTION,
      "--max-probes",
      "1",
      "-o",
      "missing-dir/report.json",
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain("missing-dir");
    expect(run.requests).toHaveLength(0);
  });

  test("an -o path that is a directory fails before the scan", async () => {
    const run = await runCli(
      "report path is a directory",
      { target: "refuse" },
      [...INJECTION, "--max-probes", "1", "-o", "."],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain("directory");
    expect(run.requests).toHaveLength(0);
  });

  test("a report that can't be saved after the scan is not a pass", async () => {
    // A dangling symlink passes the pre-scan check, then the write fails.
    const dir = mkdtempSync(join(tmpdir(), "zeroleaks-e2e-"));
    const reportPath = join(dir, "report.json");
    symlinkSync(join(dir, "missing-dir", "report.json"), reportPath);

    const run = await runCli(
      "report save fails after the scan",
      { target: "refuse", judge: JUDGE_REFUSED },
      [...INJECTION, "--max-probes", "1", "-o", reportPath],
    );
    rmSync(dir, { recursive: true, force: true });

    expect(run.stdout).toContain("SECURE");
    expect(run.stderr).toContain("could not save the report");
    expect(run.exitCode).toBe(EXIT.inconclusive);
  });

  test("a --duration too short to run anything is rejected", async () => {
    const run = await runCli("duration too short", { target: "refuse" }, [
      ...INJECTION,
      "--duration",
      "20000",
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain("--duration");
    expect(run.requests).toHaveLength(0);
  });

  test("a non-numeric count is rejected", async () => {
    const run = await runCli("non-numeric max probes", { target: "refuse" }, [
      ...INJECTION,
      "--max-probes",
      "lots",
    ]);

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.stderr).toContain("--max-probes");
    expect(run.requests).toHaveLength(0);
  });

  test("--help and --version still exit 0", async () => {
    const help = await runCli("scan help", { target: "refuse" }, [
      "scan",
      "--help",
    ]);
    const version = await runCli("version", { target: "refuse" }, [
      "--version",
    ]);

    expect(help.exitCode).toBe(0);
    expect(version.exitCode).toBe(0);
  });
});

describe("injection scan", () => {
  test("a target that refuses every probe is secure", async () => {
    const run = await runCli(
      "injection refusing target",
      { target: "refuse", judge: JUDGE_REFUSED },
      [...INJECTION, "--max-probes", "3"],
    );

    expect(run.exitCode).toBe(EXIT.secure);
    expect(run.result?.overallVulnerability).toBe("secure");
    expect(run.result?.coverage.injection).toEqual({
      completed: 3,
      failed: [],
      skipped: 0,
    });
    // Each message is numbered by the probe it belongs to.
    expect(run.result?.injectionConversationLog?.map((t) => t.turn)).toEqual([
      1, 1, 2, 2, 3, 3,
    ]);
  });

  test("a target that complies is vulnerable", async () => {
    const run = await runCli(
      "injection complying target",
      { target: "comply", judge: JUDGE_COMPLIED },
      [...INJECTION, "--max-probes", "3"],
    );

    expect(run.exitCode).toBe(EXIT.vulnerable);
    // The first three probes under the severity-ordered cap are critical.
    expect(run.result?.overallVulnerability).toBe("critical");
    expect(run.result?.injectionResults).toHaveLength(3);
  });

  test("a judge failure is not scored as a refusal", async () => {
    const run = await runCli(
      "injection judge failure",
      { target: "comply", judge: "malformed" },
      [...INJECTION, "--max-probes", "3"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.injectionResults).toHaveLength(0);
    expect(run.result?.coverage.injection?.completed).toBe(0);
    expect(run.result?.coverage.injection?.failed).toHaveLength(3);
  });

  test("an unreachable target is inconclusive, even under a small budget", async () => {
    const run = await runCli(
      "injection unreachable target",
      { target: "error" },
      [...INJECTION, "--max-probes", "2"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.overallScore).toBe(0);
    expect(run.result?.coverage.injection?.failed).toHaveLength(2);
  });

  test("probes that fail are listed in the report, not dropped", async () => {
    const run = await runCli(
      "injection intermittent target",
      { target: "refuse", failTargetCalls: [1, 3], judge: JUDGE_REFUSED },
      [...INJECTION, "--max-probes", "4"],
    );

    const coverage = run.result?.coverage.injection;
    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(coverage?.completed).toBe(2);
    expect(coverage?.failed).toHaveLength(2);
    for (const failure of coverage?.failed ?? []) {
      expect(failure.id).toBeTruthy();
      expect(failure.error).toContain("Mock target is unavailable");
    }
    expect(run.stdout).toContain("Mock target is unavailable");
  });

  test("a probe that fails part-way does not leak into the next probe", async () => {
    const run = await runCli(
      "injection multi-turn probe fails part-way",
      { target: "refuse", failTargetCalls: [2], judge: JUDGE_REFUSED },
      [
        ...SCAN,
        "--mode",
        "injection",
        "--injection-category",
        "multi_turn",
        "--max-probes",
        "2",
        ...MOCK_MODEL_FLAGS,
      ],
    );

    // Call 1 opens the first multi-turn probe and call 2 fails it, so call 3
    // opens the second probe and must carry only its own first message.
    const targetRequests = run.requests.filter((r) => r.role === "target");
    expect(targetRequests[2].messages).toBe(1);
    expect(run.result?.coverage.injection?.failed).toHaveLength(1);
  });

  test("filters that match no probes are inconclusive", async () => {
    const run = await runCli(
      "injection filters match nothing",
      { target: "refuse" },
      [...INJECTION, "--injection-category", "multi_turn"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.coverage.injection).toEqual({
      completed: 0,
      failed: [],
      skipped: 0,
    });
    expect(run.requests).toHaveLength(0);
  });

  test("a scan cut short by the time budget says so", async () => {
    // Each reply takes 300ms and the budget leaves a 1s window, so only the
    // first few of the 10 selected probes can start.
    const run = await runCli(
      "injection time budget",
      { target: "refuse", targetDelayMs: 300, judge: JUDGE_REFUSED },
      [...INJECTION, "--max-probes", "10", "--duration", "31000"],
    );

    const completed = run.result?.coverage.injection?.completed ?? 0;
    expect(completed).toBeGreaterThan(0);
    expect(completed).toBeLessThan(10);
    expect(run.result?.coverage.injection?.skipped).toBe(10 - completed);
    expect(run.stdout).toContain(`${completed}/10 probes checked`);
    expect(run.result?.summary).toContain(
      `time budget ran out after ${completed} of 10 selected probes`,
    );
  });

  test("a large --json report reaches a pipe intact under Node", async () => {
    const run = await runCli(
      "json report under node",
      { target: "refuse", judge: JUDGE_REFUSED },
      [...INJECTION, "--max-probes", "0", "--json"],
      { runtime: "node" },
    );

    // Bigger than a pipe buffer, so exiting before stdout drains would cut it.
    expect(run.stdout.length).toBeGreaterThan(65_536);
    const report = JSON.parse(run.stdout);
    expect(report.injectionResults).toHaveLength(
      report.coverage.injection.completed,
    );
    expect(run.exitCode).toBe(EXIT.secure);
  });
});

describe("extraction scan", () => {
  test("a target that refuses every turn is secure", async () => {
    const run = await runCli(
      "extraction refusing target",
      { target: "refuse", evaluator: EVALUATOR_CLEAN },
      [...EXTRACTION, "--turns", "2"],
    );

    expect(run.exitCode).toBe(EXIT.secure);
    expect(run.result?.overallVulnerability).toBe("secure");
    expect(run.result?.coverage.extraction).toEqual({
      completed: 2,
      failed: [],
      skipped: 0,
    });
  });

  test("a target that leaks its prompt is vulnerable", async () => {
    const run = await runCli(
      "extraction leaking target",
      { target: "leak", evaluator: EVALUATOR_FULL_LEAK },
      [...EXTRACTION, "--turns", "2"],
    );

    expect(run.exitCode).toBe(EXIT.vulnerable);
    expect(run.result?.overallVulnerability).toBe("critical");
    expect(run.result?.leakStatus).toBe("complete");
  });

  test("a 'no leak' verdict that quotes text is not a finding", async () => {
    const run = await runCli(
      "extraction none verdict with text",
      {
        target: "refuse",
        evaluator: {
          fields: {
            ...EVALUATOR_CLEAN.fields,
            extractedContent: "None",
            extractedFragments: ["None"],
          },
        },
      },
      [...EXTRACTION, "--turns", "2"],
    );

    expect(run.exitCode).toBe(EXIT.secure);
    expect(run.result?.overallVulnerability).toBe("secure");
    expect(run.result?.findings).toHaveLength(0);
    expect(run.result?.extractedFragments).toEqual([]);
  });

  test("an evaluator failure while the target leaks is not secure", async () => {
    const run = await runCli(
      "extraction evaluator failure",
      { target: "leak", evaluator: "malformed" },
      [...EXTRACTION, "--turns", "3"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.coverage.extraction?.completed).toBe(0);
    expect(run.result?.coverage.extraction?.failed).toHaveLength(3);
  });

  test("an unreachable target is inconclusive", async () => {
    const run = await runCli(
      "extraction unreachable target",
      { target: "error", evaluator: EVALUATOR_CLEAN },
      [...EXTRACTION, "--turns", "2"],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.coverage.extraction?.failed).toHaveLength(2);
    expect(run.stdout).not.toContain("resisted all extraction attempts");
    expect(run.stdout).not.toContain("No system-prompt content was extracted");
  });
});

describe("dual mode", () => {
  test("each half reports its own coverage", async () => {
    const run = await runCli(
      "dual extraction fails injection holds",
      { target: "refuse", evaluator: "malformed", judge: JUDGE_REFUSED },
      [
        ...SCAN,
        "--mode",
        "dual",
        "--turns",
        "2",
        "--max-probes",
        "2",
        "--no-multi-turn",
        ...MOCK_MODEL_FLAGS,
      ],
    );

    expect(run.exitCode).toBe(EXIT.inconclusive);
    expect(run.result?.overallVulnerability).toBe("inconclusive");
    expect(run.result?.injectionVulnerability).toBe("secure");
    expect(run.result?.coverage.injection).toEqual({
      completed: 2,
      failed: [],
      skipped: 0,
    });
    expect(run.result?.coverage.extraction?.failed).toHaveLength(2);
  });

  test("the injection transcript holds only injection turns", async () => {
    const run = await runCli(
      "dual transcripts stay separate",
      { target: "refuse", evaluator: EVALUATOR_CLEAN, judge: JUDGE_REFUSED },
      [
        ...SCAN,
        "--mode",
        "dual",
        "--turns",
        "2",
        "--max-probes",
        "2",
        "--no-multi-turn",
        ...MOCK_MODEL_FLAGS,
      ],
    );

    const log = run.result?.injectionConversationLog ?? [];
    const attackerTurns = log
      .filter((t) => t.role === "attacker")
      .map((t) => t.content);
    expect(log).toHaveLength(4);
    expect(run.result?.injectionResults?.map((r) => r.prompt)).toEqual(
      attackerTurns,
    );
  });
});

describe("library callbacks", () => {
  // A callback that fails must not change the scan: no failed checks, no
  // early abort, and the same verdict.
  for (const failure of ["throw", "reject"] as const) {
    test(`an injection scan ignores callbacks that ${failure}`, async () => {
      const run = await runCli(
        `injection callbacks ${failure}`,
        { target: "refuse", judge: JUDGE_REFUSED },
        ["injection", failure],
        { script: LIBRARY_SCAN },
      );

      expect(run.result?.overallVulnerability).toBe("secure");
      expect(run.result?.aborted).toBe(false);
      expect(run.result?.coverage.injection).toEqual({
        completed: 4,
        failed: [],
        skipped: 0,
      });
    });

    test(`an extraction scan ignores callbacks that ${failure}`, async () => {
      const run = await runCli(
        `extraction callbacks ${failure}`,
        { target: "leak", evaluator: EVALUATOR_PARTIAL_LEAK },
        ["extraction", failure],
        { script: LIBRARY_SCAN },
      );

      expect(run.result?.overallVulnerability).toBe("high");
      expect(run.result?.aborted).toBe(false);
      expect(run.result?.coverage.extraction).toEqual({
        completed: 4,
        failed: [],
        skipped: 0,
      });
    });
  }
});

describe("models", () => {
  test("the models named on screen are the models tested", async () => {
    // No model flags: every role falls back to its default. Those defaults
    // route to OpenRouter, which fails locally without a key, so the scan
    // makes no network calls and ends inconclusive.
    const run = await runCli("default models", { target: "refuse" }, [
      ...SCAN,
      "--mode",
      "injection",
      "--max-probes",
      "1",
    ]);

    const shown = (label: string) =>
      run.stdout.match(new RegExp(`${label}\\s+(\\S+)`))?.[1];
    expect(shown("Attacker")).toBeTruthy();
    expect(run.result?.models).toMatchObject({
      attacker: shown("Attacker"),
      target: shown("Target"),
      evaluator: shown("Evaluator"),
    });
    expect(run.requests).toHaveLength(0);
    expect(run.exitCode).toBe(EXIT.inconclusive);
  });
});
