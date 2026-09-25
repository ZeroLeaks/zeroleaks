/**
 * Runs a scan through the library API with callbacks that fail, the way a
 * caller's buggy callback would. The harness spawns it like the CLI:
 *
 *   bun library-scan.ts <extraction|injection> <throw|reject>
 *
 * The result goes to result.json in the working directory.
 */
import { writeFileSync } from "fs";
import { runSecurityScan } from "../../src";
import { SYSTEM_PROMPT } from "./harness";
import { MOCK_MODELS } from "./mock-llm";

const [scanMode, failure] = process.argv.slice(2) as [
  "extraction" | "injection",
  "throw" | "reject",
];

// The callback types return a promise, but a plain function can throw
// before it returns one.
const failingCallback =
  failure === "throw"
    ? () => {
        throw new Error("Callback threw");
      }
    : () => Promise.reject(new Error("Callback rejected"));

const result = await runSecurityScan(SYSTEM_PROMPT, {
  scanMode,
  maxTurns: 4,
  maxInjectionProbes: 4,
  enableMultiTurnInjection: false,
  attackerModel: MOCK_MODELS.attacker,
  targetModel: MOCK_MODELS.target,
  evaluatorModel: MOCK_MODELS.evaluator,
  injectionEvaluatorModel: MOCK_MODELS.judge,
  onProgress: failingCallback,
  onFinding: failingCallback,
  onInjectionResult: failingCallback,
});

writeFileSync("result.json", JSON.stringify(result, null, 2));
