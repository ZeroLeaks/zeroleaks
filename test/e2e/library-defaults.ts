/**
 * Runs a two-turn extraction scan through the library API and leaves every
 * other option out, so runSecurityScan's own defaults apply:
 *
 *   bun library-defaults.ts <mock|default>
 *
 * "mock" names the mock models and nothing else. "default" names no models.
 * The result goes to result.json in the working directory.
 */
import { writeFileSync } from "fs";
import { runSecurityScan } from "../../src";
import { SYSTEM_PROMPT } from "./harness";
import { MOCK_MODELS } from "./mock-llm";

const models =
  process.argv[2] === "mock"
    ? {
        attackerModel: MOCK_MODELS.attacker,
        targetModel: MOCK_MODELS.target,
        evaluatorModel: MOCK_MODELS.evaluator,
      }
    : {};

const result = await runSecurityScan(SYSTEM_PROMPT, { maxTurns: 2, ...models });

writeFileSync("result.json", JSON.stringify(result, null, 2));
