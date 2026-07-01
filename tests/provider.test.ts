import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { isRequestyModel, parseProvider, resolveModel } from "../src/provider";

const ENV_KEYS = [
  "OPENROUTER_API_KEY",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "REQUESTY_API_KEY",
  "ZEROLEAKS_PROVIDER",
] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

describe("parseProvider", () => {
  test("defaults to openrouter and accepts known names", () => {
    expect(parseProvider(undefined)).toBe("openrouter");
    expect(parseProvider("")).toBe("openrouter");
    expect(parseProvider(" OpenRouter ")).toBe("openrouter");
    expect(parseProvider("requesty")).toBe("requesty");
  });

  test("rejects unknown providers instead of falling back", () => {
    expect(() => parseProvider("gpt")).toThrow(/Unknown provider "gpt"/);
  });
});

describe("resolveModel", () => {
  test("uses OpenRouter by default, even when only a Requesty key is set", () => {
    process.env.REQUESTY_API_KEY = "rq-test";
    const model = resolveModel("anthropic/claude-sonnet-5");
    expect(model.provider).toStartWith("openrouter");
    expect(model.modelId).toBe("anthropic/claude-sonnet-5");
  });

  test("requesty/ prefix routes that model to Requesty and strips the prefix", () => {
    process.env.OPENROUTER_API_KEY = "sk-or-test";
    process.env.REQUESTY_API_KEY = "rq-test";
    expect(isRequestyModel("anthropic/claude-sonnet-5")).toBe(false);
    const model = resolveModel("requesty/anthropic/claude-sonnet-4-5");
    expect(model.provider).toStartWith("requesty");
    expect(model.modelId).toBe("anthropic/claude-sonnet-4-5");
  });

  test("provider option or ZEROLEAKS_PROVIDER routes every agent model to Requesty", () => {
    process.env.REQUESTY_API_KEY = "rq-test";
    const viaOption = resolveModel("anthropic/claude-sonnet-5", {
      provider: "requesty",
    });
    expect(viaOption.provider).toStartWith("requesty");
    expect(viaOption.modelId).toBe("anthropic/claude-sonnet-5");

    process.env.ZEROLEAKS_PROVIDER = "requesty";
    for (const id of ["anthropic/claude-opus-4.8", "x-ai/grok-4"]) {
      expect(resolveModel(id).provider).toStartWith("requesty");
    }
  });

  test("OpenAI ids keep the OpenAI direct path when an OpenAI key is set", () => {
    process.env.REQUESTY_API_KEY = "rq-test";
    const routed = resolveModel("openai/gpt-5", { provider: "requesty" });
    expect(routed.provider).toStartWith("requesty");
    expect(routed.modelId).toBe("openai/gpt-5");

    process.env.OPENAI_API_KEY = "sk-test";
    const direct = resolveModel("openai/gpt-5", { provider: "requesty" });
    expect(direct.provider).toStartWith("openai");
    expect(direct.modelId).toBe("gpt-5");
  });
});

describe("cli provider selection", () => {
  const runCli = (...args: string[]) => {
    const env: Record<string, string | undefined> = { ...process.env };
    for (const key of ENV_KEYS) delete env[key];
    return Bun.spawnSync({
      cmd: ["bun", "src/bin/cli.ts", "scan", "--prompt", "test", ...args],
      cwd: `${import.meta.dir}/..`,
      env,
      stderr: "pipe",
      stdout: "pipe",
    });
  };

  test("rejects an unknown --provider", () => {
    const result = runCli("--provider", "gpt", "--api-key", "sk-or-test");
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain('Unknown provider "gpt"');
  });

  test("requires a Requesty key with --provider requesty", () => {
    const result = runCli("--provider", "requesty", "--api-key", "sk-or-test");
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain("Requesty API key");
  });
});
