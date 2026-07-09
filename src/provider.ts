import { createOpenAI } from "@ai-sdk/openai";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import type { LanguageModelV1 } from "ai";

export interface ProviderKeys {
  openrouterApiKey?: string;
  openaiApiKey?: string;
}

/**
 * Does this model id refer to an OpenAI model that should go to the OpenAI API
 * directly rather than through OpenRouter? Matches an explicit `openai/` prefix
 * or the bare OpenAI model families (gpt-*, o1/o3/o4-*, chatgpt-*).
 */
export function isOpenAiModel(model: string): boolean {
  const m = model.trim().toLowerCase();
  return (
    m.startsWith("openai/") ||
    /^(gpt-|gpt4|chatgpt-|o[134](-|$)|text-embedding-|davinci|babbage)/.test(m)
  );
}

/**
 * Resolve a model id to an AI SDK model.
 *
 * An OpenAI-style id routes to the OpenAI API when an OpenAI key is available
 * (via `opts.openaiApiKey` or `OPENAI_API_KEY`); everything else — and OpenAI
 * ids with no OpenAI key — goes through OpenRouter, preserving prior behavior.
 * Set `OPENAI_BASE_URL` to target an OpenAI-compatible endpoint (Azure, a
 * gateway, a local server).
 */
export function resolveModel(
  model: string,
  opts: ProviderKeys = {},
): LanguageModelV1 {
  const openaiApiKey = opts.openaiApiKey ?? process.env.OPENAI_API_KEY;

  if (openaiApiKey && isOpenAiModel(model)) {
    const openai = createOpenAI({
      apiKey: openaiApiKey,
      baseURL: process.env.OPENAI_BASE_URL || undefined,
    });
    return openai(model.replace(/^openai\//, ""));
  }

  const openrouter = createOpenRouter({
    apiKey: opts.openrouterApiKey ?? process.env.OPENROUTER_API_KEY,
  });
  return openrouter(model) as LanguageModelV1;
}
