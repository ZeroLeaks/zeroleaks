import { createOpenAI } from "@ai-sdk/openai";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import type { LanguageModelV1 } from "ai";

export interface ProviderKeys {
  openrouterApiKey?: string;
  openaiApiKey?: string;
  /** An OpenAI-compatible endpoint; defaults to `OPENAI_BASE_URL`. */
  openaiBaseUrl?: string;
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
 * With `OPENAI_BASE_URL` set, the model goes to that OpenAI-compatible
 * endpoint (OpenAI, Azure, a gateway, Ollama, vLLM, LM Studio...) when either:
 *   - the id is OpenAI-style (`openai/*`, `gpt-*`, `o1/o3/o4-*`), or
 *   - there is no OpenRouter key, so the endpoint is the only provider.
 * A leading `openai/` is stripped, so `openai/llama3.1:8b` sends `llama3.1:8b`
 * to the endpoint even when OpenRouter serves the other roles. Local servers
 * don't need a key.
 *
 * Without a base URL, OpenAI-style ids go to the OpenAI API when an OpenAI key
 * is available, and everything else goes through OpenRouter.
 */
export function resolveModel(
  model: string,
  opts: ProviderKeys = {},
): LanguageModelV1 {
  const openaiApiKey = opts.openaiApiKey ?? process.env.OPENAI_API_KEY;
  const openrouterApiKey =
    opts.openrouterApiKey ?? process.env.OPENROUTER_API_KEY;
  const baseURL =
    opts.openaiBaseUrl ?? (process.env.OPENAI_BASE_URL || undefined);

  const useOpenAi = baseURL
    ? isOpenAiModel(model) || !openrouterApiKey
    : Boolean(openaiApiKey) && isOpenAiModel(model);

  if (useOpenAi) {
    const openai = createOpenAI({
      // The SDK throws on a missing key; keyless local servers ignore it.
      apiKey: openaiApiKey ?? "",
      baseURL,
    });
    return openai(model.replace(/^openai\//, ""));
  }

  const openrouter = createOpenRouter({ apiKey: openrouterApiKey });
  return openrouter(model) as LanguageModelV1;
}
