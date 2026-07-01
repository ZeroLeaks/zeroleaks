import { createOpenAI } from "@ai-sdk/openai";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import type { LanguageModelV1 } from "ai";

/** Routers that can serve the model ids not sent to the OpenAI API directly. */
export type RouterProvider = "openrouter" | "requesty";

export const ROUTER_PROVIDERS: readonly RouterProvider[] = [
  "openrouter",
  "requesty",
];

export const REQUESTY_BASE_URL = "https://router.requesty.ai/v1";

export interface ProviderKeys {
  openrouterApiKey?: string;
  openaiApiKey?: string;
  requestyApiKey?: string;
  /**
   * Router for ids that do not go to the OpenAI API. Defaults to OpenRouter;
   * falls back to `ZEROLEAKS_PROVIDER` when unset. Requesty is only used when
   * selected here, via that env var, or via a `requesty/` model id prefix.
   */
  provider?: RouterProvider;
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
 * Does this model id carry an explicit `requesty/` prefix? The prefix is
 * stripped before the id is sent to Requesty, so `requesty/openai/gpt-5`
 * becomes `openai/gpt-5` on the Requesty side.
 */
export function isRequestyModel(model: string): boolean {
  return model.trim().toLowerCase().startsWith("requesty/");
}

/**
 * Validate a router provider name (CLI flag or `ZEROLEAKS_PROVIDER`).
 * An empty value means the default, OpenRouter; anything unknown throws so a
 * typo does not silently fall back to another provider.
 */
export function parseProvider(value?: string): RouterProvider {
  const v = (value ?? "").trim().toLowerCase();
  if (v === "") return "openrouter";
  if ((ROUTER_PROVIDERS as readonly string[]).includes(v)) {
    return v as RouterProvider;
  }
  throw new Error(
    `Unknown provider "${value}". Valid values: ${ROUTER_PROVIDERS.join(", ")}`,
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
 *
 * Requesty replaces OpenRouter as that router only when chosen explicitly:
 * `opts.provider`, `ZEROLEAKS_PROVIDER=requesty`, or a `requesty/` model id
 * prefix. Its key comes from `opts.requestyApiKey` or `REQUESTY_API_KEY`.
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

  const provider =
    opts.provider ?? parseProvider(process.env.ZEROLEAKS_PROVIDER);

  if (provider === "requesty" || isRequestyModel(model)) {
    const requesty = createOpenAI({
      name: "requesty",
      apiKey: opts.requestyApiKey ?? process.env.REQUESTY_API_KEY,
      baseURL: REQUESTY_BASE_URL,
      compatibility: "compatible",
    });
    return requesty.chat(model.trim().replace(/^requesty\//i, ""));
  }

  const openrouter = createOpenRouter({
    apiKey: opts.openrouterApiKey ?? process.env.OPENROUTER_API_KEY,
  });
  return openrouter(model) as LanguageModelV1;
}
