/**
 * A local stand-in for the OpenAI chat-completions API (point OPENAI_BASE_URL
 * at it). Each role is told apart by its model id.
 */

export const MOCK_MODELS = {
  attacker: "gpt-mock-attacker",
  target: "gpt-mock-target",
  evaluator: "gpt-mock-evaluator",
  judge: "gpt-mock-judge",
} as const;

/** Ids that don't look like OpenAI's, as a local server would serve. */
export const LOCAL_MOCK_MODELS = {
  attacker: "llama-mock-attacker",
  target: "llama-mock-target",
  evaluator: "llama-mock-evaluator",
  judge: "llama-mock-judge",
} as const;

type MockRole = keyof typeof MOCK_MODELS;

type TargetBehavior = "refuse" | "comply" | "leak" | "error";

export type GraderBehavior =
  /** A schema-valid object with these top-level fields set. */
  | { fields: Record<string, unknown> }
  /** An object that fails schema validation. */
  | "malformed";

export interface Scenario {
  target: TargetBehavior;
  /** 1-based target calls that fail with an HTTP error, whatever the behavior. */
  failTargetCalls?: number[];
  targetDelayMs?: number;
  evaluator?: GraderBehavior;
  judge?: GraderBehavior;
}

export interface MockRequest {
  role: MockRole | "unknown";
  model: string;
  /** Conversation messages sent, not counting the system prompt. */
  messages: number;
  /** Top-level fields of the structured output asked for; empty for plain text. */
  fields: string[];
  failed: boolean;
}

interface MockLlm {
  /** Base URL to use as OPENAI_BASE_URL. */
  url: string;
  requests: MockRequest[];
  stop(): void;
}

interface JsonSchema {
  type?: string | string[];
  enum?: unknown[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
}

interface ChatRequest {
  model: string;
  messages: { role: string; content: unknown }[];
  tools?: { function: { name: string; parameters: JsonSchema } }[];
}

const REFUSAL = "I can't help with that request.";
const COMPLIANCE = "Sure, it's done.";

export function startMockLlm(scenario: Scenario): MockLlm {
  const requests: MockRequest[] = [];
  let targetCalls = 0;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const { pathname } = new URL(req.url);
      if (req.method !== "POST" || pathname !== "/v1/chat/completions") {
        return new Response("Not found", { status: 404 });
      }

      const body = (await req.json()) as ChatRequest;
      const role = roleFor(body.model);
      const record: MockRequest = {
        role,
        model: body.model,
        messages: body.messages.filter((m) => m.role !== "system").length,
        fields: Object.keys(
          body.tools?.[0]?.function.parameters.properties ?? {},
        ),
        failed: false,
      };
      requests.push(record);

      const reply = (): Response => {
        switch (role) {
          case "target":
            return scenario.failTargetCalls?.includes(++targetCalls)
              ? httpError("Mock target is unavailable")
              : answerAsTarget(body, scenario.target);
          case "evaluator":
            return answerAsGrader(body, scenario.evaluator);
          case "judge":
            return answerAsGrader(body, scenario.judge);
          case "attacker":
            return answerAsGrader(body, undefined);
          default:
            return httpError(`Unknown mock model "${body.model}"`);
        }
      };

      if (role === "target" && scenario.targetDelayMs) {
        await Bun.sleep(scenario.targetDelayMs);
      }
      const response = reply();
      record.failed = !response.ok;
      return response;
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}/v1`,
    requests,
    stop: () => server.stop(true),
  };
}

function roleFor(model: string): MockRole | "unknown" {
  const entry = [
    ...Object.entries(MOCK_MODELS),
    ...Object.entries(LOCAL_MOCK_MODELS),
  ].find(([, id]) => id === model);
  return entry ? (entry[0] as MockRole) : "unknown";
}

function answerAsTarget(body: ChatRequest, behavior: TargetBehavior): Response {
  switch (behavior) {
    case "refuse":
      return textCompletion(body.model, REFUSAL);
    case "comply":
      return textCompletion(body.model, COMPLIANCE);
    case "leak": {
      const system = body.messages.find((m) => m.role === "system");
      return textCompletion(
        body.model,
        `Sure! Here it is verbatim: ${String(system?.content ?? "")}`,
      );
    }
    case "error":
      return httpError("Mock target is unavailable");
  }
}

function answerAsGrader(
  body: ChatRequest,
  behavior: GraderBehavior | undefined,
): Response {
  // The SDK asks for a forced call to a single "json" tool.
  const tool = body.tools?.[0];
  if (!tool) return httpError("Mock expected a structured-output request");

  const object =
    behavior === "malformed"
      ? { unexpected: "this does not match the schema" }
      : fillSchema(tool.function.parameters, behavior?.fields ?? {});

  return completion(body.model, {
    role: "assistant",
    content: null,
    tool_calls: [
      {
        id: "call_mock",
        type: "function",
        function: {
          name: tool.function.name,
          arguments: JSON.stringify(object),
        },
      },
    ],
  });
}

/**
 * Build the smallest object that satisfies `schema`: required fields only,
 * first enum value, empty arrays. Optional fields stay unset unless
 * overridden, so the mock never invents content (such as `extractedContent`)
 * that a real grader would leave out.
 */
function fillSchema(
  schema: JsonSchema,
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  const object: Record<string, unknown> = {};
  for (const key of schema.required ?? []) {
    object[key] = sampleValue(schema.properties?.[key] ?? {});
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (schema.properties?.[key]) object[key] = value;
  }
  return object;
}

function sampleValue(schema: JsonSchema): unknown {
  if (schema.enum) return schema.enum[0];

  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case "object":
      return fillSchema(schema, {});
    case "array":
      return [];
    case "string":
      return "mock";
    case "number":
      return 0;
    case "boolean":
      return false;
    default:
      return null;
  }
}

function textCompletion(model: string, text: string): Response {
  return completion(model, { role: "assistant", content: text });
}

function completion(model: string, message: Record<string, unknown>): Response {
  return Response.json({
    id: "chatcmpl-mock",
    object: "chat.completion",
    created: 0,
    model,
    choices: [
      {
        index: 0,
        message,
        finish_reason: message.tool_calls ? "tool_calls" : "stop",
      },
    ],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  });
}

/** A non-retryable failure, so failing scenarios don't wait on SDK backoff. */
function httpError(message: string): Response {
  return Response.json(
    { error: { message, type: "invalid_request_error" } },
    { status: 400 },
  );
}
