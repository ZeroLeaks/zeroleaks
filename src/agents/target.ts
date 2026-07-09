import { generateText } from "ai";
import { resolveModel } from "../provider";
import { generateId } from "../utils";
import type { ConversationTurn } from "../types";

export interface Target {
  systemPrompt: string;
  conversationHistory: ConversationTurn[];
  respond: (userMessage: string) => Promise<string>;
  resetConversation: () => void;
}

export interface TargetConfig {
  model?: string;
  apiKey?: string;
}

export async function createTarget(
  systemPrompt: string,
  config?: TargetConfig,
): Promise<Target> {
  let conversationHistory: ConversationTurn[] = [];
  let turnCount = 0;
  const model = config?.model || "x-ai/grok-3-mini";

  const target: Target = {
    systemPrompt,
    get conversationHistory() {
      return conversationHistory;
    },
    set conversationHistory(value: ConversationTurn[]) {
      conversationHistory = value;
    },

    resetConversation() {
      conversationHistory = [];
      turnCount = 0;
    },

    async respond(userMessage: string): Promise<string> {
      turnCount++;

      const messages = conversationHistory
        .filter((turn) => turn.role === "attacker" || turn.role === "target")
        .map((turn) => ({
          role:
            turn.role === "attacker"
              ? ("user" as const)
              : ("assistant" as const),
          content:
            typeof turn.content === "string"
              ? turn.content
              : String(turn.content),
        }));

      messages.push({ role: "user" as const, content: userMessage });

      const response = await generateText({
        model: resolveModel(model, { openrouterApiKey: config?.apiKey }),
        system: systemPrompt,
        messages,
        maxRetries: 2,
      });

      conversationHistory.push({
        id: generateId("target-atk"),
        turn: turnCount,
        timestamp: Date.now(),
        role: "attacker",
        content: userMessage,
      });

      conversationHistory.push({
        id: generateId("target-resp"),
        turn: turnCount,
        timestamp: Date.now(),
        role: "target",
        content: response.text,
      });

      return response.text;
    },
  };

  return target;
}
