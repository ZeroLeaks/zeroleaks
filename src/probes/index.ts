import { advancedProbes } from "./advanced";
import { directProbes } from "./direct";
import { generateEncodingAttacks } from "./encoding";
import {
  modernProbes,
  probeSequences,
  getModernProbesByCategory,
  getProbesForDefenseLevel,
  getSequenceById,
  crescendoProbes,
  cotHijackProbes,
  manyShotProbes,
  asciiArtProbes,
  reasoningExploitProbes,
  policyPuppetryProbes,
  contextOverflowProbes,
} from "./modern";
import { personaProbes } from "./personas";
import { socialProbes } from "./social";
import { technicalProbes } from "./technical";
import {
  hybridProbes,
  getHybridProbesByType,
  getHybridProbesForDefense,
} from "./hybrid";
import {
  toolExploitProbes,
  getToolExploitsByType,
  getToolExploitsForDefense,
} from "./tool-exploits";
import {
  garakInspiredProbes,
  getAllGarakProbes,
  getGarakProbesBySeverity,
  getGarakProbesByModule,
  convertGarakToProbe,
} from "./garak-inspired";
import {
  injectionProbes,
  getInjectionProbesByType,
  getInjectionProbesForDefense,
  getCrescendoSequence,
  getProbesByResearch,
  getAllInjectionProbesAsStandard,
} from "./jailbreak-techniques";
import {
  INJECTION_PROBES,
  INJECTION_CATEGORIES,
  getInjectionProbesByCategory,
  type InjectionProbe,
  type InjectionCategory,
} from "./injections";
import type {
  AttackCategory,
  DefenseLevel,
  Probe as ModernProbe,
  ProbeSequence,
  GarakProbe,
  InjectionTestType,
} from "../types";

export interface Probe {
  id: string;
  category: string;
  technique: string;
  prompt: string;
}

export type ExtendedProbe = ModernProbe;

export type ProbeCategory =
  | "direct"
  | "encoding"
  | "persona"
  | "social"
  | "technical"
  | "advanced"
  | "crescendo"
  | "many_shot"
  | "cot_hijack"
  | "ascii_art"
  | "reasoning_exploit"
  | "policy_puppetry"
  | "context_overflow"
  | "semantic_shift"
  | "hybrid"
  | "tool_exploit"
  | "garak"
  | "injection"
  | "extraction"
  | "tool_hijacking"
  | "indirect_injection"
  | "authority_exploit"
  | "multi_turn"
  | "protocol_exploit";

function toStandardProbe(p: InjectionProbe): Probe {
  return {
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.multiTurn?.turns.join("\n\n") || p.prompt,
  };
}

export function getAllProbes(): Probe[] {
  const encodingAttacks = generateEncodingAttacks();
  const garakProbesConverted = getAllGarakProbes();
  const injectionProbesConverted = getAllInjectionProbesAsStandard();

  const modernProbesLegacy: Probe[] = modernProbes.map((p) => ({
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.prompt,
  }));

  const hybridProbesLegacy: Probe[] = hybridProbes.map((p) => ({
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.prompt,
  }));

  const toolExploitProbesLegacy: Probe[] = toolExploitProbes.map((p) => ({
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.prompt,
  }));

  const garakProbesLegacy: Probe[] = garakProbesConverted.map((p) => ({
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.prompt,
  }));

  const injectionProbesLegacy: Probe[] = injectionProbesConverted.map((p) => ({
    id: p.id,
    category: p.category,
    technique: p.technique,
    prompt: p.prompt,
  }));

  return [
    ...directProbes,
    ...encodingAttacks,
    ...personaProbes,
    ...socialProbes,
    ...technicalProbes,
    ...advancedProbes,
    ...modernProbesLegacy,
    ...hybridProbesLegacy,
    ...toolExploitProbesLegacy,
    ...garakProbesLegacy,
    ...injectionProbesLegacy,
    ...INJECTION_PROBES.map(toStandardProbe),
  ];
}

export function getAllExtendedProbes(): ExtendedProbe[] {
  const encodingAttacks = generateEncodingAttacks();
  const garakProbesConverted = getAllGarakProbes();
  const injectionProbesConverted = getAllInjectionProbesAsStandard();

  const legacyAsModern: ExtendedProbe[] = [
    ...directProbes,
    ...encodingAttacks,
    ...personaProbes,
    ...socialProbes,
    ...technicalProbes,
    ...advancedProbes,
  ].map((p) => ({
    ...p,
    category: p.category as AttackCategory,
    phase: ["soft_probe", "escalation"] as const,
    defenseLevel: ["none", "weak", "moderate"] as DefenseLevel[],
    requiresContext: false,
    multiTurn: false,
    expectedSuccessRate: 0.3,
    sophistication: 5,
    stealthiness: 5,
  }));

  return [
    ...legacyAsModern,
    ...modernProbes,
    ...hybridProbes,
    ...toolExploitProbes,
    ...garakProbesConverted,
    ...injectionProbesConverted,
  ];
}

export function getProbesByCategory(category: ProbeCategory): Probe[] {
  switch (category) {
    case "direct":
      return directProbes;
    case "encoding":
      return generateEncodingAttacks();
    case "persona":
      return personaProbes;
    case "social":
      return socialProbes;
    case "technical":
      return technicalProbes;
    case "advanced":
      return advancedProbes;
    case "crescendo":
      return crescendoProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "many_shot":
      return manyShotProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "cot_hijack":
      return cotHijackProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "ascii_art":
      return asciiArtProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "reasoning_exploit":
      return reasoningExploitProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "policy_puppetry":
      return policyPuppetryProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "context_overflow":
      return contextOverflowProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "hybrid":
      return hybridProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "tool_exploit":
      return toolExploitProbes.map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "garak":
      return getAllGarakProbes().map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "injection":
      return getAllInjectionProbesAsStandard().map((p) => ({
        id: p.id,
        category: p.category,
        technique: p.technique,
        prompt: p.prompt,
      }));
    case "extraction":
    case "tool_hijacking":
    case "indirect_injection":
    case "authority_exploit":
    case "multi_turn":
    case "protocol_exploit":
      return getInjectionProbesByCategory(category as InjectionCategory).map(
        toStandardProbe,
      );
    default:
      return [];
  }
}

export function getExtendedProbesByCategory(
  category: AttackCategory,
): ExtendedProbe[] {
  if (category === "hybrid") {
    return hybridProbes;
  }
  if (category === "tool_exploit") {
    return toolExploitProbes;
  }
  if (category === "injection") {
    return getAllInjectionProbesAsStandard();
  }
  return getModernProbesByCategory(category);
}

export function getProbesForDefense(level: DefenseLevel): ExtendedProbe[] {
  const modern = getProbesForDefenseLevel(level);
  const hybrid = getHybridProbesForDefense(level);
  const tool = getToolExploitsForDefense(level);
  const injection = getInjectionProbesForDefense(level);
  return [...modern, ...hybrid, ...tool, ...injection];
}

export function getProbeSequence(id: string): ProbeSequence | undefined {
  return getSequenceById(id);
}

export function getAllProbeSequences(): ProbeSequence[] {
  return probeSequences;
}

export function getRandomProbeFromCategory(category: ProbeCategory): Probe {
  const probes = getProbesByCategory(category);
  return probes[Math.floor(Math.random() * probes.length)];
}

export function getAttackSequence(length = 10): Probe[] {
  const categories: ProbeCategory[] = [
    "direct",
    "encoding",
    "persona",
    "social",
    "technical",
    "advanced",
    "hybrid",
    "tool_exploit",
    "garak",
    "injection",
  ];

  const sequence: Probe[] = [];

  sequence.push(getRandomProbeFromCategory("direct"));

  for (let i = 1; i < length; i++) {
    const category = categories[Math.floor(Math.random() * categories.length)];
    const probe = getRandomProbeFromCategory(category);

    if (sequence.some((p) => p.id === probe.id)) {
      const altCategory =
        categories[(categories.indexOf(category) + 1) % categories.length];
      sequence.push(getRandomProbeFromCategory(altCategory));
    } else {
      sequence.push(probe);
    }
  }

  return sequence;
}

export function getProbesForPhase(
  phase: "reconnaissance" | "soft" | "escalation" | "advanced",
): Probe[] {
  switch (phase) {
    case "reconnaissance":
      return [...directProbes.slice(0, 5), ...socialProbes.slice(0, 3)];
    case "soft":
      return [...directProbes, ...socialProbes];
    case "escalation":
      return [
        ...technicalProbes,
        ...personaProbes,
        ...hybridProbes.map((p) => ({
          id: p.id,
          category: p.category,
          technique: p.technique,
          prompt: p.prompt,
        })),
      ];
    case "advanced":
      return [
        ...advancedProbes,
        ...generateEncodingAttacks().slice(0, 10),
        ...toolExploitProbes.map((p) => ({
          id: p.id,
          category: p.category,
          technique: p.technique,
          prompt: p.prompt,
        })),
        ...getAllInjectionProbesAsStandard()
          .slice(0, 10)
          .map((p) => ({
            id: p.id,
            category: p.category,
            technique: p.technique,
            prompt: p.prompt,
          })),
      ];
    default:
      return getAllProbes();
  }
}

export { advancedProbes } from "./advanced";
export { directProbes } from "./direct";
export {
  encodingProbes,
  encodingUtils,
  generateEncodingAttacks,
} from "./encoding";
export { danPersonas, personaProbes } from "./personas";
export { socialProbes } from "./social";
export { technicalProbes } from "./technical";

export {
  modernProbes,
  probeSequences,
  crescendoProbes,
  cotHijackProbes,
  manyShotProbes,
  asciiArtProbes,
  reasoningExploitProbes,
  policyPuppetryProbes,
  contextOverflowProbes,
  getModernProbesByCategory,
  getProbesForDefenseLevel,
  getSequenceById,
} from "./modern";

export {
  hybridProbes,
  xssStyleProbes,
  csrfStyleProbes,
  injectionChainProbes,
  agenticExploitProbes,
  protocolConfusionProbes,
  getHybridProbesByType,
  getHybridProbesForDefense,
} from "./hybrid";

export {
  toolExploitProbes,
  imistProbes,
  mcpInjectionProbes,
  functionCallProbes,
  authBypassProbes,
  agentChainProbes,
  getToolExploitsByType,
  getToolExploitsForDefense,
} from "./tool-exploits";

export {
  garakInspiredProbes,
  danVariantProbes,
  encodingBypassProbes,
  continuationProbes,
  promptInjectionProbes,
  leakageProbes,
  maliciousInstructionProbes,
  getAllGarakProbes,
  getGarakProbesBySeverity,
  getGarakProbesByModule,
  convertGarakToProbe,
} from "./garak-inspired";

export {
  injectionProbes,
  skeletonKeyProbes,
  crescendoProbes as injectionCrescendoProbes,
  echoChamberProbes,
  manyShotProbes as injectionManyShotProbes,
  semanticVariationProbes,
  toolPoisoningProbes,
  indirectInjectionProbes,
  asciiArtProbes as injectionAsciiArtProbes,
  promptwareProbes,
  hybridInjectionProbes,
  outputControlProbes,
  roleHijackProbes,
  getInjectionProbesByType,
  getInjectionProbesForDefense,
  getCrescendoSequence,
  getProbesByResearch,
  getAllInjectionProbesAsStandard,
} from "./jailbreak-techniques";

export {
  INJECTION_PROBES,
  INJECTION_CATEGORIES,
  INJECTION_SEVERITIES,
  getInjectionProbesByCategory,
  getInjectionProbesBySeverity,
  getSingleTurnProbes,
  getMultiTurnProbes,
  countProbesByCategory,
  generateDynamicProbes,
  mapCategoryToTestType,
} from "./injections";

export {
  ATTACK_CORPUS,
  CORPUS_VERSION,
  getSeedsByKind,
  getSeedsForBenchmark,
  getSeedsBySurface,
} from "./redteam-corpus";

export type {
  InjectionProbe,
  InjectionCategory,
  InjectionSeverity,
  UserTool,
} from "./injections";
export type {
  AttackSeed,
  AttackSeedKind,
  AttackSurface,
} from "./redteam-corpus";
export type { GarakProbe };
