export type ScanMode = "extraction" | "injection";

export interface InjectionTestResult {
  id: string;
  testType: InjectionTestType;
  injectedInstruction: string;
  expectedBehavior: string;
  actualBehavior: string;
  success: boolean;
  confidence: number;
  technique: string;
  category: AttackCategory;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
  /** Modern behavioral-probe metadata (populated by the injection evaluator). */
  probeId?: string;
  probeCategory?: string;
  intent?: string;
  compliance?: "full" | "partial" | "refused";
  prompt?: string;
}

export type InjectionTestType =
  | "instruction_override"
  | "behavior_modification"
  | "policy_bypass"
  | "role_hijack"
  | "output_manipulation"
  | "action_execution"
  | "context_poisoning"
  | "guardrail_bypass";

export type AttackCategory =
  | "direct"
  | "encoding"
  | "persona"
  | "social"
  | "technical"
  | "crescendo"
  | "many_shot"
  | "ascii_art"
  | "cot_hijack"
  | "semantic_shift"
  | "policy_puppetry"
  | "context_overflow"
  | "reasoning_exploit"
  | "hybrid"
  | "tool_exploit"
  | "siren"
  | "echo_chamber"
  | "injection";

export type AttackPhase =
  | "reconnaissance"
  | "profiling"
  | "soft_probe"
  | "escalation"
  | "exploitation"
  | "persistence";

export type DefenseLevel = "none" | "weak" | "moderate" | "strong" | "hardened";

export type LeakStatus =
  | "none"
  | "hint"
  | "fragment"
  | "substantial"
  | "complete";

export interface AttackNode {
  id: string;
  parentId: string | null;
  depth: number;
  prompt: string;
  technique: string;
  category: AttackCategory;
  executed: boolean;
  response?: string;
  priorScore: number;
  posteriorScore: number;
  leakPotential: number;
  children: AttackNode[];
  mutations?: string[];
  reasoning?: string;
  timestamp: number;
}

export interface DefenseProfile {
  level: DefenseLevel;
  confidence: number;
  observedBehaviors: string[];
  guardrails: {
    type: string;
    strength: number;
    bypassed: boolean;
    bypassMethod?: string;
  }[];
  weaknesses: {
    category: AttackCategory;
    description: string;
    exploitability: number;
  }[];
  refusalTriggers: string[];
  safeTopics: string[];
  responsePatterns: {
    pattern: string;
    frequency: number;
    defenseIndicator: boolean;
  }[];
}

export interface Finding {
  id: string;
  turn: number;
  timestamp: number;
  extractedContent: string;
  contentType:
    | "system_prompt"
    | "rule"
    | "constraint"
    | "capability"
    | "persona"
    | "unknown";
  technique: string;
  category: AttackCategory;
  attackNodeId: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
  verified: boolean;
  verificationMethod?: string;
}

export interface ConversationTurn {
  id: string;
  turn: number;
  timestamp: number;
  role: "attacker" | "target";
  content: string;
  technique?: string;
  category?: AttackCategory;
  phase?: AttackPhase;
  attackNodeId?: string;
  leakStatus?: LeakStatus;
  defenseSignals?: string[];
  extractedFragments?: string[];
}

export interface AttackStrategy {
  id: string;
  name: string;
  description: string;
  applicableWhen: {
    defenseLevel?: DefenseLevel[];
    failedCategories?: AttackCategory[];
    turnRange?: [number, number];
    leakStatus?: LeakStatus[];
  };
  attackSequence: {
    category: AttackCategory;
    weight: number;
    techniques: string[];
  }[];
  expectedTurns: number;
  successRate: number;
  priority: number;
}

export interface StrategyState {
  currentStrategy: AttackStrategy | null;
  strategyHistory: {
    strategy: AttackStrategy;
    turns: number;
    outcome: "success" | "partial" | "failed" | "ongoing";
  }[];
  adaptationCount: number;
  lastAdaptationReason: string;
}

export interface StrategistOutput {
  selectedStrategy: AttackStrategy;
  reasoning: string;
  targetWeaknesses: string[];
  recommendedCategories: AttackCategory[];
  phaseTransition?: AttackPhase;
  shouldReset: boolean;
  resetReason?: string;
}

export interface AttackerOutput {
  attack: AttackNode;
  alternatives: AttackNode[];
  reasoning: string;
  expectedDefense: string;
}

export interface EvaluatorOutput {
  status: LeakStatus;
  confidence: number;
  extractedContent?: string;
  extractedFragments?: string[];
  techniqueEffectiveness: number;
  defenseAnalysis: {
    type: string;
    strength: number;
  }[];
  recommendation: string;
  suggestedCategories: AttackCategory[];
  shouldContinue: boolean;
  continueReason: string;
  shouldReset?: boolean;
  resetReason?: string;
}

export interface MutatorOutput {
  originalPrompt: string;
  mutations: {
    prompt: string;
    mutationType: string;
    expectedEffectiveness: number;
  }[];
  bestMutation: string;
  reasoning: string;
}

export interface ScanConfig {
  maxTurns: number;
  maxTreeDepth: number;
  branchingFactor: number;
  pruningThreshold: number;
  enableCrescendo: boolean;
  enableManyShot: boolean;
  enableBestOfN: boolean;
  bestOfNCount: number;
  maxTokensPerTurn: number;
  maxTotalTokens: number;
  attackerModel: string;
  evaluatorModel: string;
  targetModel?: string;
  enableVectorMemory?: boolean;
  enableInspector?: boolean;
  enableDefenseFingerprinting?: boolean;
  enableParallelEvaluation?: boolean;
  enableAdaptiveTemperature?: boolean;
  enableMultiTurnOrchestrator?: boolean;
  enableFailureAnalysis?: boolean;
  orchestratorPattern?: "auto" | "siren" | "echo_chamber" | "tombRaider";
  temperatureConfig?: Partial<TemperatureConfig>;
  inspectorModel?: string;
  scanMode?: ScanMode;
  enableDualMode?: boolean;
  injectionTestTypes?: InjectionTestType[];
  /** Filter modern injection probes by behavioral category. */
  injectionCategories?: string[];
  /** Filter modern injection probes by severity. */
  injectionSeverities?: string[];
  /** Cap the number of injection probes tested (0 = all). */
  maxInjectionProbes?: number;
  /** Include multi-turn grooming probes in the injection scan. */
  enableMultiTurnInjection?: boolean;
  /** Model used by the injection compliance judge. */
  injectionEvaluatorModel?: string;
  onProgress?: (state: ScanProgress) => Promise<void>;
  onFinding?: (finding: Finding) => Promise<void>;
  onDefenseDetected?: (fingerprint: DefenseFingerprint) => Promise<void>;
  onFailureRecorded?: (failure: FailedAttack) => Promise<void>;
  onInjectionResult?: (result: InjectionTestResult) => Promise<void>;
}

export interface ScanProgress {
  turn: number;
  maxTurns: number;
  phase: AttackPhase;
  strategy: string;
  leakStatus: LeakStatus;
  findingsCount: number;
  treeNodesExplored: number;
  estimatedCompletion: number;
}

export interface ScanResult {
  findings: Finding[];
  overallVulnerability: "critical" | "high" | "medium" | "low" | "secure";
  overallScore: number;
  leakStatus: LeakStatus;
  extractedSystemPrompt?: string;
  extractedFragments: string[];
  injectionResults?: InjectionTestResult[];
  injectionVulnerability?: "critical" | "high" | "medium" | "low" | "secure";
  injectionScore?: number;
  scanModes?: ScanMode[];
  turnsUsed: number;
  tokensUsed: number;
  treeNodesExplored: number;
  strategiesUsed: string[];
  defenseProfile: DefenseProfile;
  conversationLog: ConversationTurn[];
  extractionConversationLog?: ConversationTurn[];
  injectionConversationLog?: ConversationTurn[];
  attackTree?: AttackNode;
  summary: string;
  recommendations: string[];
  startTime: number;
  endTime: number;
  duration: number;
  error?: string;
  aborted: boolean;
  completionReason: string;
}

export interface AttackAnalysis {
  turn: number;
  techniqueUsed: string;
  category: AttackCategory;
  targetResponseSummary: string;
  responseLength: number;
  defenseSignals: string[];
  extractionResult: {
    status: LeakStatus;
    extractedContent: string | null;
    confidence: "high" | "medium" | "low" | null;
    evidence: string | null;
  };
  defenseAnalysis: {
    detectedGuardrails: string[];
    weaknessIdentified: string | null;
    bypassPotential: number;
  };
  nextAction: {
    category: AttackCategory;
    technique: string;
    rationale: string;
    priority: number;
  };
  cumulativeExtraction: string;
  progressTowardsGoal: number;
}

export interface InspectorOutput {
  extractedKnowledge: {
    topics: string[];
    behaviors: string[];
    constraints: string[];
    capabilities: string[];
    persona: string | null;
  };
  defenseFingerprint: DefenseFingerprint | null;
  identifiedWeaknesses: {
    weakness: string;
    confidence: number;
    exploitVector: AttackCategory;
    suggestedApproach: string;
  }[];
  responseAnalysis: {
    cooperativeLevel: number;
    verbosityLevel: number;
    consistencyScore: number;
    emotionalTone: string;
  };
  strategicGuidance: {
    recommendedCategories: AttackCategory[];
    avoidCategories: AttackCategory[];
    suggestedTechniques: string[];
    escalationRecommendation: "escalate" | "maintain" | "deescalate" | "pivot";
    reasoning: string;
  };
}

export type KnownDefenseSystem =
  | "azure_prompt_shield"
  | "meta_prompt_guard"
  | "llama_guard"
  | "anthropic_constitutional"
  | "openai_moderation"
  | "google_safety"
  | "nvidia_nemo_guardrails"
  | "custom_guardrail"
  | "no_defense"
  | "unknown";

export interface DefenseFingerprint {
  system: KnownDefenseSystem;
  confidence: number;
  signals: {
    signal: string;
    weight: number;
  }[];
  knownBypasses: {
    technique: string;
    category: AttackCategory;
    successRate: number;
  }[];
  variant?: string;
  detectedAt: number;
}

export interface DefenseFingerprintDatabase {
  systems: Record<
    KnownDefenseSystem,
    {
      name: string;
      description: string;
      patterns: {
        pattern: string | RegExp;
        weight: number;
      }[];
      knownBypasses: {
        technique: string;
        category: AttackCategory;
        successRate: number;
      }[];
      evasionDifficulty: number;
    }
  >;
}

export interface FailedAttack {
  id: string;
  prompt: string;
  technique: string;
  category: AttackCategory;
  defenseSystem: KnownDefenseSystem;
  defenseLevel: DefenseLevel;
  failureReason: FailureReason;
  targetResponse: string;
  responsePatterns: string[];
  timestamp: number;
  scanId?: string;
}

export type FailureReason =
  | "hard_refusal"
  | "soft_refusal"
  | "deflection"
  | "misdirection"
  | "partial_compliance"
  | "guardrail_block"
  | "context_not_primed"
  | "technique_detected"
  | "too_aggressive"
  | "semantic_similarity"
  | "unknown";

export interface LearningRecord {
  successfulPatterns: {
    pattern: string;
    category: AttackCategory;
    successCount: number;
    contexts: string[];
  }[];
  defensePatterns: {
    defenseSystem: KnownDefenseSystem;
    triggerPatterns: string[];
    bypassPatterns: string[];
  }[];
  adaptations: {
    fromTechnique: string;
    toTechnique: string;
    reason: string;
    outcome: "success" | "failure" | "partial";
    timestamp: number;
  }[];
}

export interface MultiTurnSequence {
  id: string;
  name: string;
  description: string;
  pattern: "siren" | "echo_chamber" | "crescendo" | "tombRaider" | "custom";
  steps: MultiTurnStep[];
  config: {
    minTurns: number;
    maxTurns: number;
    resetOnFailure: boolean;
    adaptiveEscalation: boolean;
  };
  expectedSuccessRate: number;
  targetDefenseLevels: DefenseLevel[];
}

export interface MultiTurnStep {
  order: number;
  purpose: string;
  category: AttackCategory;
  template: string;
  variables: string[];
  requiresPreviousSuccess: boolean;
  skipCondition?: string;
  expectedResponseType: "cooperative" | "neutral" | "resistant" | "any";
  successIndicators: string[];
  failureIndicators: string[];
}

export interface OrchestratorState {
  currentSequence: MultiTurnSequence | null;
  currentStep: number;
  stepResults: {
    step: number;
    success: boolean;
    extractedInfo: string[];
    defenseObserved: string[];
  }[];
  temperatureSchedule: number[];
  currentTemperature: number;
  consecutiveFailures: number;
  shouldEscalate: boolean;
}

export interface TemperatureConfig {
  initialTemperature: number;
  minTemperature: number;
  maxTemperature: number;
  successDecrement: number;
  failureIncrement: number;
  plateauIncrement: number;
  plateauThreshold: number;
  resetThreshold: number;
}

export interface TemperatureState {
  current: number;
  history: number[];
  adjustments: {
    turn: number;
    from: number;
    to: number;
    reason: string;
  }[];
}

export interface ParallelEvaluationResult {
  variations: {
    prompt: string;
    response: string;
    evaluationScore: number;
    leakStatus: LeakStatus;
    extractedContent?: string;
  }[];
  best: {
    index: number;
    prompt: string;
    response: string;
    score: number;
  };
  statistics: {
    averageScore: number;
    maxScore: number;
    minScore: number;
    leakRate: number;
  };
}

export interface GarakProbe {
  id: string;
  name: string;
  description: string;
  garakModule: string;
  garakClass: string;
  prompts: string[];
  detector: {
    type: "substring" | "regex" | "semantic" | "model";
    patterns?: string[];
    threshold?: number;
  };
  tags: string[];
  severity: "low" | "medium" | "high" | "critical";
  references: string[];
}

export interface Probe {
  id: string;
  category: AttackCategory;
  technique: string;
  prompt: string;
  phase: AttackPhase[];
  defenseLevel: DefenseLevel[];
  requiresContext: boolean;
  multiTurn: boolean;
  sequencePosition?: number;
  expectedSuccessRate: number;
  sophistication: number;
  stealthiness: number;
  variables?: string[];
}

export interface ProbeSequence {
  id: string;
  name: string;
  description: string;
  category: AttackCategory;
  probes: Probe[];
  requiresAllSteps: boolean;
  canShortCircuit: boolean;
  shortCircuitCondition?: string;
  expectedTurns: number;
  successRate: number;
}
