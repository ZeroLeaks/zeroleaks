import {
  getAllProbes,
  getProbesByCategory,
  getProbesForDefense,
  getProbesForPhase,
  getAllProbeSequences,
  allDocumentedTechniques,
  getCVETechniques,
} from "zeroleaks";

console.log("=== ZEROLEAKS PROBE LIBRARY ===\n");

const allProbes = getAllProbes();
console.log(`Total probes available: ${allProbes.length}\n`);

const categories = [
  "direct",
  "encoding",
  "persona",
  "social",
  "technical",
  "crescendo",
];
for (const category of categories) {
  const probes = getProbesByCategory(category);
  console.log(`${category.toUpperCase()}: ${probes.length} probes`);
}

console.log("\n=== PROBES BY DEFENSE LEVEL ===\n");
const defenseLevels = [
  "none",
  "weak",
  "moderate",
  "strong",
  "hardened",
] as const;
for (const level of defenseLevels) {
  const probes = getProbesForDefense(level);
  console.log(`${level.toUpperCase()}: ${probes.length} effective probes`);
}

console.log("\n=== PROBES BY ATTACK PHASE ===\n");
const phases = [
  "reconnaissance",
  "profiling",
  "soft_probe",
  "escalation",
  "exploitation",
] as const;
for (const phase of phases) {
  const probes = getProbesForPhase(phase);
  console.log(`${phase.toUpperCase()}: ${probes.length} probes`);
}

console.log("\n=== MULTI-TURN SEQUENCES ===\n");
const sequences = getAllProbeSequences();
for (const seq of sequences) {
  console.log(`${seq.name}`);
  console.log(`  Category: ${seq.category}`);
  console.log(`  Probes: ${seq.probes.length}`);
  console.log(`  Expected turns: ${seq.expectedTurns}`);
  console.log(`  Success rate: ${Math.round(seq.successRate * 100)}%`);
}

console.log("\n=== DOCUMENTED CVE TECHNIQUES ===\n");
const cves = getCVETechniques();
for (const cve of cves) {
  console.log(`${cve.name}`);
  console.log(`  Reference: ${cve.source.reference}`);
  console.log(`  CVSS: ${cve.source.cvss || "N/A"}`);
  console.log(`  Targets: ${cve.targetedSystems.join(", ")}`);
}
