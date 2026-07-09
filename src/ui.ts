/**
 * Tiny dependency-free terminal UI helpers: ANSI colors, severity styling,
 * score bars, and boxes. Honors NO_COLOR / non-TTY / --no-color.
 */

const forceColor = process.env.FORCE_COLOR;
let colorEnabled =
  process.env.NO_COLOR === undefined &&
  forceColor !== "0" &&
  (forceColor !== undefined || (process.stdout.isTTY ?? false));

export function setColorEnabled(enabled: boolean): void {
  colorEnabled = enabled;
}

export function isColorEnabled(): boolean {
  return colorEnabled;
}

function wrap(code: number, close: number) {
  return (text: string | number): string =>
    colorEnabled ? `\x1b[${code}m${text}\x1b[${close}m` : String(text);
}

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  italic: wrap(3, 23),
  underline: wrap(4, 24),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
  white: wrap(97, 39),
  bgRed: wrap(41, 49),
  bgGreen: wrap(42, 49),
  bgYellow: wrap(43, 49),
};

export type Severity = "critical" | "high" | "medium" | "low" | "secure";

// Built from a char code so the source carries no literal control character.
const ANSI_PATTERN = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");

/** Strip ANSI codes to measure visible width. */
export function visibleLength(text: string): number {
  return text.replace(ANSI_PATTERN, "").length;
}

export function severityColor(
  severity: string,
): (t: string | number) => string {
  switch (severity.toLowerCase()) {
    case "critical":
      return c.red;
    case "high":
      return (t) => c.red(t);
    case "medium":
      return c.yellow;
    case "low":
      return c.blue;
    case "secure":
      return c.green;
    default:
      return c.gray;
  }
}

const SEVERITY_ICON: Record<string, string> = {
  critical: "✖",
  high: "▲",
  medium: "●",
  low: "○",
  secure: "✔",
};

export function severityBadge(severity: string): string {
  const label = severity.toUpperCase();
  const icon = SEVERITY_ICON[severity.toLowerCase()] ?? "•";
  return severityColor(severity)(c.bold(`${icon} ${label}`));
}

/** A colored 0-100 score bar. Higher score = more secure = greener. */
export function scoreBar(score: number, width = 24): string {
  const clamped = Math.max(0, Math.min(100, score));
  const filled = Math.round((clamped / 100) * width);
  const empty = width - filled;
  const color = clamped >= 80 ? c.green : clamped >= 50 ? c.yellow : c.red;
  const bar = color("█".repeat(filled)) + c.gray("░".repeat(empty));
  return `${bar} ${c.bold(`${clamped}/100`)}`;
}

export function heading(text: string): string {
  return `\n${c.bold(c.cyan(text))}\n${c.gray("─".repeat(Math.max(text.length, 12)))}`;
}

export function box(title: string, lines: string[]): string {
  const width = Math.max(visibleLength(title), ...lines.map(visibleLength), 24);
  const top = c.cyan(
    `╭─ ${c.bold(title)} ${"─".repeat(Math.max(0, width - visibleLength(title) - 1))}╮`,
  );
  const body = lines
    .map((line) => {
      const pad = " ".repeat(Math.max(0, width - visibleLength(line)));
      return `${c.cyan("│")} ${line}${pad} ${c.cyan("│")}`;
    })
    .join("\n");
  const bottom = c.cyan(`╰${"─".repeat(width + 3)}╯`);
  return `${top}\n${body}\n${bottom}`;
}

export const BANNER = `${c.cyan(c.bold("  ▟▛ ZeroLeaks"))} ${c.gray("· AI Security Scanner")}`;

export function bullet(text: string, color = c.gray): string {
  return `  ${color("›")} ${text}`;
}
