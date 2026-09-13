/**
 * Safe numeric formatting and parsing utilities for VigiLock.
 * Handles null, undefined, empty strings, NaN, non-numeric API strings (e.g. "Not Available"),
 * percentage ratios (0.0 to 1.0), and percentage values (0 to 100).
 */

/**
 * Safely parses any input into a valid JavaScript number, or null if not numeric.
 */
export function parseNumeric(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const lower = trimmed.toLowerCase();
    if (
      lower === "unavailable" ||
      lower === "not available" ||
      lower === "n/a" ||
      lower === "none" ||
      lower === "null" ||
      lower === "undefined" ||
      lower === "nan"
    ) {
      return null;
    }
    // Remove trailing percent sign or quotes if present
    const cleaned = trimmed.replace(/[%'"]/g, "").trim();
    if (!cleaned) return null;
    const parsed = Number(cleaned);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/**
 * Safely formats a numeric value (or string representation) as a percentage string (e.g. "95.25%").
 * Automatically scales decimal ratios (<= 1.0) to percentage (0 - 100).
 *
 * Examples:
 * - formatPercent(0.9525, 2) -> "95.25%"
 * - formatPercent(87, 2) -> "87.00%"
 * - formatPercent(0, 2) -> "0.00%"
 * - formatPercent("95.25", 2) -> "95.25%"
 * - formatPercent("Unavailable", 2, "N/A") -> "N/A"
 */
export function formatPercent(
  value: unknown,
  decimals: number = 2,
  fallback: string = "N/A"
): string {
  const num = parseNumeric(value);
  if (num === null) return fallback;

  // If the value is a ratio between 0 and 1 (inclusive), convert to percentage 0..100.
  // Note: Values > 1.0 (e.g., 87, 95.25) are assumed to already be percentages.
  // Value === 0 gives 0 -> 0.00%
  // Value === 1 gives 1 * 100 = 100 -> 100.00%
  const pct = num >= 0 && num <= 1.0 ? num * 100 : num;
  return `${pct.toFixed(decimals)}%`;
}

/**
 * Safely formats confidence values by checking primary confidence and optional mlConfidence fallback.
 */
export function formatConfidence(
  confidence: unknown,
  mlConfidence?: unknown,
  decimals: number = 2,
  fallback: string = "N/A"
): string {
  const num = parseNumeric(confidence) ?? parseNumeric(mlConfidence);
  if (num === null) return fallback;
  return formatPercent(num, decimals, fallback);
}

/**
 * Safely normalizes confidence to a 0-100 number or null.
 */
export function normalizeConfidence(
  confidence: unknown,
  mlConfidence?: unknown
): number | null {
  const num = parseNumeric(confidence) ?? parseNumeric(mlConfidence);
  if (num === null) return null;
  const pct = num >= 0 && num <= 1.0 ? num * 100 : num;
  return Number(pct.toFixed(2));
}

/**
 * Safely formats a numeric score (e.g. trust score, risk score).
 */
export function formatScore(
  value: unknown,
  decimals: number = 0,
  fallback: string = "—"
): string {
  const num = parseNumeric(value);
  if (num === null) return fallback;
  return num.toFixed(decimals);
}
