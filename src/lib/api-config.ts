/**
 * Centralized API configuration.
 *
 * Set VITE_API_BASE_URL in your .env file to override the default backend URL.
 * Example: VITE_API_BASE_URL=http://localhost:8081
 */

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string) ||
  (import.meta.env.VITE_JAVA_BASE_URL as string) ||
  "http://localhost:8081";

export const ML_API_URL: string =
  (import.meta.env.VITE_ML_API_URL as string) ||
  (import.meta.env.VITE_API_URL as string) ||
  "http://localhost:5000";

/** Default fetch timeout (ms) for API requests */
export const DEFAULT_TIMEOUT_MS = 8000;

/** Default page size for server-side pagination */
export const DEFAULT_PAGE_SIZE = 50;

/**
 * Helper to build a paginated entity URL.
 * Supports both limit/offset and page/size param styles.
 */
export function entityUrl(entity: string, page = 0, size = DEFAULT_PAGE_SIZE): string {
  const offset = page * size;
  return `${API_BASE_URL}/api/v1/entity/${entity}?limit=${size}&offset=${offset}`;
}
