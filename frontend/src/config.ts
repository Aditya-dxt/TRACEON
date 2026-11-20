/**
 * Traceon Frontend Configuration
 * Toggle `USE_MOCK` or update `BASE_URL` to connect to the live backend API.
 */

export const API_CONFIG = {
  // Set to false to switch the entire dashboard from mock JSON to the live FastAPI backend
  USE_MOCK: true,
  // Live backend API URL (Vaibhav's service)
  BASE_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  // Engine version
  ENGINE_VERSION: "0.1.0",
};

export default API_CONFIG;
