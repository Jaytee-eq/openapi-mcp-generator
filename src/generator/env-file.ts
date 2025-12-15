/**
 * Generator for .env file and .env.example file
 */
import { OpenAPIV3 } from 'openapi-types';
import { getEnvVarName, getCredentialArgName } from '../utils/security.js';

/**
 * Generates the content of .env.example file for the MCP server
 *
 * @param securitySchemes Security schemes from the OpenAPI spec
 * @returns Content for .env.example file
 */
export function generateEnvExample(
  securitySchemes?: OpenAPIV3.ComponentsObject['securitySchemes']
): string {
  let content = `# MCP Server Environment Variables
# Copy this file to .env and fill in the values

# Server configuration
PORT=3000
LOG_LEVEL=info

# =============================================================================
# AUTHENTICATION CONFIGURATION
# =============================================================================
# This MCP server supports session-based authentication for multi-user scenarios.
#
# 1. SESSION CREDENTIALS (Recommended for multi-user)
#    After connecting, call auth/setCredentials to set credentials for your session:
#    {
#      "method": "auth/setCredentials",
#      "params": {
#        "credentials": {
#          "api_key_MY_SCHEME": "user-specific-api-key"
#        }
#      }
#    }
#    Credentials are stored in memory and cleared when the session ends.
#
# 2. ENVIRONMENT VARIABLES (Server-level fallback)
#    Set credentials below. These are used when session credentials are not set.
#    Useful for single-user scenarios or default credentials.
#
# Session credentials ALWAYS take precedence over environment variables.
# =============================================================================

`;

  // Add security scheme environment variables with examples
  if (securitySchemes && Object.keys(securitySchemes).length > 0) {
    content += `# API Authentication - Server Defaults\n`;
    content += `# (These can be overridden per-session via auth/setCredentials)\n\n`;

    for (const [name, schemeOrRef] of Object.entries(securitySchemes)) {
      if ('$ref' in schemeOrRef) {
        content += `# ${name} - Referenced security scheme (reference not resolved)\n`;
        continue;
      }

      const scheme = schemeOrRef;

      if (scheme.type === 'apiKey') {
        const varName = getEnvVarName(name, 'API_KEY');
        const credKey = getCredentialArgName(name, 'API_KEY');
        content += `# API Key: ${name}\n`;
        content += `# Session key (auth/setCredentials): ${credKey}\n`;
        content += `${varName}=your_api_key_here\n\n`;
      } else if (scheme.type === 'http') {
        if (scheme.scheme?.toLowerCase() === 'bearer') {
          const varName = getEnvVarName(name, 'BEARER_TOKEN');
          const credKey = getCredentialArgName(name, 'BEARER_TOKEN');
          content += `# Bearer Token: ${name}\n`;
          content += `# Session key (auth/setCredentials): ${credKey}\n`;
          content += `${varName}=your_bearer_token_here\n\n`;
        } else if (scheme.scheme?.toLowerCase() === 'basic') {
          const usernameVar = getEnvVarName(name, 'BASIC_USERNAME');
          const passwordVar = getEnvVarName(name, 'BASIC_PASSWORD');
          const usernameCredKey = getCredentialArgName(name, 'BASIC_USERNAME');
          const passwordCredKey = getCredentialArgName(name, 'BASIC_PASSWORD');
          content += `# Basic Auth: ${name}\n`;
          content += `# Session keys (auth/setCredentials): ${usernameCredKey}, ${passwordCredKey}\n`;
          content += `${usernameVar}=your_username_here\n`;
          content += `${passwordVar}=your_password_here\n\n`;
        }
      } else if (scheme.type === 'oauth2') {
        const flowTypes = scheme.flows ? Object.keys(scheme.flows).join(', ') : 'unknown';
        const tokenVar = getEnvVarName(name, 'OAUTH_TOKEN');
        const clientIdVar = getEnvVarName(name, 'OAUTH_CLIENT_ID');
        const clientSecretVar = getEnvVarName(name, 'OAUTH_CLIENT_SECRET');
        const scopesVar = getEnvVarName(name, 'OAUTH_SCOPES');
        const tokenCredKey = getCredentialArgName(name, 'OAUTH_TOKEN');
        const clientIdCredKey = getCredentialArgName(name, 'OAUTH_CLIENT_ID');
        const clientSecretCredKey = getCredentialArgName(name, 'OAUTH_CLIENT_SECRET');

        content += `# OAuth2: ${name} (${flowTypes} flow)\n`;
        content += `# Option 1: Pre-acquired token\n`;
        content += `# Session key (auth/setCredentials): ${tokenCredKey}\n`;
        content += `${tokenVar}=your_oauth_token_here\n`;
        content += `# Option 2: Client credentials for auto token acquisition\n`;
        content += `# Session keys (auth/setCredentials): ${clientIdCredKey}, ${clientSecretCredKey}\n`;
        content += `${clientIdVar}=your_client_id_here\n`;
        content += `${clientSecretVar}=your_client_secret_here\n`;
        content += `${scopesVar}=scope1 scope2\n\n`;
      } else if (scheme.type === 'openIdConnect') {
        const tokenVar = getEnvVarName(name, 'OPENID_TOKEN');
        const credKey = getCredentialArgName(name, 'OPENID_TOKEN');
        content += `# OpenID Connect: ${name}\n`;
        content += `# Session key (auth/setCredentials): ${credKey}\n`;
        content += `${tokenVar}=your_openid_token_here\n\n`;
      }
    }
  } else {
    content += `# No API authentication required\n`;
  }

  content += `# Add any other environment variables your API might need\n`;

  return content;
}

/**
 * Generates dotenv configuration code for the MCP server
 *
 * @returns Code for loading environment variables
 */
export function generateDotenvConfig(): string {
  return `
/**
 * Load environment variables from .env file
 */
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from .env file
const result = dotenv.config({ path: path.resolve(__dirname, '../.env') });

if (result.error) {
  console.warn('Warning: No .env file found or error loading .env file.');
  console.warn('Using default environment variables.');
}

export const config = {
  port: process.env.PORT || '3000',
  logLevel: process.env.LOG_LEVEL || 'info',
};
`;
}
