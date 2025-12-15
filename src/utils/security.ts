/**
 * Security handling utilities for OpenAPI to MCP generator
 */
import { OpenAPIV3 } from 'openapi-types';

/**
 * Credential type names used in tool arguments and environment variables
 */
export type CredentialType =
  | 'API_KEY'
  | 'BEARER_TOKEN'
  | 'BASIC_USERNAME'
  | 'BASIC_PASSWORD'
  | 'OAUTH_CLIENT_ID'
  | 'OAUTH_CLIENT_SECRET'
  | 'OAUTH_TOKEN'
  | 'OAUTH_SCOPES'
  | 'OPENID_TOKEN';

/**
 * Get environment variable name for a security scheme
 *
 * @param schemeName Security scheme name
 * @param type Type of security credentials
 * @returns Environment variable name
 */
export function getEnvVarName(schemeName: string, type: CredentialType): string {
  const sanitizedName = schemeName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();
  return `${type}_${sanitizedName}`;
}

/**
 * Get the credential key name for session storage
 *
 * @param schemeName Security scheme name
 * @param type Type of security credentials
 * @returns Credential key (e.g., "api_key_SCHEME_NAME")
 */
export function getCredentialArgName(schemeName: string, type: CredentialType): string {
  const sanitizedName = schemeName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();
  return `${type.toLowerCase()}_${sanitizedName}`;
}

/**
 * Generates the session credential management infrastructure
 * This provides secure, per-session credential storage for multi-user MCP servers
 *
 * @returns Generated code for session credential management
 */
export function generateSessionCredentialCode(): string {
  return `
/**
 * Interface for session credentials storage
 */
interface SessionCredentials {
  [key: string]: string | undefined;
}

/**
 * Global session credential store - maps session IDs to their credentials
 * Credentials are stored in memory only and cleared when sessions end
 */
const sessionCredentialStore: Map<string, SessionCredentials> = new Map();

/**
 * Current session ID for this execution context
 * For stdio transport, this is a single global session
 * For web transports, this is set per-request from the transport layer
 */
let currentSessionId: string = 'default';

/**
 * Sets the current session ID for credential lookup
 * Called by the transport layer before processing each request
 *
 * @param sessionId The session ID to use for credential lookups
 */
export function setCurrentSessionId(sessionId: string): void {
    currentSessionId = sessionId;
}

/**
 * Gets the current session ID
 *
 * @returns The current session ID
 */
export function getCurrentSessionId(): string {
    return currentSessionId;
}

/**
 * Stores credentials for a session
 * Called by the auth/setCredentials handler
 *
 * @param sessionId The session ID to store credentials for
 * @param credentials The credentials to store
 */
export function setSessionCredentials(sessionId: string, credentials: SessionCredentials): void {
    // Merge with existing credentials (allows partial updates)
    const existing = sessionCredentialStore.get(sessionId) || {};
    sessionCredentialStore.set(sessionId, { ...existing, ...credentials });
    console.error(\`Stored credentials for session \${sessionId}: \${Object.keys(credentials).join(', ')}\`);
}

/**
 * Gets all credentials for a session
 *
 * @param sessionId The session ID to get credentials for
 * @returns The session credentials or empty object
 */
export function getSessionCredentials(sessionId: string): SessionCredentials {
    return sessionCredentialStore.get(sessionId) || {};
}

/**
 * Clears credentials for a session (called when session ends)
 *
 * @param sessionId The session ID to clear credentials for
 */
export function clearSessionCredentials(sessionId: string): void {
    sessionCredentialStore.delete(sessionId);
    console.error(\`Cleared credentials for session \${sessionId}\`);
}

/**
 * Checks if a session has any credentials stored
 *
 * @param sessionId The session ID to check
 * @returns True if credentials exist for this session
 */
export function hasSessionCredentials(sessionId: string): boolean {
    const creds = sessionCredentialStore.get(sessionId);
    return creds !== undefined && Object.keys(creds).length > 0;
}

/**
 * Gets a credential value from session storage, falling back to environment variables
 * This is the primary method for retrieving credentials during API execution
 *
 * @param credentialKey The credential key (e.g., "api_key_MY_SCHEME")
 * @param envVarName The environment variable name to fall back to
 * @returns The credential value or undefined if not found
 */
function getCredential(credentialKey: string, envVarName: string): string | undefined {
    // First check session credentials
    const sessionCreds = getSessionCredentials(currentSessionId);
    const sessionValue = sessionCreds[credentialKey];
    if (sessionValue) {
        console.error(\`Using session credential: \${credentialKey}\`);
        return sessionValue;
    }
    
    // Fall back to environment variable
    const envValue = process.env[envVarName];
    if (envValue) {
        console.error(\`Using environment variable: \${envVarName}\`);
    }
    return envValue;
}
`;
}

/**
 * Generates code for handling API key security
 *
 * @param scheme API key security scheme
 * @returns Generated code
 */
export function generateApiKeySecurityCode(scheme: OpenAPIV3.ApiKeySecurityScheme): string {
  const schemeName = 'schemeName'; // Placeholder, will be replaced in template
  return `
    if (scheme?.type === 'apiKey') {
        const apiKey = process.env[\`${getEnvVarName(schemeName, 'API_KEY')}\`];
        if (apiKey) {
            if (scheme.in === 'header') {
                headers[scheme.name.toLowerCase()] = apiKey;
            }
            else if (scheme.in === 'query') {
                queryParams[scheme.name] = apiKey;
            }
            else if (scheme.in === 'cookie') {
                headers['cookie'] = \`\${scheme.name}=\${apiKey}\${headers['cookie'] ? \`; \${headers['cookie']}\` : ''}\`;
            }
        }
    }`;
}

/**
 * Generates code for handling HTTP security (Bearer/Basic)
 *
 * @returns Generated code
 */
export function generateHttpSecurityCode(): string {
  const schemeName = 'schemeName'; // Placeholder, will be replaced in template
  return `
    else if (scheme?.type === 'http') {
        if (scheme.scheme?.toLowerCase() === 'bearer') {
            const token = process.env[\`${getEnvVarName(schemeName, 'BEARER_TOKEN')}\`];
            if (token) {
                headers['authorization'] = \`Bearer \${token}\`;
            }
        } 
        else if (scheme.scheme?.toLowerCase() === 'basic') {
            const username = process.env[\`${getEnvVarName(schemeName, 'BASIC_USERNAME')}\`];
            const password = process.env[\`${getEnvVarName(schemeName, 'BASIC_PASSWORD')}\`];
            if (username && password) {
                headers['authorization'] = \`Basic \${Buffer.from(\`\${username}:\${password}\`).toString('base64')}\`;
            }
        }
    }`;
}

/**
 * Generates code for OAuth2 token acquisition
 *
 * @returns Generated code for OAuth2 token acquisition
 */
export function generateOAuth2TokenAcquisitionCode(): string {
  return `
/**
 * Type definition for cached OAuth tokens
 * Cache key includes session ID to ensure per-session token isolation
 */
interface TokenCacheEntry {
    token: string;
    expiresAt: number;
}

/**
 * Declare global __oauthTokenCache property for TypeScript
 */
declare global {
    var __oauthTokenCache: Record<string, TokenCacheEntry> | undefined;
}

/**
 * Acquires an OAuth2 token using client credentials flow
 * Uses session credentials or environment variables
 * 
 * @param schemeName Name of the security scheme
 * @param scheme OAuth2 security scheme
 * @returns Acquired token or null if unable to acquire
 */
async function acquireOAuth2Token(schemeName: string, scheme: any): Promise<string | null | undefined> {
    try {
        const sanitizedName = schemeName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();
        const sessionId = getCurrentSessionId();
        
        // Check if we have the necessary credentials (session or env)
        const clientIdCredKey = \`oauth_client_id_\${sanitizedName}\`;
        const clientIdEnvKey = \`OAUTH_CLIENT_ID_\${sanitizedName}\`;
        const clientSecretCredKey = \`oauth_client_secret_\${sanitizedName}\`;
        const clientSecretEnvKey = \`OAUTH_CLIENT_SECRET_\${sanitizedName}\`;
        const scopesCredKey = \`oauth_scopes_\${sanitizedName}\`;
        const scopesEnvKey = \`OAUTH_SCOPES_\${sanitizedName}\`;
        
        const clientId = getCredential(clientIdCredKey, clientIdEnvKey);
        const clientSecret = getCredential(clientSecretCredKey, clientSecretEnvKey);
        const scopes = getCredential(scopesCredKey, scopesEnvKey);
        
        if (!clientId || !clientSecret) {
            console.error(\`Missing client credentials for OAuth2 scheme '\${schemeName}'\`);
            return null;
        }
        
        // Initialize token cache if needed
        if (typeof global.__oauthTokenCache === 'undefined') {
            global.__oauthTokenCache = {};
        }
        
        // Cache key includes session ID to ensure per-session token isolation
        const cacheKey = \`\${sessionId}_\${schemeName}_\${clientId}\`;
        const cachedToken = global.__oauthTokenCache[cacheKey];
        const now = Date.now();
        
        // Use cached token if still valid
        if (cachedToken && cachedToken.expiresAt > now) {
            console.error(\`Using cached OAuth2 token for '\${schemeName}' (expires in \${Math.floor((cachedToken.expiresAt - now) / 1000)} seconds)\`);
            return cachedToken.token;
        }
        
        // Determine token URL based on flow type
        let tokenUrl = '';
        if (scheme.flows?.clientCredentials?.tokenUrl) {
            tokenUrl = scheme.flows.clientCredentials.tokenUrl;
            console.error(\`Using client credentials flow for '\${schemeName}'\`);
        } else if (scheme.flows?.password?.tokenUrl) {
            tokenUrl = scheme.flows.password.tokenUrl;
            console.error(\`Using password flow for '\${schemeName}'\`);
        } else {
            console.error(\`No supported OAuth2 flow found for '\${schemeName}'\`);
            return null;
        }
        
        // Prepare the token request
        let formData = new URLSearchParams();
        formData.append('grant_type', 'client_credentials');
        
        // Add scopes if specified
        if (scopes) {
            formData.append('scope', scopes);
        }
        
        console.error(\`Requesting OAuth2 token from \${tokenUrl}\`);
        
        // Make the token request
        const response = await axios({
            method: 'POST',
            url: tokenUrl,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': \`Basic \${Buffer.from(\`\${clientId}:\${clientSecret}\`).toString('base64')}\`
            },
            data: formData.toString()
        });
        
        // Process the response
        if (response.data?.access_token) {
            const token = response.data.access_token;
            const expiresIn = response.data.expires_in || 3600; // Default to 1 hour
            
            // Cache the token (per-session)
            global.__oauthTokenCache[cacheKey] = {
                token,
                expiresAt: now + (expiresIn * 1000) - 60000 // Expire 1 minute early
            };
            
            console.error(\`Successfully acquired OAuth2 token for '\${schemeName}' (expires in \${expiresIn} seconds)\`);
            return token;
        } else {
            console.error(\`Failed to acquire OAuth2 token for '\${schemeName}': No access_token in response\`);
            return null;
        }
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(\`Error acquiring OAuth2 token for '\${schemeName}':\`, errorMessage);
        return null;
    }
}
`;
}

/**
 * Generates code for executing API tools with security handling
 *
 * @param securitySchemes Security schemes from OpenAPI spec
 * @returns Generated code for the execute API tool function
 */
export function generateExecuteApiToolFunction(
  securitySchemes?: OpenAPIV3.ComponentsObject['securitySchemes']
): string {
  // Generate OAuth2 token acquisition function
  const oauth2TokenAcquisitionCode = generateOAuth2TokenAcquisitionCode();

  // Generate session credential management code
  const sessionCredentialCode = generateSessionCredentialCode();

  // Generate security handling code for checking, applying security
  // Uses session credentials first, then falls back to environment variables
  const securityCode = `
    // Apply security requirements if available
    // Security requirements use OR between array items and AND within each object
    // Credentials are retrieved from session storage (set via auth/setCredentials) or environment variables
    const appliedSecurity = definition.securityRequirements?.find(req => {
        // Try each security requirement (combined with OR)
        return Object.entries(req).every(([schemeName, scopesArray]) => {
            const scheme = allSecuritySchemes[schemeName];
            if (!scheme) return false;
            
            const sanitizedName = schemeName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();
            
            // API Key security (header, query, cookie)
            if (scheme.type === 'apiKey') {
                const credKey = \`api_key_\${sanitizedName}\`;
                const envKey = \`API_KEY_\${sanitizedName}\`;
                return !!getCredential(credKey, envKey);
            }
            
            // HTTP security (basic, bearer)
            if (scheme.type === 'http') {
                if (scheme.scheme?.toLowerCase() === 'bearer') {
                    const credKey = \`bearer_token_\${sanitizedName}\`;
                    const envKey = \`BEARER_TOKEN_\${sanitizedName}\`;
                    return !!getCredential(credKey, envKey);
                }
                else if (scheme.scheme?.toLowerCase() === 'basic') {
                    const usernameCredKey = \`basic_username_\${sanitizedName}\`;
                    const usernameEnvKey = \`BASIC_USERNAME_\${sanitizedName}\`;
                    const passwordCredKey = \`basic_password_\${sanitizedName}\`;
                    const passwordEnvKey = \`BASIC_PASSWORD_\${sanitizedName}\`;
                    return !!getCredential(usernameCredKey, usernameEnvKey) && 
                           !!getCredential(passwordCredKey, passwordEnvKey);
                }
            }
            
            // OAuth2 security
            if (scheme.type === 'oauth2') {
                // Check for pre-existing token
                const tokenCredKey = \`oauth_token_\${sanitizedName}\`;
                const tokenEnvKey = \`OAUTH_TOKEN_\${sanitizedName}\`;
                if (getCredential(tokenCredKey, tokenEnvKey)) {
                    return true;
                }
                
                // Check for client credentials for auto-acquisition
                const clientIdCredKey = \`oauth_client_id_\${sanitizedName}\`;
                const clientIdEnvKey = \`OAUTH_CLIENT_ID_\${sanitizedName}\`;
                const clientSecretCredKey = \`oauth_client_secret_\${sanitizedName}\`;
                const clientSecretEnvKey = \`OAUTH_CLIENT_SECRET_\${sanitizedName}\`;
                
                if (getCredential(clientIdCredKey, clientIdEnvKey) &&
                    getCredential(clientSecretCredKey, clientSecretEnvKey)) {
                    // Verify we have a supported flow
                    if (scheme.flows?.clientCredentials || scheme.flows?.password) {
                        return true;
                    }
                }
                
                return false;
            }
            
            // OpenID Connect
            if (scheme.type === 'openIdConnect') {
                const credKey = \`openid_token_\${sanitizedName}\`;
                const envKey = \`OPENID_TOKEN_\${sanitizedName}\`;
                return !!getCredential(credKey, envKey);
            }
            
            return false;
        });
    });

    // If we found matching security scheme(s), apply them
    if (appliedSecurity) {
        // Apply each security scheme from this requirement (combined with AND)
        for (const [schemeName, scopesArray] of Object.entries(appliedSecurity)) {
            const scheme = allSecuritySchemes[schemeName];
            const sanitizedName = schemeName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();
            
            // API Key security
            if (scheme?.type === 'apiKey') {
                const credKey = \`api_key_\${sanitizedName}\`;
                const envKey = \`API_KEY_\${sanitizedName}\`;
                const apiKey = getCredential(credKey, envKey);
                if (apiKey) {
                    if (scheme.in === 'header') {
                        headers[scheme.name.toLowerCase()] = apiKey;
                        console.error(\`Applied API key '\${schemeName}' in header '\${scheme.name}'\`);
                    }
                    else if (scheme.in === 'query') {
                        queryParams[scheme.name] = apiKey;
                        console.error(\`Applied API key '\${schemeName}' in query parameter '\${scheme.name}'\`);
                    }
                    else if (scheme.in === 'cookie') {
                        // Add the cookie, preserving other cookies if they exist
                        headers['cookie'] = \`\${scheme.name}=\${apiKey}\${headers['cookie'] ? \`; \${headers['cookie']}\` : ''}\`;
                        console.error(\`Applied API key '\${schemeName}' in cookie '\${scheme.name}'\`);
                    }
                }
            } 
            // HTTP security (Bearer or Basic)
            else if (scheme?.type === 'http') {
                if (scheme.scheme?.toLowerCase() === 'bearer') {
                    const credKey = \`bearer_token_\${sanitizedName}\`;
                    const envKey = \`BEARER_TOKEN_\${sanitizedName}\`;
                    const token = getCredential(credKey, envKey);
                    if (token) {
                        headers['authorization'] = \`Bearer \${token}\`;
                        console.error(\`Applied Bearer token for '\${schemeName}'\`);
                    }
                } 
                else if (scheme.scheme?.toLowerCase() === 'basic') {
                    const usernameCredKey = \`basic_username_\${sanitizedName}\`;
                    const usernameEnvKey = \`BASIC_USERNAME_\${sanitizedName}\`;
                    const passwordCredKey = \`basic_password_\${sanitizedName}\`;
                    const passwordEnvKey = \`BASIC_PASSWORD_\${sanitizedName}\`;
                    const username = getCredential(usernameCredKey, usernameEnvKey);
                    const password = getCredential(passwordCredKey, passwordEnvKey);
                    if (username && password) {
                        headers['authorization'] = \`Basic \${Buffer.from(\`\${username}:\${password}\`).toString('base64')}\`;
                        console.error(\`Applied Basic authentication for '\${schemeName}'\`);
                    }
                }
            }
            // OAuth2 security
            else if (scheme?.type === 'oauth2') {
                // First try to use a pre-provided token
                const tokenCredKey = \`oauth_token_\${sanitizedName}\`;
                const tokenEnvKey = \`OAUTH_TOKEN_\${sanitizedName}\`;
                let token = getCredential(tokenCredKey, tokenEnvKey);
                
                // If no token but we have client credentials, try to acquire a token
                if (!token && (scheme.flows?.clientCredentials || scheme.flows?.password)) {
                    console.error(\`Attempting to acquire OAuth token for '\${schemeName}'\`);
                    token = (await acquireOAuth2Token(schemeName, scheme)) ?? '';
                }
                
                // Apply token if available
                if (token) {
                    headers['authorization'] = \`Bearer \${token}\`;
                    console.error(\`Applied OAuth2 token for '\${schemeName}'\`);
                    
                    // List the scopes that were requested, if any
                    const scopes = scopesArray as string[];
                    if (scopes && scopes.length > 0) {
                        console.error(\`Requested scopes: \${scopes.join(', ')}\`);
                    }
                }
            }
            // OpenID Connect
            else if (scheme?.type === 'openIdConnect') {
                const credKey = \`openid_token_\${sanitizedName}\`;
                const envKey = \`OPENID_TOKEN_\${sanitizedName}\`;
                const token = getCredential(credKey, envKey);
                if (token) {
                    headers['authorization'] = \`Bearer \${token}\`;
                    console.error(\`Applied OpenID Connect token for '\${schemeName}'\`);
                    
                    // List the scopes that were requested, if any
                    const scopes = scopesArray as string[];
                    if (scopes && scopes.length > 0) {
                        console.error(\`Requested scopes: \${scopes.join(', ')}\`);
                    }
                }
            }
        }
    } 
    // Log warning if security is required but not available
    else if (definition.securityRequirements?.length > 0) {
        // First generate a more readable representation of the security requirements
        const securityRequirementsString = definition.securityRequirements
            .map(req => {
                const parts = Object.entries(req)
                    .map(([name, scopesArray]) => {
                        const scopes = scopesArray as string[];
                        if (scopes.length === 0) return name;
                        return \`\${name} (scopes: \${scopes.join(', ')})\`;
                    })
                    .join(' AND ');
                return \`[\${parts}]\`;
            })
            .join(' OR ');
            
        console.warn(\`Tool '\${toolName}' requires security: \${securityRequirementsString}, but no suitable credentials found. Use auth/setCredentials to provide session credentials.\`);
    }
    `;

  // Generate complete execute API tool function
  return `
${sessionCredentialCode}
${oauth2TokenAcquisitionCode}

/**
 * Executes an API tool with the provided arguments
 * 
 * @param toolName Name of the tool to execute
 * @param definition Tool definition
 * @param toolArgs Arguments provided by the user
 * @param allSecuritySchemes Security schemes from the OpenAPI spec
 * @returns Call tool result
 */
async function executeApiTool(
    toolName: string,
    definition: McpToolDefinition,
    toolArgs: JsonObject,
    allSecuritySchemes: Record<string, any>
): Promise<CallToolResult> {
  try {
    // Validate arguments against the input schema
    let validatedArgs: JsonObject;
    try {
        const zodSchema = getZodSchemaFromJsonSchema(definition.inputSchema, toolName);
        const argsToParse = (typeof toolArgs === 'object' && toolArgs !== null) ? toolArgs : {};
        validatedArgs = zodSchema.parse(argsToParse);
    } catch (error: unknown) {
        if (error instanceof ZodError) {
            const validationErrorMessage = \`Invalid arguments for tool '\${toolName}': \${error.errors.map(e => \`\${e.path.join('.')} (\${e.code}): \${e.message}\`).join(', ')}\`;
            return { content: [{ type: 'text', text: validationErrorMessage }] };
        } else {
             const errorMessage = error instanceof Error ? error.message : String(error);
             return { content: [{ type: 'text', text: \`Internal error during validation setup: \${errorMessage}\` }] };
        }
    }

    // Prepare URL, query parameters, headers, and request body
    let urlPath = definition.pathTemplate;
    const queryParams: Record<string, any> = {};
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    let requestBodyData: any = undefined;

    // Apply parameters to the URL path, query, or headers
    definition.executionParameters.forEach((param) => {
        const value = validatedArgs[param.name];
        if (typeof value !== 'undefined' && value !== null) {
            if (param.in === 'path') {
                urlPath = urlPath.replace(\`{\${param.name}}\`, encodeURIComponent(String(value)));
            }
            else if (param.in === 'query') {
                queryParams[param.name] = value;
            }
            else if (param.in === 'header') {
                headers[param.name.toLowerCase()] = String(value);
            }
        }
    });

    // Ensure all path parameters are resolved
    if (urlPath.includes('{')) {
        throw new Error(\`Failed to resolve path parameters: \${urlPath}\`);
    }
    
    // Construct the full URL
    const requestUrl = API_BASE_URL ? \`\${API_BASE_URL}\${urlPath}\` : urlPath;

    // Handle request body if needed
    if (definition.requestBodyContentType && typeof validatedArgs['requestBody'] !== 'undefined') {
        requestBodyData = validatedArgs['requestBody'];
        headers['content-type'] = definition.requestBodyContentType;
    }

${securityCode}

    // Prepare the axios request configuration
    const config: AxiosRequestConfig = {
      method: definition.method.toUpperCase(), 
      url: requestUrl, 
      params: queryParams, 
      headers: headers,
      ...(requestBodyData !== undefined && { data: requestBodyData }),
    };

    // Log request info to stderr (doesn't affect MCP output)
    console.error(\`Executing tool "\${toolName}": \${config.method} \${config.url}\`);
    
    // Execute the request
    const response = await axios(config);

    // Process and format the response
    let responseText = '';
    const contentType = response.headers['content-type']?.toLowerCase() || '';
    
    // Handle JSON responses
    if (contentType.includes('application/json') && typeof response.data === 'object' && response.data !== null) {
         try { 
             responseText = JSON.stringify(response.data, null, 2); 
         } catch (e) { 
             responseText = "[Stringify Error]"; 
         }
    } 
    // Handle string responses
    else if (typeof response.data === 'string') { 
         responseText = response.data; 
    }
    // Handle other response types
    else if (response.data !== undefined && response.data !== null) { 
         responseText = String(response.data); 
    }
    // Handle empty responses
    else { 
         responseText = \`(Status: \${response.status} - No body content)\`; 
    }
    
    // Return formatted response
    return { 
        content: [ 
            { 
                type: "text", 
                text: \`API Response (Status: \${response.status}):\\n\${responseText}\` 
            } 
        ], 
    };

  } catch (error: unknown) {
    // Handle errors during execution
    let errorMessage: string;
    
    // Format Axios errors specially
    if (axios.isAxiosError(error)) { 
        errorMessage = formatApiError(error); 
    }
    // Handle standard errors
    else if (error instanceof Error) { 
        errorMessage = error.message; 
    }
    // Handle unexpected error types
    else { 
        errorMessage = 'Unexpected error: ' + String(error); 
    }
    
    // Log error to stderr
    console.error(\`Error during execution of tool '\${toolName}':\`, errorMessage);
    
    // Return error message to client
    return { content: [{ type: "text", text: errorMessage }] };
  }
}
`;
}

/**
 * Generates the auth/setCredentials request handler code
 * This allows clients to set their credentials once per session
 *
 * @param securitySchemes Security schemes from OpenAPI spec
 * @returns Generated code for the auth handler
 */
export function generateAuthSetCredentialsHandler(
  securitySchemes?: OpenAPIV3.ComponentsObject['securitySchemes']
): string {
  // Generate list of expected credential keys for documentation/validation
  const expectedKeys: string[] = [];

  if (securitySchemes) {
    for (const [name, schemeOrRef] of Object.entries(securitySchemes)) {
      if ('$ref' in schemeOrRef) continue;
      const scheme = schemeOrRef;

      if (scheme.type === 'apiKey') {
        expectedKeys.push(getCredentialArgName(name, 'API_KEY'));
      } else if (scheme.type === 'http') {
        if (scheme.scheme?.toLowerCase() === 'bearer') {
          expectedKeys.push(getCredentialArgName(name, 'BEARER_TOKEN'));
        } else if (scheme.scheme?.toLowerCase() === 'basic') {
          expectedKeys.push(getCredentialArgName(name, 'BASIC_USERNAME'));
          expectedKeys.push(getCredentialArgName(name, 'BASIC_PASSWORD'));
        }
      } else if (scheme.type === 'oauth2') {
        expectedKeys.push(getCredentialArgName(name, 'OAUTH_TOKEN'));
        expectedKeys.push(getCredentialArgName(name, 'OAUTH_CLIENT_ID'));
        expectedKeys.push(getCredentialArgName(name, 'OAUTH_CLIENT_SECRET'));
        expectedKeys.push(getCredentialArgName(name, 'OAUTH_SCOPES'));
      } else if (scheme.type === 'openIdConnect') {
        expectedKeys.push(getCredentialArgName(name, 'OPENID_TOKEN'));
      }
    }
  }

  return `
/**
 * Schema for auth/setCredentials request
 */
const AuthSetCredentialsRequestSchema = z.object({
    method: z.literal("auth/setCredentials"),
    params: z.object({
        credentials: z.record(z.string(), z.string()).describe("Key-value pairs of credential names and values")
    })
});

/**
 * Schema for auth/clearCredentials request
 */
const AuthClearCredentialsRequestSchema = z.object({
    method: z.literal("auth/clearCredentials"),
    params: z.object({}).optional()
});

/**
 * Expected credential keys for this API:
 * ${expectedKeys.length > 0 ? expectedKeys.join(', ') : 'None defined'}
 */
const EXPECTED_CREDENTIAL_KEYS = ${JSON.stringify(expectedKeys)};

/**
 * Handler for auth/setCredentials - stores credentials for the current session
 * Clients should call this after initialize to set their API keys
 */
server.setRequestHandler(
    AuthSetCredentialsRequestSchema,
    async (request: { params: { credentials: Record<string, string> } }): Promise<{ success: boolean; message: string; storedKeys: string[] }> => {
        const { credentials } = request.params;
        const sessionId = getCurrentSessionId();
        
        // Validate that we received credentials
        if (!credentials || typeof credentials !== 'object') {
            console.error(\`auth/setCredentials: Invalid credentials format\`);
            return { 
                success: false, 
                message: 'Invalid credentials format. Expected object with key-value pairs.',
                storedKeys: []
            };
        }
        
        const providedKeys = Object.keys(credentials);
        
        // Filter to only store non-empty string values
        const validCredentials: Record<string, string> = {};
        for (const [key, value] of Object.entries(credentials)) {
            if (typeof value === 'string' && value.length > 0) {
                validCredentials[key] = value;
            }
        }
        
        const storedKeys = Object.keys(validCredentials);
        
        if (storedKeys.length === 0) {
            console.error(\`auth/setCredentials: No valid credentials provided\`);
            return { 
                success: false, 
                message: 'No valid credentials provided. Values must be non-empty strings.',
                storedKeys: []
            };
        }
        
        // Store credentials for this session
        setSessionCredentials(sessionId, validCredentials);
        
        // Log which keys were stored (not the values!)
        console.error(\`auth/setCredentials: Stored \${storedKeys.length} credential(s) for session \${sessionId}: \${storedKeys.join(', ')}\`);
        
        // Check if any provided keys are unexpected (warning only)
        const unexpectedKeys = providedKeys.filter(k => !EXPECTED_CREDENTIAL_KEYS.includes(k));
        if (unexpectedKeys.length > 0) {
            console.warn(\`auth/setCredentials: Unknown credential keys provided: \${unexpectedKeys.join(', ')}\`);
        }
        
        return { 
            success: true, 
            message: \`Successfully stored \${storedKeys.length} credential(s) for this session.\`,
            storedKeys
        };
    }
);

/**
 * Handler for auth/clearCredentials - clears all credentials for the current session
 */
server.setRequestHandler(
    AuthClearCredentialsRequestSchema,
    async (): Promise<{ success: boolean; message: string }> => {
        const sessionId = getCurrentSessionId();
        
        // Clear credentials for this session
        clearSessionCredentials(sessionId);
        
        console.error(\`auth/clearCredentials: Cleared credentials for session \${sessionId}\`);
        
        return { 
            success: true, 
            message: 'Successfully cleared all credentials for this session.'
        };
    }
);
`;
}

/**
 * Gets security scheme documentation for README
 *
 * @param securitySchemes Security schemes from OpenAPI spec
 * @returns Documentation for security schemes
 */
export function getSecuritySchemesDocs(
  securitySchemes?: OpenAPIV3.ComponentsObject['securitySchemes']
): string {
  if (!securitySchemes) return 'No security schemes defined in the OpenAPI spec.';

  let docs = `## Authentication

This MCP server supports secure, session-based authentication for multi-user scenarios.

### Session-Based Authentication (Recommended)

After connecting to the MCP server, call the \`auth/setCredentials\` method to set your credentials for the session.
Credentials are stored securely in memory and automatically cleared when the session ends.

**Step 1: Connect and Initialize**
\`\`\`json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": { "clientName": "MyClient", "clientVersion": "1.0.0" }
}
\`\`\`

**Step 2: Set Credentials**
\`\`\`json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "auth/setCredentials",
  "params": {
    "credentials": {
      "api_key_API_KEY": "your-api-key-here"
    }
  }
}
\`\`\`

**Step 3: Call Tools (credentials are applied automatically)**
\`\`\`json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "callTool",
  "params": { "name": "getPets", "arguments": { "status": "available" } }
}
\`\`\`

### Environment Variables (Server-Level Fallback)

If session credentials are not set, the server falls back to environment variables.
This is useful for single-user scenarios or default credentials.

### Clearing Credentials

To clear credentials for the current session:
\`\`\`json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "auth/clearCredentials",
  "params": {}
}
\`\`\`

## Available Security Schemes

`;

  for (const [name, schemeOrRef] of Object.entries(securitySchemes)) {
    if ('$ref' in schemeOrRef) {
      docs += `### ${name}\n`;
      docs += `Referenced security scheme (reference not resolved)\n\n`;
      continue;
    }

    const scheme = schemeOrRef;

    docs += `### ${name}\n\n`;

    if (scheme.type === 'apiKey') {
      const envVar = getEnvVarName(name, 'API_KEY');
      const credKey = getCredentialArgName(name, 'API_KEY');
      docs += `**Type:** API Key (in ${scheme.in}: \`${scheme.name}\`)\n\n`;
      docs += `| Method | Key |\n`;
      docs += `|--------|-----|\n`;
      docs += `| Session (auth/setCredentials) | \`${credKey}\` |\n`;
      docs += `| Environment variable | \`${envVar}\` |\n\n`;
    } else if (scheme.type === 'http') {
      if (scheme.scheme?.toLowerCase() === 'bearer') {
        const envVar = getEnvVarName(name, 'BEARER_TOKEN');
        const credKey = getCredentialArgName(name, 'BEARER_TOKEN');
        docs += `**Type:** HTTP Bearer Token\n\n`;
        docs += `| Method | Key |\n`;
        docs += `|--------|-----|\n`;
        docs += `| Session (auth/setCredentials) | \`${credKey}\` |\n`;
        docs += `| Environment variable | \`${envVar}\` |\n\n`;
      } else if (scheme.scheme?.toLowerCase() === 'basic') {
        const usernameEnvVar = getEnvVarName(name, 'BASIC_USERNAME');
        const passwordEnvVar = getEnvVarName(name, 'BASIC_PASSWORD');
        const usernameCredKey = getCredentialArgName(name, 'BASIC_USERNAME');
        const passwordCredKey = getCredentialArgName(name, 'BASIC_PASSWORD');
        docs += `**Type:** HTTP Basic Authentication\n\n`;
        docs += `| Method | Username Key | Password Key |\n`;
        docs += `|--------|--------------|---------------|\n`;
        docs += `| Session (auth/setCredentials) | \`${usernameCredKey}\` | \`${passwordCredKey}\` |\n`;
        docs += `| Environment variable | \`${usernameEnvVar}\` | \`${passwordEnvVar}\` |\n\n`;
      }
    } else if (scheme.type === 'oauth2') {
      const flowTypes = scheme.flows ? Object.keys(scheme.flows) : ['unknown'];
      docs += `**Type:** OAuth2 (${flowTypes.join(', ')} flow)\n\n`;

      // Token option
      const tokenEnvVar = getEnvVarName(name, 'OAUTH_TOKEN');
      const tokenCredKey = getCredentialArgName(name, 'OAUTH_TOKEN');
      docs += `**Option 1: Pre-acquired Token**\n\n`;
      docs += `| Method | Key |\n`;
      docs += `|--------|-----|\n`;
      docs += `| Session (auth/setCredentials) | \`${tokenCredKey}\` |\n`;
      docs += `| Environment variable | \`${tokenEnvVar}\` |\n\n`;

      // Client credentials for auto-acquisition
      const clientIdEnvVar = getEnvVarName(name, 'OAUTH_CLIENT_ID');
      const clientSecretEnvVar = getEnvVarName(name, 'OAUTH_CLIENT_SECRET');
      const scopesEnvVar = getEnvVarName(name, 'OAUTH_SCOPES');
      const clientIdCredKey = getCredentialArgName(name, 'OAUTH_CLIENT_ID');
      const clientSecretCredKey = getCredentialArgName(name, 'OAUTH_CLIENT_SECRET');
      const scopesCredKey = getCredentialArgName(name, 'OAUTH_SCOPES');

      docs += `**Option 2: Client Credentials (auto token acquisition)**\n\n`;
      docs += `| Credential | Session Key | Environment Variable |\n`;
      docs += `|------------|-------------|----------------------|\n`;
      docs += `| Client ID | \`${clientIdCredKey}\` | \`${clientIdEnvVar}\` |\n`;
      docs += `| Client Secret | \`${clientSecretCredKey}\` | \`${clientSecretEnvVar}\` |\n`;
      docs += `| Scopes | \`${scopesCredKey}\` | \`${scopesEnvVar}\` |\n\n`;

      // Flow-specific details
      if (scheme.flows?.clientCredentials) {
        docs += `Token URL: \`${scheme.flows.clientCredentials.tokenUrl}\`\n\n`;

        if (
          scheme.flows.clientCredentials.scopes &&
          Object.keys(scheme.flows.clientCredentials.scopes).length > 0
        ) {
          docs += `Available scopes:\n`;
          for (const [scope, description] of Object.entries(
            scheme.flows.clientCredentials.scopes
          )) {
            docs += `- \`${scope}\`: ${description}\n`;
          }
          docs += '\n';
        }
      }
    } else if (scheme.type === 'openIdConnect') {
      const tokenEnvVar = getEnvVarName(name, 'OPENID_TOKEN');
      const tokenCredKey = getCredentialArgName(name, 'OPENID_TOKEN');
      docs += `**Type:** OpenID Connect\n\n`;
      docs += `| Method | Key |\n`;
      docs += `|--------|-----|\n`;
      docs += `| Session (auth/setCredentials) | \`${tokenCredKey}\` |\n`;
      docs += `| Environment variable | \`${tokenEnvVar}\` |\n\n`;
      if (scheme.openIdConnectUrl) {
        docs += `Discovery URL: \`${scheme.openIdConnectUrl}\`\n\n`;
      }
    }
  }

  return docs;
}
