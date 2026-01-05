/*
 * ContainerProxy
 *
 * Copyright (C) 2016-2025 Open Analytics
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.containerproxy.auth.impl.spcs;

import eu.openanalytics.containerproxy.backend.spcs.client.ApiClient;
import eu.openanalytics.containerproxy.backend.spcs.client.ApiException;
import eu.openanalytics.containerproxy.backend.spcs.client.api.StatementsApi;
import eu.openanalytics.containerproxy.backend.spcs.client.auth.HttpBearerAuth;
import eu.openanalytics.containerproxy.backend.spcs.client.model.ResultSet;
import eu.openanalytics.containerproxy.backend.spcs.client.model.SubmitStatementRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SpcsAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(SpcsAuthenticationProvider.class);
    private static final String USER_AGENT = "ContainerProxy/1.2.2";

    private final Set<String> adminGroups;
    private final Environment environment;

    public SpcsAuthenticationProvider(Environment environment) {
        this.environment = environment;
        // Load admin groups from environment (same logic as UserService.init())
        this.adminGroups = new HashSet<>();
        
        // Support for old, non-array notation
        String singleGroup = environment.getProperty("proxy.admin-groups");
        if (singleGroup != null && !singleGroup.isEmpty()) {
            adminGroups.add(singleGroup.toUpperCase());
        }

        for (int i = 0; ; i++) {
            String groupName = environment.getProperty(String.format("proxy.admin-groups[%s]", i));
            if (groupName == null || groupName.isEmpty()) {
                break;
            }
            adminGroups.add(groupName.toUpperCase());
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SpcsAuthenticationToken authRequest = (SpcsAuthenticationToken) authentication;

        if (authRequest.isValid()) {
            String spcsIngressUserToken = authRequest.getCredentials() != null ? authRequest.getCredentials().toString() : null;
            
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            
            // Only check admin roles if user token is present (required for caller's rights context)
            if (spcsIngressUserToken != null && !spcsIngressUserToken.isBlank() && !adminGroups.isEmpty()) {
                logger.debug("User token available, checking admin roles for {} admin groups", adminGroups.size());
                Set<String> userAdminGroups = validateAdminRoles(spcsIngressUserToken);
                logger.debug("User has {} admin roles out of {} configured", userAdminGroups.size(), adminGroups.size());
                for (String adminGroup : userAdminGroups) {
                    // Format: ROLE_GROUPNAME (UserService.getGroups() strips the "ROLE_" prefix)
                    String roleName = adminGroup.startsWith("ROLE_") ? adminGroup : "ROLE_" + adminGroup;
                    authorities.add(new SimpleGrantedAuthority(roleName));
                }
            } else if (adminGroups.isEmpty()) {
                logger.debug("No admin groups configured, skipping admin role check");
            } else {
                logger.debug("User token not available (executeAsCaller may not be enabled), skipping admin role check");
            }
            
            return new SpcsAuthenticationToken(
                authRequest.getPrincipal().toString(),
                spcsIngressUserToken,
                authorities,
                authRequest.getDetails(),
                true
            );
        }

        throw new SpcsAuthenticationException("Invalid Snowflake username");
    }

    /**
     * Validates which admin roles the user has by calling IS_ROLE_IN_SESSION() for all admin groups in a single SQL query.
     * Uses the Sf-Context-Current-User-Token to authenticate as the caller.
     * 
     * @param userToken The Sf-Context-Current-User-Token
     * @return Set of admin group names that the user has in their session
     */
    private Set<String> validateAdminRoles(String userToken) {
        Set<String> userAdminGroups = new HashSet<>();
        
        if (adminGroups.isEmpty()) {
            return userAdminGroups;
        }
        
        try {
            // Get account URL from environment
            String accountUrl = getAccountUrl();
            if (accountUrl == null) {
                logger.warn("Cannot validate admin roles: account URL not available");
                return userAdminGroups;
            }
            
            // Create a new API client instance (not shared) with user token as bearer token
            // Use KeyPair authentication scheme (HttpBearerAuth) - works for OAuth tokens from SPCS ingress
            ApiClient apiClient = new ApiClient();
            apiClient.setBasePath(accountUrl);
            
            // DEBUG: Decode and log token (temporary debug logging)
            try {
                // Try to decode as JWT (three parts separated by dots)
                String[] jwtParts = userToken.split("\\.");
                if (jwtParts.length == 3) {
                    // JWT token - decode header and payload
                    logger.debug("Token is JWT format ({} parts)", jwtParts.length);
                    
                    // Decode header (part 0)
                    try {
                        String headerPart = jwtParts[0];
                        String base64Header = headerPart.replace('-', '+').replace('_', '/');
                        switch (base64Header.length() % 4) {
                            case 2: base64Header += "=="; break;
                            case 3: base64Header += "="; break;
                        }
                        byte[] decodedHeader = Base64.getDecoder().decode(base64Header);
                        String headerStr = new String(decodedHeader, StandardCharsets.UTF_8);
                        logger.debug("JWT header: {}", headerStr);
                    } catch (Exception e) {
                        logger.debug("Could not decode JWT header: {}", e.getMessage());
                    }
                    
                    // Decode payload (part 1) and extract "aud" claim
                    try {
                        String payloadPart = jwtParts[1];
                        String base64Payload = payloadPart.replace('-', '+').replace('_', '/');
                        switch (base64Payload.length() % 4) {
                            case 2: base64Payload += "=="; break;
                            case 3: base64Payload += "="; break;
                        }
                        byte[] decodedPayload = Base64.getDecoder().decode(base64Payload);
                        String payloadStr = new String(decodedPayload, StandardCharsets.UTF_8);
                        logger.debug("JWT payload: {}", payloadStr);
                        
                        // Extract "aud" claim from JSON payload (simple string search for "aud":)
                        // This is a simple approach - for production, use a proper JSON parser
                        int audStart = payloadStr.indexOf("\"aud\":");
                        if (audStart >= 0) {
                            int audValueStart = payloadStr.indexOf("\"", audStart + 6) + 1;
                            int audValueEnd = payloadStr.indexOf("\"", audValueStart);
                            if (audValueEnd > audValueStart) {
                                String audValue = payloadStr.substring(audValueStart, audValueEnd);
                                logger.warn("JWT token 'aud' (audience) claim: '{}' | Account URL used for API: '{}' | Match: {}", 
                                    audValue, accountUrl, audValue.equals(accountUrl) || accountUrl.contains(audValue) || audValue.contains(accountUrl));
                                
                                // If audience doesn't match account URL, this could cause "Invalid OAuth access token" error
                                if (!audValue.equals(accountUrl) && !accountUrl.contains(audValue) && !audValue.contains(accountUrl)) {
                                    logger.warn("WARNING: JWT audience '{}' does not match account URL '{}' - this may cause token rejection", audValue, accountUrl);
                                }
                            }
                        }
                    } catch (Exception e) {
                        logger.debug("Could not decode JWT payload or extract 'aud' claim: {}", e.getMessage());
                    }
                } else {
                    // Not a JWT, try direct base64 decode
                    try {
                        byte[] decoded = Base64.getDecoder().decode(userToken);
                        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
                        logger.debug("Token decoded (not JWT, {} chars): {}", decodedStr.length(), decodedStr);
                    } catch (Exception e) {
                        logger.debug("Token is not base64 encoded: {}", e.getMessage());
                    }
                }
            } catch (Exception e) {
                logger.debug("Error decoding token for debugging: {}", e.getMessage());
            }
            
            HttpBearerAuth bearerAuth = (HttpBearerAuth) apiClient.getAuthentication("KeyPair");
            bearerAuth.setBearerToken(userToken);
            
            // using SQL statement endpoint.  there maybe a REST API for this in the future.
            StatementsApi statementsApi = new StatementsApi(apiClient);
            
            // Build a single SQL query with one column per admin group using IS_ROLE_IN_SESSION()
            // Example: SELECT IS_ROLE_IN_SESSION('ROLE1') AS role1, IS_ROLE_IN_SESSION('ROLE2') AS role2, ...
            StringBuilder sqlBuilder = new StringBuilder("SELECT ");
            List<String> adminGroupList = new ArrayList<>(adminGroups);
            for (int i = 0; i < adminGroupList.size(); i++) {
                if (i > 0) {
                    sqlBuilder.append(", ");
                }
                String adminGroup = adminGroupList.get(i).toUpperCase();
                sqlBuilder.append("IS_ROLE_IN_SESSION('").append(escapeSqlString(adminGroup)).append("') AS role_").append(i);
            }
            String sql = sqlBuilder.toString();
            
            try {
                SubmitStatementRequest request = new SubmitStatementRequest();
                request.setStatement(sql);
                
                // Set xSnowflakeAuthorizationTokenType for debugging: indicates source of bearer token
                // Using "OAUTH" since the user token (Sf-Context-Current-User-Token) is an OAuth token
                logger.debug("Checking admin roles using user token (token length: {})", userToken != null ? userToken.length() : 0);
                ResultSet result = statementsApi.submitStatement(
                    USER_AGENT,
                    request,
                    null, // requestId
                    false, // async
                    false, // nullable
                    null, // accept
                    "OAUTH" // xSnowflakeAuthorizationTokenType: OAuth token from SPCS ingress
                );
                
                // Parse result: Each column contains TRUE or FALSE for the corresponding admin group
                // ResultSet.data is List<List<String>>, first row contains all the boolean values
                if (result.getData() != null && !result.getData().isEmpty()) {
                    List<String> firstRow = result.getData().get(0);
                    if (firstRow != null && firstRow.size() == adminGroupList.size()) {
                        for (int i = 0; i < firstRow.size(); i++) {
                            String value = firstRow.get(i);
                            // Snowflake returns "true" or "false" as strings
                            if ("true".equalsIgnoreCase(value) || "TRUE".equals(value)) {
                                String adminGroup = adminGroupList.get(i);
                                userAdminGroups.add(adminGroup);
                                logger.debug("User has admin role: {}", adminGroup);
                            }
                        }
                    } else {
                        logger.warn("Unexpected result format: expected {} columns but got {}", 
                            adminGroupList.size(), firstRow != null ? firstRow.size() : 0);
                    }
                }
            } catch (ApiException e) {
                // Log full error details for debugging
                logger.warn("Failed to check admin roles (user will not have admin privileges): status={}, code={}, message={}", 
                    e.getCode(), e.getCode(), e.getMessage());
                if (logger.isDebugEnabled()) {
                    logger.debug("Full API exception details:", e);
                }
            }
        } catch (Exception e) {
            logger.error("Error validating admin roles: {}", e.getMessage(), e);
        }
        
        return userAdminGroups;
    }
    
    /**
     * Gets the Snowflake account URL from environment variables.
     * 
     * @return Account URL or null if not available
     */
    private String getAccountUrl() {
        // Check SNOWFLAKE_HOST first (preferred when running inside SPCS)
        String snowflakeHost = environment.getProperty("SNOWFLAKE_HOST");
        if (snowflakeHost != null && !snowflakeHost.isEmpty()) {
            if (snowflakeHost.startsWith("https://") || snowflakeHost.startsWith("http://")) {
                return snowflakeHost;
            } else {
                return "https://" + snowflakeHost;
            }
        }
        
        // Fall back to constructing from SNOWFLAKE_ACCOUNT
        String snowflakeAccount = environment.getProperty("SNOWFLAKE_ACCOUNT");
        if (snowflakeAccount != null && !snowflakeAccount.isEmpty()) {
            return String.format("https://%s.snowflakecomputing.com", snowflakeAccount);
        }
        
        return null;
    }
    
    /**
     * Escapes single quotes in SQL string literals.
     * 
     * @param value The string value to escape
     * @return Escaped string safe for use in SQL string literal
     */
    private String escapeSqlString(String value) {
        // Escape single quotes by doubling them: ' -> ''
        return value.replace("'", "''");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SpcsAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
