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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SpcsAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(SpcsAuthenticationProvider.class);
    private static final String USER_AGENT = "ContainerProxy/1.2.2";

    private final Set<String> adminGroups;
    private final Environment environment;
    private final String computeWarehouse;

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
        
        // Load optional compute warehouse for SPCS authentication admin check
        this.computeWarehouse = environment.getProperty("proxy.spcs.compute-warehouse");
        if (computeWarehouse != null && !computeWarehouse.isEmpty()) {
            logger.debug("SPCS compute warehouse configured for admin role validation: {}", computeWarehouse);
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SpcsAuthenticationToken authRequest = (SpcsAuthenticationToken) authentication;

        if (authRequest.isValid()) {
            String spcsIngressUserToken = authRequest.getCredentials() != null ? authRequest.getCredentials().toString() : null;
            
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            
            // Check conditions that would skip admin role validation (guard clauses)
            if (adminGroups.isEmpty()) {
                logger.debug("No admin groups configured, skipping admin role check");
            } else if (computeWarehouse == null || computeWarehouse.isEmpty()) {
                logger.debug("Compute warehouse not configured (proxy.spcs.compute-warehouse), skipping admin role check");
            } else if (spcsIngressUserToken == null || spcsIngressUserToken.isBlank()) {
                logger.debug("User token not available (executeAsCaller may not be enabled), skipping admin role check");
            } else {
                // All conditions met: perform admin role validation
                // Requires: user token, admin groups, and compute warehouse
                logger.debug("User token available, checking admin roles for {} admin groups using warehouse {}", adminGroups.size(), computeWarehouse);
                Set<String> userAdminGroups = validateAdminRoles(spcsIngressUserToken);
                logger.debug("User has {} admin roles out of {} configured", userAdminGroups.size(), adminGroups.size());
                for (String adminGroup : userAdminGroups) {
                    // Format: ROLE_GROUPNAME (UserService.getGroups() strips the "ROLE_" prefix)
                    String roleName = adminGroup.startsWith("ROLE_") ? adminGroup : "ROLE_" + adminGroup;
                    authorities.add(new SimpleGrantedAuthority(roleName));
                }
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
            
            HttpBearerAuth bearerAuth = (HttpBearerAuth) apiClient.getAuthentication("KeyPair");
            
            // SPCS authentication requires combined token format: <service-oauth-token>.<Sf-Context-Current-User-Token>
            // Read service OAuth token from file and combine with user token
            String serviceToken = readSpcsSessionTokenFromFile();
            if (serviceToken == null || serviceToken.isEmpty()) {
                logger.warn("Service OAuth token not available from file for admin role validation");
                return userAdminGroups;
            }
            
            // Format: <service-oauth-token>.<Sf-Context-Current-User-Token>
            String combinedToken = serviceToken + "." + userToken;           
            bearerAuth.setBearerToken(combinedToken);
            
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
            
            // Prepare request outside try so it is available in catch/retry
            SubmitStatementRequest request = new SubmitStatementRequest();
            request.setStatement(sql);
            // Set warehouse for SQL execution
            request.setWarehouse(computeWarehouse.toUpperCase());
            
            try {
                
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
                // Log error details: exception includes message and stack trace
                logger.warn("Failed to check admin roles (user will not have admin privileges): code={}", 
                    e.getCode(), e);
                // Return empty admin groups on failure (no fallback)
                return userAdminGroups;
            }
        } catch (Exception e) {
            logger.error("Error validating admin roles: {}", e.getMessage(), e);
            // Return empty admin groups on exception (no fallback)
            return userAdminGroups;
        }
        
        return userAdminGroups;
    }
    
    /**
     * Reads the SPCS session token from the standard file location if available.
     * @return The token string or null if not available.
     */
    private String readSpcsSessionTokenFromFile() {
        try {
            Path tokenPath = Paths.get("/snowflake/session/token");
            if (Files.exists(tokenPath) && Files.isRegularFile(tokenPath)) {
                String token = Files.readString(tokenPath).trim();
                if (!token.isEmpty()) {
                    return token;
                } else {
                    logger.warn("SPCS session token file exists but is empty: {}", tokenPath);
                }
            }
        } catch (Exception ex) {
            logger.warn("Error reading SPCS session token from file: {}", ex.getMessage());
        }
        return null;
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
