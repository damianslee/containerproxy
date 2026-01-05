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
package eu.openanalytics.containerproxy.backend.spcs;

import eu.openanalytics.containerproxy.backend.spcs.client.ApiClient;
import eu.openanalytics.containerproxy.backend.spcs.client.ApiException;
import eu.openanalytics.containerproxy.backend.spcs.client.JSON;
import eu.openanalytics.containerproxy.backend.spcs.client.auth.HttpBearerAuth;
import eu.openanalytics.containerproxy.backend.spcs.client.api.ServiceApi;
import eu.openanalytics.containerproxy.backend.spcs.client.model.Service;
import eu.openanalytics.containerproxy.backend.spcs.client.model.ServiceContainer;
import eu.openanalytics.containerproxy.backend.spcs.client.model.ServiceEndpoint;
import eu.openanalytics.containerproxy.backend.spcs.client.model.ServiceSpec;
import eu.openanalytics.containerproxy.backend.spcs.client.model.ServiceSpecInlineText;
import com.google.gson.reflect.TypeToken;
import eu.openanalytics.containerproxy.ContainerFailedToStartException;
import eu.openanalytics.containerproxy.backend.AbstractContainerBackend;
import eu.openanalytics.containerproxy.event.NewProxyEvent;
import eu.openanalytics.containerproxy.model.runtime.Container;
import eu.openanalytics.containerproxy.model.runtime.ExistingContainerInfo;
import eu.openanalytics.containerproxy.model.runtime.PortMappings;
import eu.openanalytics.containerproxy.model.runtime.Proxy;
import eu.openanalytics.containerproxy.model.runtime.ProxyStartupLog;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.BackendContainerName;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.BackendContainerNameKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.ContainerImageKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.HttpHeaders;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.HttpHeadersKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.InstanceIdKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.ProxyIdKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.ProxySpecIdKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.RealmIdKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.UserIdKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.RuntimeValue;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.RuntimeValueKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.RuntimeValueKeyRegistry;
import eu.openanalytics.containerproxy.model.spec.ContainerSpec;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.spec.IProxySpecProvider;
import eu.openanalytics.containerproxy.util.EnvironmentUtils;
import eu.openanalytics.containerproxy.util.Retrying;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import eu.openanalytics.containerproxy.auth.impl.spcs.SpcsAuthenticationToken;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Component
@ConditionalOnProperty(name = "proxy.container-backend", havingValue = "spcs")
public class SpcsBackend extends AbstractContainerBackend {

    private static final String PROPERTY_PREFIX = "proxy.spcs.";
    private static final String PROPERTY_ACCOUNT_IDENTIFIER = "account-identifier";
    private static final String PROPERTY_USERNAME = "username";
    private static final String PROPERTY_PROGRAMMATIC_ACCESS_TOKEN = "programmatic-access-token";
    private static final String PROPERTY_PRIVATE_RSA_KEY_PATH = "private-rsa-key-path";
    private static final String PROPERTY_DATABASE = "database";
    private static final String PROPERTY_SCHEMA = "schema";
    private static final String PROPERTY_COMPUTE_POOL = "compute-pool";
    private static final String PROPERTY_EXTERNAL_ACCESS_INTEGRATIONS = "external-access-integrations";
    private static final String PROPERTY_SERVICE_WAIT_TIME = "service-wait-time";

    private ServiceApi snowflakeServiceAPI;
    private ApiClient snowflakeAPIClient;
    private int serviceWaitTime;
    private String database;
    private String schema;
    private String computePool;
    private List<String> externalAccessIntegrations;
    private String accountUrl;
    private String accountIdentifier; // Account identifier (e.g., "ORG-ACCOUNT" or "ACCOUNT") - stored separately from URL
    private String username;
    private AuthMethod authMethod;
    private String privateRsaKeyPath; // For keypair authentication - path to RSA private key
    private Supplier<String> jwtTokenSupplier; // Supplier to generate/regenerate JWT tokens for keypair auth

    private static final Path SPCS_SESSION_TOKEN_PATH = Paths.get("/snowflake/session/token");

    private enum AuthMethod {
        SPCS_SESSION_TOKEN,  // Running inside SPCS, token from /snowflake/session/token
        KEYPAIR,            // Username + private RSA key
        PAT                 // Username + PAT token
    }

    @Inject
    private IProxySpecProvider proxySpecProvider;


    @Override
    @PostConstruct
    public void initialize() {
        super.initialize();

        // Detect if running inside SPCS by checking SNOWFLAKE_SERVICE_NAME environment variable
        String snowflakeServiceName = environment.getProperty("SNOWFLAKE_SERVICE_NAME");
        boolean runningInsideSpcs = snowflakeServiceName != null && !snowflakeServiceName.isEmpty();

        if (runningInsideSpcs) {
            loadConfigurationFromEnvironment();
            setupSpcsSessionTokenAuth();
        } else {
            loadConfigurationFromProperties();
            setupExternalAuth();
        }

        serviceWaitTime = environment.getProperty(PROPERTY_PREFIX + PROPERTY_SERVICE_WAIT_TIME, Integer.class, 180000);

        initializeSnowflakeAPIClient();

        // Validate specs
        for (ProxySpec spec : proxySpecProvider.getSpecs()) {
            ContainerSpec containerSpec = spec.getContainerSpecs().get(0);
            if (!containerSpec.getMemoryRequest().isOriginalValuePresent()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has no 'memory-request' configured, this is required for running on Snowflake SPCS", spec.getId()));
            }
            if (!containerSpec.getCpuRequest().isOriginalValuePresent()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has no 'cpu-request' configured, this is required for running on Snowflake SPCS", spec.getId()));
            }
            if (containerSpec.getMemoryLimit().isOriginalValuePresent()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has 'memory-limit' configured, this is not supported by Snowflake SPCS", spec.getId()));
            }
            if (containerSpec.getCpuLimit().isOriginalValuePresent()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has 'cpu-limit' configured, this is not supported by Snowflake SPCS", spec.getId()));
            }
            if (containerSpec.isPrivileged()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has 'privileged: true' configured, this is not supported by Snowflake SPCS", spec.getId()));
            }
            if (containerSpec.getVolumes().isOriginalValuePresent() && !containerSpec.getVolumes().getOriginalValue().isEmpty()) {
                throw new IllegalStateException(String.format("Error in configuration of specs: spec with id '%s' has 'volumes' configured, this is not yet supported by Snowflake SPCS", spec.getId()));
            }
        }
    }


    /**
     * Loads configuration from Snowflake environment variables (when running inside SPCS).
     */
    private void loadConfigurationFromEnvironment() {
        log.info("Detected running inside SPCS (SNOWFLAKE_SERVICE_NAME: {})", environment.getProperty("SNOWFLAKE_SERVICE_NAME"));
        
        // Load Snowflake environment variables
        String snowflakeHost = environment.getProperty("SNOWFLAKE_HOST");
        String snowflakeAccount = environment.getProperty("SNOWFLAKE_ACCOUNT");
        String snowflakeDatabase = environment.getProperty("SNOWFLAKE_DATABASE");
        String snowflakeSchema = environment.getProperty("SNOWFLAKE_SCHEMA");
        String snowflakeRegion = environment.getProperty("SNOWFLAKE_REGION");
        String snowflakeComputePool = environment.getProperty("SNOWFLAKE_COMPUTE_POOL");
        
        // Get account identifier from SNOWFLAKE_ACCOUNT (required)
        if (snowflakeAccount == null || snowflakeAccount.isEmpty()) {
            throw new IllegalStateException("Error in SPCS environment: SNOWFLAKE_ACCOUNT not set");
        }
        accountIdentifier = snowflakeAccount;
        
        // Use SNOWFLAKE_HOST if available, otherwise build from account identifier
        if (snowflakeHost != null && !snowflakeHost.isEmpty()) {
            // SNOWFLAKE_HOST contains the full hostname (e.g., "<identifier>.us-east-1.snowflakecomputing.com")
            // Add https:// if not present
            if (snowflakeHost.startsWith("https://") || snowflakeHost.startsWith("http://")) {
                accountUrl = snowflakeHost;
            } else {
                accountUrl = "https://" + snowflakeHost;
            }
            log.info("Using account URL from SNOWFLAKE_HOST environment variable: {}", accountUrl);
        } else {
            // Build account URL from account identifier by appending .snowflakecomputing.com
            // Format: https://{account_identifier}.snowflakecomputing.com
            accountUrl = String.format("https://%s.snowflakecomputing.com", accountIdentifier);
        }
        
        // Use database and schema from environment variables (available when running inside SPCS)
        if (snowflakeDatabase != null && !snowflakeDatabase.isEmpty()) {
            database = snowflakeDatabase;
            log.info("Using database from SNOWFLAKE_DATABASE environment variable: {}", database);
        } else {
            database = getProperty(PROPERTY_DATABASE);
            if (database == null) {
                throw new IllegalStateException("Error in configuration of SPCS backend: SNOWFLAKE_DATABASE not set and proxy.spcs.database not configured");
            }
        }
        
        if (snowflakeSchema != null && !snowflakeSchema.isEmpty()) {
            schema = snowflakeSchema;
            log.info("Using schema from SNOWFLAKE_SCHEMA environment variable: {}", schema);
        } else {
            schema = getProperty(PROPERTY_SCHEMA);
            if (schema == null) {
                throw new IllegalStateException("Error in configuration of SPCS backend: SNOWFLAKE_SCHEMA not set and proxy.spcs.schema not configured");
            }
        }
        
        // Compute pool: use configured value if set, otherwise use SNOWFLAKE_COMPUTE_POOL
        computePool = getProperty(PROPERTY_COMPUTE_POOL);
        if (computePool == null) {
            if (snowflakeComputePool != null && !snowflakeComputePool.isEmpty()) {
                computePool = snowflakeComputePool;
                log.info("Using compute pool from SNOWFLAKE_COMPUTE_POOL environment variable: {}", computePool);
            } else {
                throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.compute-pool not set and SNOWFLAKE_COMPUTE_POOL environment variable not available");
            }
        } else {
            log.info("Using compute pool from configuration: {} (SNOWFLAKE_COMPUTE_POOL was: {})", computePool, snowflakeComputePool);
        }
        
        // Load external access integrations (optional, can be null)
        externalAccessIntegrations = EnvironmentUtils.readList(environment, PROPERTY_PREFIX + PROPERTY_EXTERNAL_ACCESS_INTEGRATIONS);
        if (externalAccessIntegrations != null && !externalAccessIntegrations.isEmpty()) {
            log.info("Using external access integrations from configuration: {}", externalAccessIntegrations);
        }
        
        log.info("Loaded SPCS environment: account={}, region={}, compute-pool={}", 
            snowflakeAccount, snowflakeRegion, computePool);
    }

    /**
     * Loads configuration from properties (when running external to SPCS).
     */
    private void loadConfigurationFromProperties() {
        // Get account identifier from property (required when running external to SPCS)
        String accountIdentifierConfig = getProperty(PROPERTY_ACCOUNT_IDENTIFIER);
        if (accountIdentifierConfig == null || accountIdentifierConfig.isEmpty()) {
            throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.account-identifier not set");
        }
        accountIdentifier = accountIdentifierConfig;
        
        // Check for SNOWFLAKE_HOST environment variable for account URL (works both inside and outside SPCS)
        String snowflakeHost = environment.getProperty("SNOWFLAKE_HOST");
        if (snowflakeHost != null && !snowflakeHost.isEmpty()) {
            // SNOWFLAKE_HOST contains the full hostname
            // Add https:// if not present
            if (snowflakeHost.startsWith("https://") || snowflakeHost.startsWith("http://")) {
                accountUrl = snowflakeHost;
            } else {
                accountUrl = "https://" + snowflakeHost;
            }
            log.info("Using account URL from SNOWFLAKE_HOST environment variable: {}", accountUrl);
        } else {
            // Construct account URL from account identifier by appending .snowflakecomputing.com
            accountUrl = String.format("https://%s.snowflakecomputing.com", accountIdentifier);
        }
        
        database = getProperty(PROPERTY_DATABASE);
        if (database == null) {
            throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.database not set");
        }

        schema = getProperty(PROPERTY_SCHEMA);
        if (schema == null) {
            throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.schema not set");
        }

        computePool = getProperty(PROPERTY_COMPUTE_POOL);
        if (computePool == null) {
            throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.compute-pool not set");
        }
        
        // Load external access integrations (optional, can be null)
        externalAccessIntegrations = EnvironmentUtils.readList(environment, PROPERTY_PREFIX + PROPERTY_EXTERNAL_ACCESS_INTEGRATIONS);
        if (externalAccessIntegrations != null && !externalAccessIntegrations.isEmpty()) {
            log.info("Using external access integrations from configuration: {}", externalAccessIntegrations);
        }
    }

    /**
     * Sets up SPCS session token authentication (when running inside SPCS).
     */
    private void setupSpcsSessionTokenAuth() {
        // Check for session token file
        if (!Files.exists(SPCS_SESSION_TOKEN_PATH) || !Files.isRegularFile(SPCS_SESSION_TOKEN_PATH)) {
            throw new IllegalStateException("Running inside SPCS but session token file not found: " + SPCS_SESSION_TOKEN_PATH);
        }
        
        // Use supplier to read token fresh on each request (allows SPCS to refresh it automatically)
        authMethod = AuthMethod.SPCS_SESSION_TOKEN;
        jwtTokenSupplier = () -> {
            try {
                String sessionToken = Files.readString(SPCS_SESSION_TOKEN_PATH).trim();
                if (sessionToken.isEmpty()) {
                    throw new IllegalStateException("SPCS session token file exists but is empty: " + SPCS_SESSION_TOKEN_PATH);
                }
                return sessionToken;
            } catch (IOException e) {
                throw new RuntimeException("Error reading SPCS session token from " + SPCS_SESSION_TOKEN_PATH + ": " + e.getMessage(), e);
            }
        };
        log.info("Running inside SPCS: will read authentication token from {} on each request", SPCS_SESSION_TOKEN_PATH);
    }

    /**
     * Initializes the Snowflake API client with authentication.
     */
    private void initializeSnowflakeAPIClient() {
        try {
            // Create a new API client instance for SPCS backend
            snowflakeAPIClient = new ApiClient();
            snowflakeAPIClient.setBasePath(accountUrl);
            
            // Set authentication token based on auth method
            // Use KeyPair authentication scheme (HttpBearerAuth) for all token types - works for JWT, OAuth, and PAT tokens
            HttpBearerAuth bearerAuth = (HttpBearerAuth) snowflakeAPIClient.getAuthentication("KeyPair");
            
            // Set bearer token using supplier (allows automatic refresh)
                // For keypair: use supplier to generate JWT tokens on-demand (auto-refreshes on expiry)
                // For SPCS session token: use supplier to read token fresh on each request (allows SPCS auto-refresh)
                // For PAT: use supplier for consistency and to support future token rotation
                bearerAuth.setBearerToken(jwtTokenSupplier);
            
            // Set X-Snowflake-Authorization-Token-Type header
            // This helps snowflake identify the token type and useful in logs for debugging
            String tokenType;
            if (authMethod == AuthMethod.KEYPAIR) {
                tokenType = "KEYPAIR_JWT";  // Key-pair JWT token
            } else if (authMethod == AuthMethod.SPCS_SESSION_TOKEN) {
                tokenType = "OAUTH";  // OAuth token from SPCS session
            } else if (authMethod == AuthMethod.PAT) {
                tokenType = "PROGRAMMATIC_ACCESS_TOKEN";  // Programmatic access token
            } else {
                throw new IllegalStateException("Unknown authentication method: " + authMethod);
            }
            snowflakeAPIClient.addDefaultHeader("X-Snowflake-Authorization-Token-Type", tokenType);

            snowflakeServiceAPI = new ServiceApi(snowflakeAPIClient);
            log.info("Initialized Snowflake SPCS backend with account URL: {} using authentication type: {}", accountUrl, tokenType);
        } catch (Exception e) {
            throw new IllegalStateException("Error initializing Snowflake API client: " + e.getMessage(), e);
        }
    }

    /**
     * Sets up external authentication (keypair or PAT) when running external to SPCS.
     */
    private void setupExternalAuth() {
        username = getProperty(PROPERTY_USERNAME);
        
        String privateRsaKeyPath = getProperty(PROPERTY_PRIVATE_RSA_KEY_PATH);
        String programmaticAccessToken = getProperty(PROPERTY_PROGRAMMATIC_ACCESS_TOKEN);
        
        if (username == null) {
            throw new IllegalStateException("Error in configuration of SPCS backend: proxy.spcs.username not set (required when running external to Snowflake SPCS)");
        }
        
        if (privateRsaKeyPath != null && Files.exists(Paths.get(privateRsaKeyPath))) {
            // Priority 2: Keypair authentication
            this.privateRsaKeyPath = privateRsaKeyPath;
            authMethod = AuthMethod.KEYPAIR;
            // JWT token will be generated on-demand via supplier
            // This allows automatic regeneration when the token expires
            jwtTokenSupplier = () -> generateJwtTokenForKeypair();
            // For REST API, we'll use the supplier to get fresh JWT tokens
            // For ingress, JWT needs to be exchanged for Snowflake Token (handled separately)
            log.info("Using keypair authentication for user: {} with RSA key: {}", username, privateRsaKeyPath);
        } else if (programmaticAccessToken != null && !programmaticAccessToken.isEmpty()) {
            // Priority 3: Programmatic Access Token (PAT) authentication
            // Use supplier for consistency and to support future token rotation scenarios
            authMethod = AuthMethod.PAT;
            final String patToken = programmaticAccessToken; // Final variable for use in lambda
            jwtTokenSupplier = () -> patToken;
            log.info("Using programmatic access token authentication for user: {}", username);
        } else {
            throw new IllegalStateException("Error in configuration of SPCS backend: one of the following must be set: proxy.spcs.private-rsa-key-path or proxy.spcs.programmatic-access-token");
        }
    }

    
    @Override
    public Proxy startContainer(Authentication authentication, Container initialContainer, ContainerSpec spec, Proxy proxy, ProxySpec proxySpec, ProxyStartupLog.ProxyStartupLogBuilder proxyStartupLogBuilder) throws ContainerFailedToStartException {
        Container.ContainerBuilder rContainerBuilder = initialContainer.toBuilder();
        String containerId = UUID.randomUUID().toString();
        rContainerBuilder.id(containerId);

        SpcsSpecExtension specExtension = proxySpec.getSpecExtension(SpcsSpecExtension.class);
        try {
            // Build environment variables
            Map<String, String> env = buildEnv(authentication, spec, proxy);

            // Generate service name (must be unique and valid Snowflake identifier)
            String serviceName = generateServiceName(proxy.getId(), initialContainer.getIndex());

            // Build service YAML spec
            String serviceSpecYaml = buildServiceSpecYaml(spec, env, specExtension, proxy, serviceName, authentication);

            // Create service spec
            ServiceSpecInlineText serviceSpec = new ServiceSpecInlineText();
            serviceSpec.setSpecType("from_inline"); // Set discriminator value for polymorphic type
            serviceSpec.setSpecText(serviceSpecYaml);

            // Create service
            Service service = new Service();
            service.setName(serviceName);
            service.setComputePool(specExtension.getSpcsComputePool().getValueOrDefault(computePool));
            service.setSpec(serviceSpec);

            // Set external access integrations: use spec-level if specified, otherwise use global config
            List<String> externalAccessIntegrations = specExtension.getSpcsExternalAccessIntegrations().getValueOrNull();
            if (externalAccessIntegrations == null || externalAccessIntegrations.isEmpty()) {
                externalAccessIntegrations = this.externalAccessIntegrations;
            }
            if (externalAccessIntegrations != null && !externalAccessIntegrations.isEmpty()) {
                service.setExternalAccessIntegrations(externalAccessIntegrations);
            }

            // Store runtime values in comment field for recovery (similar to Docker labels)
            // This allows automatic parsing during recovery using parseCommentAsRuntimeValues()
            // proxy-id and container-index are also included for convenience (they're also in service name)
            // Note: Some values can't be stored here:
            //   - image: stored in service spec (YAML), extracted during recovery
            Map<String, String> commentMetadata = new HashMap<>();
            
            // Store all runtime values that should be included for recovery
            Stream.concat(
                proxy.getRuntimeValues().values().stream(),
                initialContainer.getRuntimeValues().values().stream()
            ).forEach(runtimeValue -> {
                if (runtimeValue.getKey().getIncludeAsLabel() || runtimeValue.getKey().getIncludeAsAnnotation()) {
                    commentMetadata.put(runtimeValue.getKey().getKeyAsLabel(), runtimeValue.toString());
                }
            });
            
            String comment = JSON.getGson().toJson(commentMetadata);
            service.setComment(comment);

            // Tell the status service we are starting the container
            proxyStartupLogBuilder.startingContainer(initialContainer.getIndex());

            // Create the service
            String fullServiceName = database + "." + schema + "." + serviceName;
            try {
                snowflakeServiceAPI.createService(database, schema, service, "ifNotExists");
                slog.info(proxy, String.format("Created Snowflake service: %s", fullServiceName));
            } catch (ApiException e) {
                if (e.getCode() != 409) { // 409 = conflict, which is OK if service exists
                    throw new ContainerFailedToStartException("Failed to create Snowflake service: " + e.getMessage(), e, rContainerBuilder.build());
                }
            }

            rContainerBuilder.addRuntimeValue(new RuntimeValue(BackendContainerNameKey.inst, new BackendContainerName(fullServiceName)), false);
            applicationEventPublisher.publishEvent(new NewProxyEvent(proxy.toBuilder().updateContainer(rContainerBuilder.build()).build(), authentication));

            // Wait for service to be ready (and endpoints if running external to SPCS)
            boolean needsEndpoints = !isRunningInsideSpcs() && spec.getPortMapping() != null && !spec.getPortMapping().isEmpty();
            String waitMessage = needsEndpoints ? "SPCS Service and Endpoints" : "SPCS Service";
            
            boolean serviceReady = Retrying.retry((currentAttempt, maxAttempts) -> {
                try {
                    // Check if service containers are running/ready
                    List<ServiceContainer> containers = snowflakeServiceAPI.listServiceContainers(database, schema, serviceName);
                    boolean serviceRunning = false;
                    if (containers != null && !containers.isEmpty()) {
                        // Check if any container is running/ready
                        for (ServiceContainer serviceContainer : containers) {
                            String status = serviceContainer.getStatus();
                            String serviceStatus = serviceContainer.getServiceStatus();
                            if (status != null && (status.equals("RUNNING") || status.equals("UP") || status.equals("READY"))) {
                                serviceRunning = true;
                                break;
                            }
                            if (serviceStatus != null && (serviceStatus.equals("RUNNING") || serviceStatus.equals("UP") || serviceStatus.equals("READY"))) {
                                serviceRunning = true;
                                break;
                            }
                            if (status != null && (status.equals("FAILED") || status.equals("ERROR"))) {
                                slog.warn(proxy, String.format("SPCS service container failed: status=%s, message=%s", status, serviceContainer.getMessage()));
                                return new Retrying.Result(false, false);
                            }
                        }
                    }
                    
                    // If service is not running yet, keep waiting
                    if (!serviceRunning) {
                        return Retrying.FAILURE;
                    }
                    
                    // If running external to SPCS, also check endpoints are ready
                    if (needsEndpoints) {
                        List<ServiceEndpoint> endpoints = snowflakeServiceAPI.showServiceEndpoints(database, schema, serviceName);
                        if (endpoints == null || endpoints.isEmpty()) {
                            return Retrying.FAILURE;
                        }
                        
                        // Check if all expected endpoints have valid ingress URLs
                        for (eu.openanalytics.containerproxy.model.spec.PortMapping portMapping : spec.getPortMapping()) {
                            boolean foundValidEndpoint = false;
                            for (ServiceEndpoint endpoint : endpoints) {
                                if (endpoint.getPort() != null && endpoint.getPort().equals(portMapping.getPort()) &&
                                    endpoint.getIsPublic() != null && endpoint.getIsPublic() &&
                                    "HTTP".equalsIgnoreCase(endpoint.getProtocol())) {
                                    String ingressUrl = endpoint.getIngressUrl();
                                    if (ingressUrl != null && !ingressUrl.isEmpty() &&
                                        !ingressUrl.toLowerCase().contains("provisioning") &&
                                        !ingressUrl.toLowerCase().contains("progress") &&
                                        (ingressUrl.contains("://") || ingressUrl.contains("."))) {
                                        foundValidEndpoint = true;
                                        break;
                                    }
                                }
                            }
                            if (!foundValidEndpoint) {
                                return Retrying.FAILURE;
                            }
                        }
                    }
                    
                    // Both service and endpoints (if needed) are ready
                    return Retrying.SUCCESS;
                } catch (ApiException e) {
                    slog.warn(proxy, String.format("Error checking service status: %s", e.getMessage()));
                    return Retrying.FAILURE;
                }
            }, serviceWaitTime, waitMessage, 10, proxy, slog);

            if (!serviceReady) {
                // Try to fetch and include logs in error message
                String logInfo = fetchServiceLogsForError(database, schema, serviceName);
                String errorMessage = "Service failed to start" + (needsEndpoints ? " or endpoints failed to provision" : "");
                if (logInfo != null && !logInfo.isEmpty()) {
                    // Log the container logs separately so they appear in the log output before service deletion
                    slog.warn(proxy, String.format("Container logs for failed service %s:\n%s", serviceName, logInfo));
                    errorMessage += ". Container logs: " + logInfo;
                }
                throw new ContainerFailedToStartException(errorMessage, null, rContainerBuilder.build());
            }

            proxyStartupLogBuilder.containerStarted(initialContainer.getIndex());

            // Get service image info (from service spec)
            rContainerBuilder.addRuntimeValue(new RuntimeValue(ContainerImageKey.inst, spec.getImage().getValue()), false);

            Proxy.ProxyBuilder proxyBuilder = proxy.toBuilder();
            Map<Integer, Integer> portBindings = new HashMap<>();
            Container rContainer = rContainerBuilder.build();
            Map<String, URI> targets = setupPortMappingExistingProxy(proxy, rContainer, portBindings);
            proxyBuilder.addTargets(targets);
            
            // when forwarding HTTP requests to SPCS we need to switch from "Bearer" authorization used on REST API to "Snowflake Token" authorization
            // Extract endpoint URL from targets for keypair auth token exchange scope
            // TODO: how do we refresh the short lived "Snowflake Token" after the proxy has been running for a while?
            String endpointUrl = extractEndpointUrlFromTargets(targets);
            
            Map<String, String> headers = setupProxyContainerHTTPHeaders(proxy, endpointUrl, authentication);
            proxyBuilder.addRuntimeValue(new RuntimeValue(HttpHeadersKey.inst, new HttpHeaders(headers)), true);
            proxyBuilder.updateContainer(rContainer);
            return proxyBuilder.build();
        } catch (ContainerFailedToStartException t) {
            throw t;
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new ContainerFailedToStartException("SPCS container failed to start", interruptedException, rContainerBuilder.build());
        } catch (Throwable throwable) {
            throw new ContainerFailedToStartException("SPCS container failed to start", throwable, rContainerBuilder.build());
        }
    }

    private String generateServiceName(String proxyId, Integer containerIndex) {
        // Snowflake service names must be valid identifiers (alphanumeric and underscore)
        // Use uppercase to match Snowflake's behavior and avoid case sensitivity issues
        // Pattern: SP_SERVICE__<proxyId_with_underscores>__<containerIndex>
        // Use double underscores as separators for easier parsing
        // Replace dashes (from UUID format) with single underscores for exact recovery
        // Note: proxyId is expected to be a UUID (alphanumeric + hyphens only)
        String normalizedProxyId = proxyId.toUpperCase().replace("-", "_");        
        String serviceName = "SP_SERVICE__" + normalizedProxyId + "__" + containerIndex;
        
        // Ensure it doesn't exceed Snowflake identifier length of 255 chars
        if (serviceName.length() > 255) {
            serviceName = serviceName.substring(0, 255);
        }
        return serviceName;
    }

    private String buildServiceSpecYaml(ContainerSpec spec, Map<String, String> env, SpcsSpecExtension specExtension, Proxy proxy, String serviceName, Authentication authentication) {
        StringBuilder yaml = new StringBuilder();
        yaml.append("spec:\n");
        yaml.append("  containers:\n");
        yaml.append("  - name: ").append(quoteYamlValue(spec.getResourceName().getValueOrDefault("container"))).append("\n");
        
        // Image from Snowflake image repository
        // Format should be: /<database>/<schema>/<repository>/<image>:<tag>
        // If image contains snowflakecomputing.com domain, remove it and convert to the correct format
        String image = spec.getImage().getValue();
        image = formatSnowflakeImageName(image);
        yaml.append("    image: ").append(quoteYamlValue(image)).append("\n");
        
        // Command
        if (spec.getCmd().isPresent() && !spec.getCmd().getValue().isEmpty()) {
            yaml.append("    command:\n");
            for (String cmd : spec.getCmd().getValue()) {
                yaml.append("    - ").append(quoteYamlValue(cmd)).append("\n");
            }
        }
        
        // Environment variables (must be a map, not a list)
        if (!env.isEmpty()) {
            yaml.append("    env:\n");
            for (Map.Entry<String, String> entry : env.entrySet()) {
                yaml.append("      ").append(quoteYamlValue(entry.getKey())).append(": ").append(quoteYamlValue(entry.getValue())).append("\n");
            }
        }
        
        // Resources (memory and CPU)
        yaml.append("    resources:\n");
        boolean hasRequests = false;
        if (spec.getMemoryRequest().isPresent()) {
            yaml.append("      requests:\n");
            hasRequests = true;
            String memoryValue = formatMemoryValue(spec.getMemoryRequest().getValue());
            yaml.append("        memory: ").append(memoryValue).append("\n");
        }
        if (spec.getCpuRequest().isPresent()) {
            if (!hasRequests) {
                yaml.append("      requests:\n");
            }
            String cpuValue = formatCpuValue(spec.getCpuRequest().getValue());
            yaml.append("        cpu: ").append(cpuValue).append("\n");
        }
        
        // Ports/endpoints (at containers level)
        // Endpoints are always needed (even when running inside SPCS) for internal DNS to be available
        List<String> endpointNames = new ArrayList<>();
        if (spec.getPortMapping() != null && !spec.getPortMapping().isEmpty()) {
            yaml.append("  endpoints:\n");
            for (eu.openanalytics.containerproxy.model.spec.PortMapping portMapping : spec.getPortMapping()) {
                String endpointName = portMapping.getName();
                endpointNames.add(endpointName);
                yaml.append("  - name: ").append(quoteYamlValue(endpointName)).append("\n");
                yaml.append("    port: ").append(portMapping.getPort()).append("\n");
                yaml.append("    protocol: HTTP\n"); // Public endpoints only support HTTP
                // Set public access: true when running external to SPCS, false when running inside SPCS (internal DNS is used)
                yaml.append("    public: ").append(!isRunningInsideSpcs()).append("\n");
            }
        }
        
        // Capabilities (at root level, same as spec)
        // Set executeAsCaller: true only if SPCS user token is available (indicates caller's rights context)
        yaml.append("capabilities:\n");
        yaml.append("  securityContext:\n");
        boolean executeAsCaller = false;
        if (authentication instanceof SpcsAuthenticationToken) {
            Object credentials = authentication.getCredentials();
            if (credentials != null) {
                String userToken = credentials.toString();
                if (!userToken.isBlank()) {
                    executeAsCaller = true;
                }
            }
        }
        yaml.append("    executeAsCaller: ").append(executeAsCaller).append("\n");
        
        // Service roles (at root level, same as spec)
        // Service roles are always needed (even when running inside SPCS) when endpoints are present
        if (!endpointNames.isEmpty()) {
            yaml.append("serviceRoles:\n");
            yaml.append("- name: ").append(quoteYamlValue(serviceName)).append("\n");
            yaml.append("  endpoints:\n");
            for (String endpointName : endpointNames) {
                yaml.append("  - ").append(quoteYamlValue(endpointName)).append("\n");
            }
        }
        
        return yaml.toString();
    }

    /**
     * Formats a Snowflake image name to the correct format.
     * If the image contains a snowflakecomputing.com domain, removes it and extracts the path.
     * Expected format: /<database>/<schema>/<repository>/<image>:<tag>
     * 
     * @param image The image name (e.g., "org-account.registry.snowflakecomputing.com/path/to/image:tag" or "/path/to/image:tag")
     * @return Formatted image name with domain removed (e.g., "/path/to/image:tag")
     */
    private String formatSnowflakeImageName(String image) {
        if (image == null || image.isEmpty()) {
            return image;
        }
        
        // If image contains snowflakecomputing.com, extract the path part after the domain
        if (image.contains("snowflakecomputing.com")) {
            // Find the path part after the domain (look for / after snowflakecomputing.com)
            int domainIndex = image.indexOf("snowflakecomputing.com");
            int pathStart = image.indexOf('/', domainIndex);
            if (pathStart >= 0) {
                // Extract path starting from /
                return image.substring(pathStart);
            }
            // If no / found after domain, return as-is (unlikely but handle gracefully)
            return image;
        }
        
        // If image already starts with /, it's already in the correct format
        // Otherwise, return as-is (might be a different format)
        return image;
    }

    /**
     * Formats a memory value for Snowflake SPCS.
     * If the value already has a unit (g, gi, m, mi, t, ti), returns it as-is.
     * Otherwise, assumes the value is in megabytes and converts to appropriate unit.
     * 
     * Supported units: g, gi, m, mi, t, ti (Snowflake accepts capitalized forms like Gi, Mi)
     * Converts large values to larger units (e.g., 2048m -> 2Gi, 1024m -> 1Gi)
     * 
     * @param memoryValue The memory value (e.g., "2048" or "2Gi")
     * @return Formatted memory value with capitalized unit (e.g., "2Gi" or "512Mi")
     */
    private String formatMemoryValue(String memoryValue) {
        if (memoryValue == null || memoryValue.isEmpty()) {
            return memoryValue;
        }
        // Check if value already has a supported unit (case-insensitive)
        // Supported units per Snowflake docs: M, Mi, G, Gi (uppercase first letter required)
        String lowerValue = memoryValue.toLowerCase();
        if (lowerValue.matches(".*(m|mi|g|gi)$")) {
            // Already has a unit, normalize to uppercase first letter
            // Extract the numeric part and unit
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("^(\\d+(?:\\.\\d+)?)([mM][iI]?|[gG][iI]?)$");
            java.util.regex.Matcher matcher = pattern.matcher(memoryValue);
            if (matcher.matches()) {
                String numberPart = matcher.group(1);
                String unitPart = matcher.group(2).toLowerCase();
                // Normalize unit: m -> M, mi -> Mi, g -> G, gi -> Gi
                String normalizedUnit;
                if (unitPart.equals("m")) {
                    normalizedUnit = "M";
                } else if (unitPart.equals("mi")) {
                    normalizedUnit = "Mi";
                } else if (unitPart.equals("g")) {
                    normalizedUnit = "G";
                } else if (unitPart.equals("gi")) {
                    normalizedUnit = "Gi";
                } else {
                    normalizedUnit = unitPart; // Should not happen
                }
                return numberPart + normalizedUnit;
            }
            // If regex doesn't match, return as-is (shouldn't happen)
            return memoryValue;
        }
        
        // Parse the numeric value
        try {
            double value = Double.parseDouble(memoryValue);
            
            // Convert megabytes to appropriate unit with capitalized format
            // 1024 MB = 1 GiB, 1000 MB = 1 GB
            // Use binary units (Gi, Mi) for consistency with Kubernetes conventions
            if (value >= 1024) {
                // Convert to GiB (gibibytes)
                double gib = value / 1024;
                // Format to remove unnecessary decimals
                if (gib == Math.floor(gib)) {
                    return String.valueOf((long) gib) + "Gi";
                } else {
                    // Round to 2 decimal places for large values
                    return String.format("%.2fGi", gib).replaceAll("\\.?0+$", "");
                }
            } else {
                // Use MiB (mebibytes) for values < 1024 MB
                return (long) value + "Mi";
            }
        } catch (NumberFormatException e) {
            // If parsing fails, just append "Mi" as fallback
            return memoryValue + "Mi";
        }
    }

    /**
     * Formats a CPU value for Snowflake SPCS.
     * CPU can be specified as:
     * - Millicores with "m" suffix (e.g., "500m", "1000m") - returned as-is
     *   According to Snowflake docs, fractional CPUs can be expressed as "m" (e.g., 500m = 0.5 CPUs)
     * - Fractional CPUs directly (e.g., "0.5", "1", "2.5") - returned as-is
     * - Whole numbers >= 1 without unit - treated as millicores and converted to fractional CPUs
     *   (e.g., "256" -> "0.256", "1000" -> "1", "1500" -> "1.5")
     * 
     * Reference: https://docs.snowflake.com/en/developer-guide/snowpark-container-services/specification-reference#containers-resources-field
     * 
     * @param cpuValue The CPU value (e.g., "256", "1000", "0.5", "500m", or "1000m")
     * @return Formatted CPU value (e.g., "0.256", "1", "0.5", "500m", or "1000m")
     */
    private String formatCpuValue(String cpuValue) {
        if (cpuValue == null || cpuValue.isEmpty()) {
            return cpuValue;
        }
        // Check if value already has "m" unit (millicores)
        String lowerValue = cpuValue.toLowerCase();
        if (lowerValue.endsWith("m")) {
            // Already has millicore unit, return as-is (Snowflake accepts "m" suffix for fractional CPUs)
            return cpuValue;
        }
        
        // Parse the numeric value
        try {
            double value = Double.parseDouble(cpuValue);
            
            // If value < 1, assume it's already in fractional CPU format (e.g., 0.5)
            if (value < 1.0) {
                return cpuValue;
            }
            
            // Value >= 1, assume it's in millicores and convert to fractional CPUs
            // (e.g., 256 millicores = 0.256 CPUs, 1000 millicores = 1 CPU)
            double cpus = value / 1000.0;
            // Format to remove unnecessary decimals
            if (cpus == Math.floor(cpus)) {
                return String.valueOf((long) cpus);
            } else {
                // Round to 3 decimal places and remove trailing zeros
                return String.format("%.3f", cpus).replaceAll("\\.?0+$", "");
            }
        } catch (NumberFormatException e) {
            // If parsing fails, return as-is
            return cpuValue;
        }
    }

    /**
     * Safely quotes a YAML string value to prevent injection attacks.
     * Escapes special characters and wraps in double quotes when necessary.
     */
    private String quoteYamlValue(String value) {
        if (value == null) {
            return "\"\"";
        }
        
        // Always quote values that could be interpreted as YAML syntax
        // Check for special YAML characters, control characters, or values that look like YAML types
        boolean needsQuoting = value.contains(":") 
            || value.contains("#") 
            || value.contains("@") 
            || value.contains("&") 
            || value.contains("*") 
            || value.contains("!") 
            || value.contains("|") 
            || value.contains(">") 
            || value.contains("'") 
            || value.contains("\"") 
            || value.contains("\n") 
            || value.contains("\r") 
            || value.contains("\t")
            || value.contains("{{")  // Template syntax
            || value.contains("}}")
            || value.trim().isEmpty()  // Empty strings
            || value.matches("^(true|false|null|yes|no|on|off)$")  // YAML boolean/null keywords
            || value.matches("^-?\\d+$")  // Numbers at start of line
            || value.startsWith("-")  // List indicator
            || value.startsWith("[")  // Array syntax
            || value.startsWith("{");  // Object syntax
        
        if (needsQuoting) {
            // Escape backslashes first, then quotes
            String escaped = value
                .replace("\\", "\\\\")  // Escape backslashes
                .replace("\"", "\\\"")  // Escape double quotes
                .replace("\n", "\\n")   // Escape newlines
                .replace("\r", "\\r")   // Escape carriage returns
                .replace("\t", "\\t");  // Escape tabs
            return "\"" + escaped + "\"";
        }
        
        return value;
    }

    @Override
    protected void doStopProxy(Proxy proxy) {
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        for (Container container : proxy.getContainers()) {
            String fullServiceName = container.getRuntimeValue(BackendContainerNameKey.inst);
            if (fullServiceName != null) {
                // Parse full service name: database.schema.service
                String[] parts = fullServiceName.split("\\.");
                if (parts.length == 3) {
                    String serviceDb = parts[0];
                    String serviceSchema = parts[1];
                    String serviceName = parts[2];
                    try {
                        snowflakeServiceAPI.deleteService(serviceDb, serviceSchema, serviceName, true);
                        slog.info(proxy, String.format("Deleted Snowflake service: %s", fullServiceName));
                    } catch (ApiException e) {
                        slog.warn(proxy, String.format("Error deleting Snowflake service %s: %s", fullServiceName, e.getMessage()));
                    }
                }
            }
        }

        // Wait for service to be stopped
        boolean isInactive = Retrying.retry((currentAttempt, maxAttempts) -> {
            for (Container container : proxy.getContainers()) {
                String fullServiceName = container.getRuntimeValue(BackendContainerNameKey.inst);
                if (fullServiceName != null) {
                    String[] parts = fullServiceName.split("\\.");
                    if (parts.length == 3) {
                        try {
                            List<ServiceContainer> containers = snowflakeServiceAPI.listServiceContainers(parts[0], parts[1], parts[2]);
                            // If we can list containers, service is not fully stopped
                            if (containers != null && !containers.isEmpty()) {
                            // Check if containers are stopped/suspended
                            boolean allStopped = true;
                            for (ServiceContainer serviceContainer : containers) {
                                String status = serviceContainer.getStatus();
                                String serviceStatus = serviceContainer.getServiceStatus();
                                if (status != null && !status.equals("SUSPENDED") && !status.equals("STOPPED") && !status.equals("DELETED")) {
                                    allStopped = false;
                                    break;
                                }
                                if (serviceStatus != null && !serviceStatus.equals("SUSPENDED") && !serviceStatus.equals("STOPPED") && !serviceStatus.equals("DELETED")) {
                                    allStopped = false;
                                    break;
                                }
                            }
                                if (!allStopped) {
                                    return Retrying.FAILURE;
                                }
                            }
                        } catch (ApiException e) {
                            // Service might be deleted already
                            if (e.getCode() == 404) {
                                return Retrying.SUCCESS;
                            }
                        }
                    }
                }
            }
            return Retrying.SUCCESS;
        }, serviceWaitTime, "Stopping SPCS Service", 0, proxy, slog);

        if (!isInactive) {
            slog.warn(proxy, "Service did not get into stopping state");
        }
    }

    @Override
    public void stopProxies(Collection<Proxy> proxies) {
        for (Proxy proxy : proxies) {
            try {
                stopProxy(proxy);
            } catch (Exception e) {
                log.error("Error stopping proxy", e);
            }
        }
    }

    @Override
    protected String getPropertyPrefix() {
        return PROPERTY_PREFIX;
    }

    @Override
    public List<ExistingContainerInfo> scanExistingContainers() {
        log.info("Scanning for existing SPCS services to recover in database schema {}.{}", database, schema);
        ArrayList<ExistingContainerInfo> containers = new ArrayList<>();
        
        try {
            // List services starting with "SP_SERVICE_" (uppercase for consistency with Snowflake)
            List<Service> services = snowflakeServiceAPI.listServices(database, schema, "SP_SERVICE__%", null, null, null);
            
            if (services == null || services.isEmpty()) {
                log.info("No existing SPCS services found to recover");
                return containers;
            }
            
            log.info("Found {} SPCS service(s) to scan for recovery", services.size());
            
            for (Service service : services) {
                String serviceName = service.getName();
                // Service names are always uppercase, check for "SP_SERVICE_" prefix
                if (serviceName == null || !serviceName.startsWith("SP_SERVICE__")) {
                    continue;
                }
                
                // Check if service has containers and is running, delete if not
                if (!checkServiceContainersAndRunningStatus(serviceName)) {
                    deleteServiceLogReason(serviceName, "Service has no containers or no running containers");
                    continue;
                }
                
                // Fetch service and extract all metadata (image, comment metadata, proxyId, containerIndex)
                Map<String, String> metadata = new HashMap<>();
                
                if (!fetchServiceImageAndMetadata(serviceName, metadata)) {
                    deleteServiceLogReason(serviceName, "Error fetching service metadata");
                    continue;
                }
                
                // Validate and delete if unrecoverable (uses comment metadata as primary source)
                if (!validateAndDeleteIfUnrecoverable(serviceName, metadata)) {
                    continue; // Service was deleted
                }
                
                // Build and add to recovery list (all data comes from comment metadata)
                ExistingContainerInfo containerInfo = buildExistingContainerInfo(serviceName, metadata);
                containers.add(containerInfo);
                String recoveredUserId = metadata.get(UserIdKey.inst.getKeyAsLabel());
                String recoveredProxyId = metadata.get(ProxyIdKey.inst.getKeyAsLabel());
                String recoveredSpecId = metadata.get(ProxySpecIdKey.inst.getKeyAsLabel());
                log.info("Added service {} to recovery list (userId: {}, proxyId: {}, specId: {})", 
                            serviceName, recoveredUserId, recoveredProxyId, recoveredSpecId);
            }
            
            log.info("Completed scanning SPCS services: {} recoverable service(s) found", containers.size());
        } catch (ApiException e) {
            log.error("Error listing services for scan: {}", e.getMessage(), e);
        }
        
        return containers;
    }

    /**
     * Deletes a service with error handling and logging.
     */
    private void deleteServiceLogReason(String serviceName, String reason) {
        log.warn("Deleting service {} due to: {}", serviceName, reason);
        try {
            snowflakeServiceAPI.deleteService(database, schema, serviceName, true);
            log.info("Deleted Snowflake service: {}.{}.{}", database, schema, serviceName);
        } catch (ApiException e) {
            log.warn("Error deleting Snowflake service {}.{}.{}: {}", database, schema, serviceName, e.getMessage());
        }
    }
    
    /**
     * Checks if service has containers and if any are running. Returns false if service should be deleted or on error.
     * Does not delete the service - caller is responsible for deletion.
     */
    private boolean checkServiceContainersAndRunningStatus(String serviceName) {
        try {
            List<ServiceContainer> serviceContainers = snowflakeServiceAPI.listServiceContainers(database, schema, serviceName);
            if (serviceContainers == null || serviceContainers.isEmpty()) {
                log.warn("Service {} has no containers", serviceName);
                return false;
            }
            
            // Check if any container is running/ready
            boolean hasRunningContainer = false;
            for (ServiceContainer serviceContainer : serviceContainers) {
                String status = serviceContainer.getStatus();
                String serviceStatus = serviceContainer.getServiceStatus();
                if ((status != null && (status.equals("RUNNING") || status.equals("UP") || status.equals("READY"))) ||
                    (serviceStatus != null && (serviceStatus.equals("RUNNING") || serviceStatus.equals("UP") || serviceStatus.equals("READY")))) {
                    hasRunningContainer = true;
                    break;
                }
            }
            
            if (!hasRunningContainer) {
                log.warn("Service {} has no running containers", serviceName);
                return false;
            }
            
            return true;
        } catch (ApiException e) {
            log.warn("Error checking service containers for {}: {}", serviceName, e.getMessage());
            return false;
        }
    }
    
    /**
     * Also calculates and stores Authorization header for SPCS ingress access
     * Adds image, comment metadata, and endpoint URL to the metadata map.
     * @param serviceName The service name to fetch
     * @param metadata Map to populate with service metadata (will also contain "endpointUrl" key)
     * @return true if successful, false on error
     */
    private boolean fetchServiceImageAndMetadata(String serviceName, Map<String, String> metadata) {
        try {
            // Get the Service object - polymorphic deserialization is now handled correctly by CustomTypeAdapterFactory
            Service fullService = snowflakeServiceAPI.fetchService(database, schema, serviceName);
            ServiceSpec serviceSpec = fullService.getSpec();
            
            // Extract spec_text (YAML string) from the properly deserialized ServiceSpecInlineText
            String specText = null;
            if (serviceSpec instanceof ServiceSpecInlineText) {
                specText = ((ServiceSpecInlineText) serviceSpec).getSpecText();
            }
            
            // Extract comment (metadata)
            // Comment contains all runtime values stored during service creation (similar to Docker labels)
            String comment = fullService.getComment();
            if (comment != null && !comment.isEmpty()) {
                try {
                    TypeToken<Map<String, String>> typeToken = new TypeToken<Map<String, String>>() {};
                    Map<String, String> commentMetadata = JSON.getGson().fromJson(comment, typeToken.getType());
                    if (commentMetadata != null) {
                        metadata.putAll(commentMetadata);
                        log.debug("Extracted {} metadata entries from comment for service {}", commentMetadata.size(), serviceName);
                    }
                } catch (Exception e) {
                    log.warn("Error parsing metadata from comment for service {}: {}", serviceName, e.getMessage());
                }
            }
            
            if (specText != null && !specText.isEmpty()) {
                String image = extractImageFromSpecText(specText);
                if (image != null && !image.isEmpty()) {
                    metadata.put("image", image);
                } else {
                    log.warn("Failed to extract image from service spec for service {} (specText length: {})", serviceName, specText.length());
                }
            } else {
                log.warn("Service spec text is null or empty for service {}", serviceName);
            }
                       
            return true;
        } catch (ApiException e) {
            log.warn("Error fetching service spec for {}: {}", serviceName, e.getMessage());
            return false;
        }
    }
    
    /**
     * Extracts image name from YAML spec text.
     * Expected YAML structure:
     *   spec:
     *     containers:
     *     - name: <name>
     *       image: <image>
     */
    private String extractImageFromSpecText(String specText) {
        if (specText == null || specText.isEmpty()) {
            log.warn("extractImageFromSpecText: specText is null or empty");
            return null;
        }
        
        String[] lines = specText.split("\n");
        boolean inContainersSection = false;
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            
            if (trimmed.isEmpty()) {
                continue;
            }
            
            // Detect containers section
            if (trimmed.equals("containers:") || trimmed.startsWith("containers:")) {
                inContainersSection = true;
                continue;
            }
            
            // If we're in containers section, look for the image field
            if (inContainersSection) {
                // Check if we've left the containers section (hit a top-level key at same or less indentation as "containers:")
                int leadingSpaces = line.length() - line.trim().length();
                if (leadingSpaces <= 2 && !trimmed.startsWith("-") && 
                    !trimmed.startsWith("name:") && !trimmed.startsWith("image:") && 
                    !trimmed.startsWith("command:") && !trimmed.startsWith("env:") &&
                    !trimmed.startsWith("resources:")) {
                    // We've left the containers section
                    break;
                }
                
                // Look for image: field (should be at 4 spaces indentation, after "- name:")
                if (trimmed.startsWith("image:")) {
                    String image = trimmed.substring(6).trim();
                    if (image.isEmpty()) {
                        log.warn("extractImageFromSpecText: found 'image:' but value is empty at line {}", i + 1);
                        continue;
                    }
                    
                    // Remove quotes if present
                    if ((image.startsWith("\"") && image.endsWith("\"")) ||
                        (image.startsWith("'") && image.endsWith("'"))) {
                        image = image.substring(1, image.length() - 1);
                    }
                    
                    log.debug("extractImageFromSpecText: extracted image '{}' from line {}", image, i + 1);
                    return image;
                }
            }
        }
        
        log.warn("extractImageFromSpecText: could not find 'image:' field in spec text ({} lines, inContainersSection={})", 
                 lines.length, inContainersSection);
        return null;
    }
    
    /**
     * Validates service metadata and deletes service if unrecoverable. Returns false if service was deleted.
     * Uses comment metadata as primary source (label keys like "openanalytics.eu/sp-proxy-id").
     */
    private boolean validateAndDeleteIfUnrecoverable(String serviceName, Map<String, String> metadata) {
        // Get values from comment metadata using label keys
        String instanceId = metadata.get(InstanceIdKey.inst.getKeyAsLabel());
        
        // Check realm-id validation
        // If current instance has realm-id configured but service doesn't, delete it (orphaned from before realm-id was used)
        // If both have realm-id but they don't match, skip it (belongs to another ShinyProxy instance)
        String storedRealmId = metadata.get(RealmIdKey.inst.getKeyAsLabel());
        String currentRealmId = identifierService.realmId;
        if (currentRealmId != null && storedRealmId == null) {
            // Current instance uses realm-id but service doesn't have it - delete orphaned service
            deleteServiceLogReason(serviceName, "Missing realm-id");
            return false;
        }
        if (storedRealmId != null && currentRealmId != null && !storedRealmId.equals(currentRealmId)) {
            // Both have realm-id but they don't match - skip it (belongs to another instance)
            log.debug("Skipping service {} because realm-id mismatch (stored: {}, current: {})", 
                    serviceName, storedRealmId, currentRealmId);
            return false;
        }
        
        // Check if we can recover this proxy based on instanceId
        // This ensures we only recover containers started with the current config (unless recover-running-proxies-from-different-config is enabled)
        if (!appRecoveryService.canRecoverProxy(instanceId)) {
            deleteServiceLogReason(serviceName, String.format("InstanceId mismatch (stored: %s, current: %s)", 
                    instanceId, identifierService.instanceId));
            return false;
        }
        
        return true;
    }
    
    /**
     * Parses service comment JSON to extract runtime values (similar to Docker's parseLabelsAsRuntimeValues).
     * This automatically extracts all runtime values that were stored in the comment during service creation.
     * 
     * @param serviceName The service name (for logging)
     * @param commentMetadata Map of label keys to string values from the service comment JSON
     * @return Map of RuntimeValueKey to RuntimeValue, or null if parsing failed
     */
    private Map<RuntimeValueKey<?>, RuntimeValue> parseCommentAsRuntimeValues(String serviceName, Map<String, String> commentMetadata) {
        if (commentMetadata == null || commentMetadata.isEmpty()) {
            log.warn("Comment metadata is null or empty for service {}", serviceName);
            return new HashMap<>();
        }

        Map<RuntimeValueKey<?>, RuntimeValue> runtimeValues = new HashMap<>();

        for (RuntimeValueKey<?> key : RuntimeValueKeyRegistry.getRuntimeValueKeys()) {
            if (key.getIncludeAsLabel() || key.getIncludeAsAnnotation()) {
                String value = commentMetadata.get(key.getKeyAsLabel());
                if (value != null) {
                    try {
                        runtimeValues.put(key, new RuntimeValue(key, key.deserializeFromString(value)));
                    } catch (Exception e) {
                        log.warn("Error deserializing runtime value {} for service {}: {}", key.getKeyAsLabel(), serviceName, e.getMessage());
                    }
                } else if (key.isRequired()) {
                    // value is null but is required - this might be a problem, but don't fail here
                    // Some required values might come from other sources (service name, service properties, etc.)
                    log.debug("Required runtime value {} not found in comment for service {}", key.getKeyAsLabel(), serviceName);
                }
            }
        }

        return runtimeValues;
    }
    
    /**
     * Builds ExistingContainerInfo from metadata map containing all extracted service data.
     * Uses parseCommentAsRuntimeValues to automatically extract runtime values from comment (similar to Docker labels).
     */
    private ExistingContainerInfo buildExistingContainerInfo(String serviceName, Map<String, String> metadata) {
        // Full service name: database.schema.serviceName
        String fullServiceName = database + "." + schema + "." + serviceName;
        
        // Extract values needed for validation/special handling
        String image = metadata.get("image");

        
        // Parse runtime values from comment metadata (similar to Docker labels)
        // This automatically extracts all runtime values that were stored in the comment
        Map<RuntimeValueKey<?>, RuntimeValue> runtimeValues = parseCommentAsRuntimeValues(serviceName, metadata);
        
        // Add/override special values that can't be stored in comment (they have includeAsLabel/includeAsAnnotation=false):
        
        // 1. BackendContainerName - full service name (not stored in comment, derived from service name)
        // BackendContainerNameKey has includeAsLabel=false, so it must be set manually (same as Docker backend does)
        runtimeValues.put(BackendContainerNameKey.inst, new RuntimeValue(BackendContainerNameKey.inst, new BackendContainerName(fullServiceName)));
        
        // 2. ContainerImageKey - extracted from service spec (not stored in comment - has includeAsLabel=false)
        // Always add ContainerImageKey (required by ShinyProxy AdminController)
        if (image == null || image.isEmpty()) {
            log.warn("Image not found for service {}, using empty string for ContainerImageKey", serviceName);
            image = "";
        }
        runtimeValues.put(ContainerImageKey.inst, new RuntimeValue(ContainerImageKey.inst, image));
        
        // 3. Add Authorization header to HttpHeaders
        // Extract endpoint URL for authorization header (needed for keypair auth token exchange scope)
        String endpointUrl = extractEndpointUrlFromService(serviceName);
        if (endpointUrl != null) {
            HttpHeaders existingHeaders = null;
            RuntimeValue existingHeadersValue = runtimeValues.get(HttpHeadersKey.inst);
            if (existingHeadersValue != null) {
                existingHeaders = existingHeadersValue.getObject();
            }
            Map<String, String> headers = existingHeaders != null ? 
                new HashMap<>(existingHeaders.jsonValue()) : new HashMap<>();
            
            // Get the ingress authorization header
            String authorizationHeader = getIngressAuthorization(endpointUrl);
            if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
                headers.put("Authorization", authorizationHeader);
                log.debug("Added Authorization header for recovered SPCS service {} (auth method: {})", serviceName, authMethod);
            } else if (authMethod == AuthMethod.KEYPAIR) {
                log.warn("Ingress authorization header not available for recovered SPCS service {} (endpoint URL: {})", serviceName, endpointUrl);
            }
            
            // Note: Sf-Context-Current-User-Token header is not available during recovery
            // as we don't have access to the Authentication context. 
            // TODO: It will be added dynamically per request 
            
            runtimeValues.put(HttpHeadersKey.inst, new RuntimeValue(HttpHeadersKey.inst, new HttpHeaders(headers)));
        }

        // Empty port bindings (SPCS uses endpoints instead of Docker-style port bindings)
        // Ports are exposed via SPCS service endpoints, not mapped to host ports
        Map<Integer, Integer> portBindings = new HashMap<>();
        
        return new ExistingContainerInfo(serviceName, runtimeValues, image, portBindings);
    }

    @Override
    public boolean isProxyHealthy(Proxy proxy) {
        for (Container container : proxy.getContainers()) {
            String fullServiceName = container.getRuntimeValue(BackendContainerNameKey.inst);
            if (fullServiceName == null) {
                slog.warn(proxy, "SPCS container failed: service name not found");
                return false;
            }

            String[] parts = fullServiceName.split("\\.");
            if (parts.length != 3) {
                slog.warn(proxy, "SPCS container failed: invalid service name format");
                return false;
            }
            
            // Extract service name (last part) and reuse checkServiceContainersAndRunningStatus
            String serviceName = parts[2];
            if (!checkServiceContainersAndRunningStatus(serviceName)) {
                slog.warn(proxy, "SPCS container failed: service unhealthy");
                return false;
            }
        }
        return true;
    }

    /**
     * Extracts the endpoint URL from target URIs for keypair auth token exchange scope.
     * This is used when targets are already available (e.g., during startup).
     * 
     * @param targets The target URIs (may be null or empty)
     * @return The endpoint URL (scheme + host) or null if not available
     */
    private String extractEndpointUrlFromTargets(Map<String, URI> targets) {
        if (authMethod == AuthMethod.KEYPAIR && targets != null && !targets.isEmpty()) {
            // Extract endpoint URL from the first target URI (already set to ingress URL by calculateTarget)
            URI firstTarget = targets.values().iterator().next();
            if (firstTarget != null && "https".equals(firstTarget.getScheme())) {
                // Extract base URL (scheme + host) for the scope
                return firstTarget.getScheme() + "://" + firstTarget.getHost();
            }
        }
        return null;
    }

    /**
     * Extracts the endpoint URL from a service name by fetching its endpoints.
     * Uses the same logic as calculateTarget to find the first public endpoint's ingress URL.
     * This is used during recovery when we need the endpoint URL but don't have targets yet.
     * 
     * @param serviceName The service name (short name, not fully qualified)
     * @return The endpoint URL (scheme + host) or null if not available
     */
    private String extractEndpointUrlFromService(String serviceName) {

        try {
            // Fetch endpoints (same as calculateTarget does)
            List<ServiceEndpoint> endpoints = snowflakeServiceAPI.showServiceEndpoints(database, schema, serviceName);
            if (endpoints != null && !endpoints.isEmpty()) {
                // Find the first public HTTP endpoint (same logic as calculateTarget)
                for (ServiceEndpoint endpoint : endpoints) {
                    if (endpoint.getIsPublic() != null && endpoint.getIsPublic() &&
                        endpoint.getIngressUrl() != null && !endpoint.getIngressUrl().isEmpty() &&
                        "HTTP".equalsIgnoreCase(endpoint.getProtocol())) {
                        String ingressUrl = endpoint.getIngressUrl();
                        
                        // Ingress URL format is typically: https://{endpoint}.snowflakecomputing.com
                        // Extract base URL (scheme + host) for the scope
                        if (!ingressUrl.startsWith("https://") && !ingressUrl.startsWith("http://")) {
                            ingressUrl = "https://" + ingressUrl;
                        }
                        
                        try {
                            URI uri = new URI(ingressUrl);
                            return uri.getScheme() + "://" + uri.getHost();
                        } catch (java.net.URISyntaxException e) {
                            log.debug("Invalid ingress URL format for endpoint: {}", ingressUrl);
                        }
                        break;
                    }
                }
            }
        } catch (ApiException e) {
            log.debug("Could not fetch endpoints to get endpoint URL for keypair auth: {}", e.getMessage());
        }
        
        return null;
    }

    /**
     * Sets up HTTP headers for proxy container communication.
     * Sets Authorization header only when running external to SPCS (for ingress access).
     * Adds SPCS user context headers when authenticated via SPCS.
     * 
     * @param proxy The proxy (used to get existing headers and container info)
     * @param endpointUrl Optional endpoint URL for keypair auth token exchange scope (only used when external)
     * @param authentication The authentication object (may be null, used to extract SPCS user token)
     * @return Map of merged headers
     */
    private Map<String, String> setupProxyContainerHTTPHeaders(Proxy proxy, String endpointUrl, Authentication authentication) {
        // Get existing headers from proxy and merge with new headers
        HttpHeaders existingHeaders = proxy.getRuntimeObject(HttpHeadersKey.inst);
        Map<String, String> mergedHeaders = existingHeaders != null ? 
            new HashMap<>(existingHeaders.jsonValue()) : new HashMap<>();
        
        // Set Authorization header only when running external to SPCS (needed for ingress access)
        if (!isRunningInsideSpcs()) {
        String authorizationHeader = getIngressAuthorization(endpointUrl);
        
        if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
            mergedHeaders.put("Authorization", authorizationHeader);
            log.info("Setting up Authorization header for SPCS ingress access (auth method: {})", authMethod);
        } else if (authMethod == AuthMethod.KEYPAIR && endpointUrl != null) {
            log.warn("Ingress authorization header not available for SPCS access (endpoint URL: {})", endpointUrl);
            }
        }
        
        // Add SPCS user headers if authenticated via SPCS
        // These headers are forwarded to proxy containers so they can use the caller's identity
        // Username header is always added when SPCS authenticated; token header only if available
        if (authentication instanceof SpcsAuthenticationToken) {
            // Add username header (always present when SPCS authenticated)
            Object principal = authentication.getPrincipal();
            if (principal != null) {
                String username = principal.toString();
                if (!username.isBlank()) {
                    mergedHeaders.put("Sf-Context-Current-User", username);
                    log.debug("Added Sf-Context-Current-User to proxy HttpHeaders");
                }
            }
            
            // Add user token header (only present when executeAsCaller=true on parent service)
            Object credentials = authentication.getCredentials();
            if (credentials != null) {
                String userToken = credentials.toString();
                if (!userToken.isBlank()) {
                    mergedHeaders.put("Sf-Context-Current-User-Token", userToken);
                    log.debug("Added Sf-Context-Current-User-Token to proxy HttpHeaders");
                }
            }
        }
        
        return mergedHeaders;
    }

    protected URI calculateTarget(Container container, PortMappings.PortMappingEntry portMapping, Integer hostPort) throws Exception {
        String fullServiceName = container.getRuntimeValue(BackendContainerNameKey.inst);
        if (fullServiceName == null) {
            throw new ContainerFailedToStartException("Service name not found while calculating target", null, container);
        }

        // database.schema.service name
        String[] parts = fullServiceName.split("\\.");
        if (parts.length != 3) {
            throw new ContainerFailedToStartException("Invalid service name format: " + fullServiceName, null, container);
        }

        // Fetch service to get DNS name or ingress URL
        try {
            Service service = snowflakeServiceAPI.fetchService(parts[0], parts[1], parts[2]);
            
            if (isRunningInsideSpcs()) {
                // When running inside SPCS: use internal DNS name for communication
                // The DNS name format is: service-name.unique-id.svc.spcs.internal
                String serviceDnsName = service.getDnsName();            
                if (serviceDnsName == null || serviceDnsName.isEmpty()) {
                    throw new ContainerFailedToStartException("Service DNS name not available from REST API", null, container);
                }
                
                log.info("Proxy container DNS name: {}", serviceDnsName);
                
                int targetPort = portMapping.getPort();            
                return new URI(String.format("%s://%s:%s%s", getDefaultTargetProtocol(), serviceDnsName, targetPort, portMapping.getTargetPath()));
            } else {
                // When running external to SPCS: use ingress URL (HTTPS) for communication
                // Note: Public endpoints have protocol HTTP, but ingress URLs use HTTPS scheme
                // Need to get the ingress URL from public service endpoints that match the port
                List<ServiceEndpoint> endpoints = snowflakeServiceAPI.showServiceEndpoints(parts[0], parts[1], parts[2]);
                int targetPort = portMapping.getPort();
                
                // Find public endpoint matching the port (when running external, we need public access)
                // Public endpoints have protocol HTTP (not HTTPS), but ingress URLs use HTTPS
                ServiceEndpoint matchingEndpoint = null;
                for (ServiceEndpoint endpoint : endpoints) {
                    if (endpoint.getPort() != null && endpoint.getPort().equals(targetPort) &&
                        endpoint.getIsPublic() != null && endpoint.getIsPublic() &&
                        "HTTP".equalsIgnoreCase(endpoint.getProtocol())) {
                        matchingEndpoint = endpoint;
                        break;
                    }
                }
                
                if (matchingEndpoint == null) {
                    throw new ContainerFailedToStartException("No public HTTP endpoint found for port " + targetPort + " in service " + fullServiceName, null, container);
                }
                
                // Get ingress URL (should already be ready since we wait for endpoints during startup)
                String ingressUrl = matchingEndpoint.getIngressUrl();
                if (ingressUrl == null || ingressUrl.isEmpty()) {
                    throw new ContainerFailedToStartException("Ingress URL not available for port " + targetPort + " in service " + fullServiceName, null, container);
                }
                
                // Check if endpoint is still provisioning (should not happen, but validate anyway)
                String lowerUrl = ingressUrl.toLowerCase();
                if (lowerUrl.contains("provisioning") || lowerUrl.contains("progress")) {
                    throw new ContainerFailedToStartException("Endpoint for port " + targetPort + " in service " + fullServiceName + " is still provisioning: " + ingressUrl, null, container);
                }
                
                // Ingress URL format is typically: https://{endpoint}.snowflakecomputing.com
                // Ensure it starts with https://
                if (!ingressUrl.startsWith("https://") && !ingressUrl.startsWith("http://")) {
                    ingressUrl = "https://" + ingressUrl;
                }
                
                // Validate and create URI
                try {
                    // Append the target path if specified
                    URI uri = new URI(ingressUrl + (portMapping.getTargetPath() != null ? portMapping.getTargetPath() : ""));
                    return uri;
                } catch (java.net.URISyntaxException e) {
                    throw new ContainerFailedToStartException("Invalid ingress URL format for port " + targetPort + ": " + ingressUrl, e, container);
                }
            }
        } catch (ApiException e) {
            throw new ContainerFailedToStartException("Failed to fetch service or endpoints: " + e.getMessage(), e, container);
        }
    }

    /**
     * Gets the Authorization header value for use in HTTPS proxy forwarding via ingress.
     * When running external to SPCS and forwarding HTTPS requests via ingress,
     * this header value should be used for the Authorization header.
     * 
     * For PAT and key-pair tokens: returns "Snowflake Token=\"<token>\""
     * For SPCS session token: returns "Bearer <token>" (token is read from session file)
     * 
     * Reference: https://docs.snowflake.com/en/developer-guide/snowpark-container-services/tutorials/advanced/tutorial-8-access-public-endpoint-programmatically#option-2-send-requests-to-the-service-endpoint-programmatically-by-using-a-jwt
     * 
     * @param endpointUrl Optional endpoint URL for key-pair token exchange scope. 
     *                    If null, a basic scope will be used.
     * @return The Authorization header value (e.g., "Bearer <token>" or "Snowflake Token=\"<token>\""), or null if not available
     */
    public String getIngressAuthorization(String endpointUrl) {
        String token;
        if (authMethod == AuthMethod.SPCS_SESSION_TOKEN) {
            // For SPCS session token: use supplier to get token directly from session file
            token = jwtTokenSupplier != null ? jwtTokenSupplier.get() : null;
            if (token == null || token.isEmpty()) {
                return null;
            }
            // Format: Snowflake Token="<token>"
            return "Snowflake Token=\"" + token + "\"";
        } else if (authMethod == AuthMethod.PAT) {
            // For PAT: use supplier to get token directly
            token = jwtTokenSupplier != null ? jwtTokenSupplier.get() : null;
            if (token == null || token.isEmpty()) {
                return null;
            }
            // Format: Snowflake Token="<token>"
            return "Snowflake Token=\"" + token + "\"";
        } else if (authMethod == AuthMethod.KEYPAIR) {
            // For keypair: exchange JWT for Snowflake OAuth token
            if (jwtTokenSupplier == null) {
                return null;
            }
            String jwtToken = jwtTokenSupplier.get();
            try {
                token = exchangeJwtForSnowflakeToken(jwtToken, endpointUrl);
                if (token == null || token.isEmpty()) {
                    return null;
                }
                // Format: Snowflake Token="<token>"
                return "Snowflake Token=\"" + token + "\"";
            } catch (IOException e) {
                log.error("Failed to exchange JWT for Snowflake OAuth token for ingress", e);
                throw new RuntimeException("Failed to exchange JWT token for ingress authentication: " + e.getMessage(), e);
            }
        }
        throw new IllegalStateException("Unknown authentication method: " + authMethod);
    }

    /**
     * Gets the username used for authentication.
     * 
     * @return The username, or null if using SPCS session token
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the authentication method currently being used.
     * 
     * @return The authentication method
     */
    public AuthMethod getAuthMethod() {
        return authMethod;
    }

    /**
     * Checks if ShinyProxy is running inside SPCS.
     * 
     * @return true if running inside SPCS, false if running external
     */
    public boolean isRunningInsideSpcs() {
        return authMethod == AuthMethod.SPCS_SESSION_TOKEN;
    }


    /**
     * Generates a JWT token from the RSA private key for keypair authentication.
     * The JWT is signed with RS256 algorithm and includes standard Snowflake claims.
     * This method is called via supplier to allow automatic regeneration when tokens expire.
     * 
     * JWT Claims:
     * - iss: {ACCOUNT}.{USERNAME}.{KEY_SHA256}
     * - sub: {ACCOUNT}.{USERNAME}
     * - exp: current time + 30 seconds (short-lived token)
     * 
     * @return The JWT token string
     */
    private String generateJwtTokenForKeypair() {
        try {
            // Read RSA private key
            PrivateKey privateKey = loadPrivateKey(privateRsaKeyPath);
            
            // Use stored account identifier (convert hyphens to underscores for JWT claims)
            String account = accountIdentifier.replace("-", "_");
            
            // Calculate SHA256 of public key for issuer claim
            String keySha256 = calculatePublicKeySha256((RSAPrivateKey) privateKey);
            
            // Build issuer: {ACCOUNT}.{USERNAME}.{KEY_SHA256}
            String issuer = account.toUpperCase() + "." + username.toUpperCase() + "." + keySha256;
            
            // Build subject: {ACCOUNT}.{USERNAME}
            String subject = account.toUpperCase() + "." + username.toUpperCase();
            
            // Expiration: current time + 30 seconds
            long now = System.currentTimeMillis() / 1000; // Unix timestamp in seconds
            Date expiration = new Date((now + 30) * 1000);
            
            // Create JWT claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .expirationTime(expiration)
                .build();
            
            // Create JWS header with RS256 algorithm
            JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
            
            // Create signed JWT
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            
            // Sign the JWT
            JWSSigner signer = new RSASSASigner(privateKey);
            signedJWT.sign(signer);
            
            // Serialize to compact form
            String jwt = signedJWT.serialize();
            
            log.debug("Generated JWT token for keypair authentication (iss: {}, sub: {})", issuer, subject);
            return jwt;
            
        } catch (Exception e) {
            log.error("Error generating JWT token for keypair authentication", e);
            throw new RuntimeException("Failed to generate JWT token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Loads an RSA private key from a file path.
     * Supports both PKCS#8 (-----BEGIN PRIVATE KEY-----) and PKCS#1 (-----BEGIN RSA PRIVATE KEY-----) formats.
     * 
     * @param keyPath Path to the private key file
     * @return The PrivateKey object
     * @throws Exception If the key cannot be loaded or parsed
     */
    private PrivateKey loadPrivateKey(String keyPath) throws Exception {
        String keyContent = Files.readString(Paths.get(keyPath));
        
        // Remove header, footer, and whitespace
        keyContent = keyContent
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        
        try {
            // Try PKCS#8 format first (most common)
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            // If PKCS#8 fails, try PKCS#1 format
            // PKCS#1 keys need to be converted to PKCS#8 format
            // For simplicity, we'll throw an error suggesting conversion
            throw new IllegalArgumentException("Unable to parse RSA private key. Please ensure the key is in PKCS#8 format (-----BEGIN PRIVATE KEY-----). " +
                "If you have a PKCS#1 key (-----BEGIN RSA PRIVATE KEY-----), convert it using: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem", e);
        }
    }
    
    /**
     * Calculates the SHA256 hash of the RSA public key.
     * This is used in the issuer (iss) claim.
     * 
     * For RSA keys, the public key consists of modulus and public exponent.
     * The standard public exponent is 65537 (0x10001), which is used for most RSA keys.
     * 
     * @param privateKey The RSA private key
     * @return The SHA256 hash as a hexadecimal string (uppercase)
     * @throws Exception If the hash cannot be calculated
     */
    private String calculatePublicKeySha256(RSAPrivateKey privateKey) throws Exception {
        // Use standard RSA public exponent (65537 = 0x10001)
        // This is the most common value for RSA keys
        java.math.BigInteger publicExponent = new java.math.BigInteger("65537");
        
        // Create public key specification using modulus and public exponent
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        // Get the DER-encoded public key
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        // Calculate SHA256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(publicKeyBytes);
        
        // Convert to hexadecimal string (uppercase)
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }
    

    /**
     * Exchanges a JWT (key-pair) token for a Snowflake OAuth token.
     * This is required when forwarding HTTPS requests via ingress with key-pair authentication.
     * 
     * Implementation note: This requires JWT encoding with RS256 algorithm and OAuth token exchange.
     * Reference: https://medium.com/@vladimir.timofeenko/hands-on-with-spcs-container-networking-b347866279f9
     * 
     * @param jwtToken The JWT token to exchange
     * @param endpointUrl Optional SPCS endpoint URL for the scope. If null, uses account URL.
     * @return The Snowflake OAuth token
     * @throws IOException If token exchange fails
     */
    private String exchangeJwtForSnowflakeToken(String jwtToken, String endpointUrl) throws IOException {
        try {
            // Build OAuth token endpoint URL
            String oauthTokenUrl = accountUrl + "/oauth/token";
            
            // Build scope - format: session:role:{role} {endpointUrl} or just {endpointUrl}
            // For now, if endpointUrl is provided, use it; otherwise use account URL
            String scope = endpointUrl != null ? endpointUrl : accountUrl;
            
            // Build form-encoded request body
            StringBuilder formData = new StringBuilder();
            formData.append("grant_type=").append(URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8));
            formData.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
            formData.append("&assertion=").append(URLEncoder.encode(jwtToken, StandardCharsets.UTF_8));
            
            // Create HTTP request
            RequestBody requestBody = RequestBody.create(
                formData.toString(),
                MediaType.parse("application/x-www-form-urlencoded")
            );
            
            Request request = new Request.Builder()
                .url(oauthTokenUrl)
                .post(requestBody)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
            
            // Execute request using OkHttpClient
            OkHttpClient httpClient = new OkHttpClient();
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "No error body";
                    throw new IOException("OAuth token exchange failed with status " + response.code() + ": " + errorBody);
                }
                
                if (response.body() == null) {
                    throw new IOException("OAuth token exchange returned empty response");
                }
                
                // Parse JSON response to extract access_token
                String responseBody = response.body().string();
                // Format: {"access_token":"...","token_type":"Bearer","expires_in":3600}
                try {
                    com.google.gson.JsonObject jsonResponse = com.google.gson.JsonParser.parseString(responseBody).getAsJsonObject();
                    if (!jsonResponse.has("access_token")) {
                        throw new IOException("OAuth token exchange response does not contain access_token: " + responseBody);
                    }
                    String oauthToken = jsonResponse.get("access_token").getAsString();
                    log.debug("Successfully exchanged JWT for Snowflake OAuth token (scope: {})", scope);
                    return oauthToken;
                } catch (com.google.gson.JsonSyntaxException e) {
                    throw new IOException("OAuth token exchange response is not valid JSON: " + responseBody, e);
                }
            }
        } catch (Exception e) {
            if (e instanceof IOException) {
                throw e;
            }
            throw new IOException("Error exchanging JWT for Snowflake OAuth token: " + e.getMessage(), e);
        }
    }

    /**
     * Attempts to fetch service logs when a service fails to start.
     * This is a best-effort attempt - if it fails, returns null and the error handling will provide SQL instructions instead.
     * 
     * Reference: https://docs.snowflake.com/en/developer-guide/snowflake-rest-api/services/services-introduction
     * REST API endpoint: GET /api/v2/databases/{database}/schemas/{schema}/services/{service_name}/logs
     * 
     * @param database Database name
     * @param schema Schema name
     * @param serviceName Service name
     * @return A summary of recent logs (last few lines), or null if logs cannot be fetched
     */
    private String fetchServiceLogsForError(String database, String schema, String serviceName) {
        try {
            // First, try to get container info to get instance and container names
            List<ServiceContainer> containers = snowflakeServiceAPI.listServiceContainers(database, schema, serviceName);
            if (containers == null || containers.isEmpty()) {
                return null;
            }
            
            // Use the first container that has info
            ServiceContainer container = containers.get(0);
            String instanceIdStr = container.getInstanceId();
            String containerName = container.getContainerName();
            
            if (instanceIdStr == null || containerName == null) {
                return null;
            }
            
            // Convert instanceId from String to Integer (API expects Integer)
            Integer instanceId;
            try {
                instanceId = Integer.parseInt(instanceIdStr);
            } catch (NumberFormatException e) {
                log.debug("Invalid instanceId format: {}", instanceIdStr);
                return null;
            }
            
            // Use the generated API method to fetch logs
            eu.openanalytics.containerproxy.backend.spcs.client.model.FetchServiceLogs200Response response = 
                snowflakeServiceAPI.fetchServiceLogs(database, schema, serviceName, instanceId, containerName, 50);
            
            if (response == null || response.getSystem$getServiceLogs() == null) {
                return null;
            }
            
            String logContent = response.getSystem$getServiceLogs();
            if (logContent.isEmpty()) {
                return null;
            }
            
            // Extract last few lines (limit to avoid huge error messages)
            String[] lines = logContent.split("\n");
            int maxLines = 10;
            if (lines.length > maxLines) {
                StringBuilder summary = new StringBuilder();
                summary.append("(last ").append(maxLines).append(" lines of ").append(lines.length).append(" total)\n");
                for (int i = lines.length - maxLines; i < lines.length; i++) {
                    summary.append(lines[i]).append("\n");
                }
                return summary.toString().trim();
            }
            return logContent.trim();
        } catch (ApiException e) {
            log.debug("Could not fetch service logs via API: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            log.debug("Could not fetch service logs for error reporting: {}", e.getMessage());
            return null;
        }
    }

}
