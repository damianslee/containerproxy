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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a Snowflake secret configuration for SPCS containers.
 * 
 * Secrets can be mounted as files (directoryPath) or as environment variables (envVarName).
 * When using envVarName, secretKeyRef specifies which key from the secret to use.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SpcsSecret {
    
    /**
     * The secret object name (specify this or objectReference, not both).
     */
    private String objectName;
    
    /**
     * The secret object reference (specify this or objectName, not both).
     */
    private String objectReference;
    
    /**
     * Directory path where the secret should be mounted as a file (specify this or envVarName, not both).
     */
    private String directoryPath;
    
    /**
     * Environment variable name for the secret value (specify this or directoryPath, not both).
     */
    private String envVarName;
    
    /**
     * Secret key reference - required when using envVarName.
     * Valid values: "username", "password", "secret_string"
     */
    private String secretKeyRef;
}
