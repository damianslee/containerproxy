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
 * Configuration for stage volumes in SPCS.
 * 
 * Reference: https://docs.snowflake.com/en/developer-guide/snowpark-container-services/specification-reference
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SpcsStageConfig {
    
    /**
     * The stage name.
     */
    private String name;
    
    /**
     * Metadata cache time period.
     */
    private String metadataCache;
    
    /**
     * Resource requests and limits for the stage volume.
     */
    private SpcsStageResources resources;
    
    /**
     * Resource configuration for stage volumes.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SpcsStageResources {
        private SpcsResourceRequests requests;
        private SpcsResourceLimits limits;
    }
    
    /**
     * Resource requests.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SpcsResourceRequests {
        private String memory;
        private String cpu;
    }
    
    /**
     * Resource limits.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SpcsResourceLimits {
        private String memory;
        private String cpu;
    }
}
