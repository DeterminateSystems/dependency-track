/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Defines an event to apply pedigree patch analysis to vulnerability findings
 * after vulnerability analysis has completed.
 *
 * @since 4.13.0
 */
public class BomPedigreeAnalysisEvent extends AbstractChainableEvent {

    private final UUID projectUuid;
    private final Map<UUID, Set<String>> resolvedVulnIdsByComponentUuid;

    public BomPedigreeAnalysisEvent(
            final UUID projectUuid,
            final Map<UUID, Set<String>> resolvedVulnIdsByComponentUuid) {
        this.projectUuid = projectUuid;
        this.resolvedVulnIdsByComponentUuid = resolvedVulnIdsByComponentUuid;
    }

    public UUID getProjectUuid() {
        return projectUuid;
    }

    public Map<UUID, Set<String>> getResolvedVulnIdsByComponentUuid() {
        return resolvedVulnIdsByComponentUuid;
    }

}
