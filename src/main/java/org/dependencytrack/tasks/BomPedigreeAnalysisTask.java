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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.BomPedigreeAnalysisEvent;
import org.dependencytrack.parser.cyclonedx.CycloneDXPedigreeImporter;
import org.dependencytrack.persistence.QueryManager;

/**
 * Applies pedigree patch analysis after vulnerability analysis has completed.
 * <p>
 * This task handles the {@link BomPedigreeAnalysisEvent}, which is chained to
 * run after {@code ProjectVulnerabilityAnalysisEvent} so that all vulnerability
 * findings (including newly discovered ones) are available for pedigree annotation.
 *
 * @since 4.13.0
 */
public class BomPedigreeAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(BomPedigreeAnalysisTask.class);

    @Override
    public void inform(final Event e) {
        if (!(e instanceof final BomPedigreeAnalysisEvent event)) {
            return;
        }
        if (event.getResolvedVulnIdsByComponentUuid().isEmpty()) {
            return;
        }

        LOGGER.debug("Applying pedigree analysis for project %s".formatted(event.getProjectUuid()));
        try (final var qm = new QueryManager()) {
            new CycloneDXPedigreeImporter().applyPedigree(qm, event.getResolvedVulnIdsByComponentUuid());
        }
    }

}
