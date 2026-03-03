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
package org.dependencytrack.parser.cyclonedx;

import alpine.common.logging.Logger;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Issue;
import org.cyclonedx.model.Patch;
import org.cyclonedx.model.Pedigree;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.AnalysisCommentUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Processes CycloneDX pedigree information embedded in BOM components.
 * <p>
 * When a component declares in its pedigree that specific vulnerabilities are resolved
 * by patches, this importer applies a {@link AnalysisState#RESOLVED} analysis state
 * to those vulnerability findings.
 *
 * @since 4.13.0
 */
public class CycloneDXPedigreeImporter {

    private static final Logger LOGGER = Logger.getLogger(CycloneDXPedigreeImporter.class);

    static final String COMMENTER = "CycloneDX BOM";

    /**
     * Applies pedigree patch information from a CycloneDX BOM to existing vulnerability findings.
     * <p>
     * For each component in the BOM that has pedigree patches resolving security issues,
     * this method looks up the corresponding vulnerability findings in the project and marks
     * them as {@link AnalysisState#RESOLVED}.
     * <p>
     * Note: Analysis states are only applied to <em>existing</em> vulnerability findings.
     * If a component has no findings yet (e.g. on first BOM upload before vulnerability
     * analysis has run), the pedigree information will be applied on the next BOM upload
     * after vulnerability analysis has completed.
     *
     * @param qm      The {@link QueryManager} to use for database operations
     * @param cdxBom  The parsed CycloneDX BOM containing pedigree information
     * @param project The project the BOM belongs to
     */
    public void applyPedigree(final QueryManager qm, final Bom cdxBom, final Project project) {
        final List<org.cyclonedx.model.Component> cdxComponents = collectAllComponents(cdxBom);
        if (cdxComponents.isEmpty()) {
            return;
        }

        for (final org.cyclonedx.model.Component cdxComponent : cdxComponents) {
            final Pedigree pedigree = cdxComponent.getPedigree();
            if (pedigree == null || pedigree.getPatches() == null || pedigree.getPatches().isEmpty()) {
                continue;
            }

            final Set<String> resolvedVulnIds = pedigree.getPatches().stream()
                    .filter(patch -> patch.getResolves() != null)
                    .flatMap(patch -> patch.getResolves().stream())
                    .filter(issue -> issue.getType() == Issue.Type.SECURITY)
                    .filter(issue -> !isBlank(issue.getId()))
                    .map(Issue::getId)
                    .collect(Collectors.toSet());

            if (resolvedVulnIds.isEmpty()) {
                continue;
            }

            LOGGER.debug("Component %s/%s declares %d vulnerability ID(s) as resolved via pedigree patches"
                    .formatted(cdxComponent.getGroup(), cdxComponent.getName(), resolvedVulnIds.size()));

            final ComponentIdentity cid = new ComponentIdentity(cdxComponent);
            final List<Component> components = qm.matchIdentity(project, cid);
            if (components.isEmpty()) {
                LOGGER.debug("""
                        Pedigree declares %d resolved vulnerability ID(s) for component %s, \
                        but no matching component was found in the project; Skipping\
                        """.formatted(resolvedVulnIds.size(), cid));
                continue;
            }

            for (final Component component : components) {
                final List<Vulnerability> componentVulns = qm.getAllVulnerabilities(component);
                for (final Vulnerability vuln : componentVulns) {
                    if (resolvedVulnIds.contains(vuln.getVulnId())) {
                        applyResolvedAnalysis(qm, component, vuln);
                    }
                }
            }
        }
    }

    /**
     * Applies pedigree patch analysis using a pre-extracted map of component UUIDs to
     * resolved vulnerability IDs. Used when the original CycloneDX BOM is no longer
     * available, e.g. in a chained event handler after vulnerability analysis.
     *
     * @param qm                          The {@link QueryManager} to use
     * @param resolvedVulnIdsByComponentUuid Map from component UUID to set of resolved vulnerability IDs
     */
    public void applyPedigree(final QueryManager qm, final Map<UUID, Set<String>> resolvedVulnIdsByComponentUuid) {
        for (final Map.Entry<UUID, Set<String>> entry : resolvedVulnIdsByComponentUuid.entrySet()) {
            final Component component = qm.getObjectByUuid(Component.class, entry.getKey());
            if (component == null) {
                LOGGER.debug("Component with UUID %s no longer exists; Skipping".formatted(entry.getKey()));
                continue;
            }
            final List<Vulnerability> componentVulns = qm.getAllVulnerabilities(component);
            for (final Vulnerability vuln : componentVulns) {
                if (entry.getValue().contains(vuln.getVulnId())) {
                    applyResolvedAnalysis(qm, component, vuln);
                }
            }
        }
    }

    /**
     * Extracts a mapping of BOM ref to resolved vulnerability IDs from a CycloneDX BOM.
     * Only patches resolving issues of type {@link Issue.Type#SECURITY} are considered.
     *
     * @param cdxBom The CycloneDX BOM to extract from
     * @return Map from BOM ref to set of resolved vulnerability IDs; empty if no pedigree data exists
     */
    public static Map<String, Set<String>> extractResolvedVulnIdsByBomRef(final Bom cdxBom) {
        final var result = new java.util.HashMap<String, Set<String>>();
        for (final org.cyclonedx.model.Component cdxComponent : collectAllComponents(cdxBom)) {
            final Pedigree pedigree = cdxComponent.getPedigree();
            if (pedigree == null || pedigree.getPatches() == null || pedigree.getPatches().isEmpty()) {
                continue;
            }
            final Set<String> resolvedIds = pedigree.getPatches().stream()
                    .filter(patch -> patch.getResolves() != null)
                    .flatMap(patch -> patch.getResolves().stream())
                    .filter(issue -> issue.getType() == Issue.Type.SECURITY)
                    .filter(issue -> !isBlank(issue.getId()))
                    .map(Issue::getId)
                    .collect(Collectors.toSet());
            if (!resolvedIds.isEmpty() && cdxComponent.getBomRef() != null) {
                result.put(cdxComponent.getBomRef(), resolvedIds);
            }
        }
        return result;
    }

    private static List<org.cyclonedx.model.Component> collectAllComponents(final Bom cdxBom) {
        final var components = new ArrayList<org.cyclonedx.model.Component>();
        if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getComponent() != null) {
            collectComponentsRecursively(cdxBom.getMetadata().getComponent(), components);
        }
        if (cdxBom.getComponents() != null) {
            for (final org.cyclonedx.model.Component cdxComponent : cdxBom.getComponents()) {
                collectComponentsRecursively(cdxComponent, components);
            }
        }
        return components;
    }

    private static void collectComponentsRecursively(
            final org.cyclonedx.model.Component cdxComponent,
            final List<org.cyclonedx.model.Component> result) {
        result.add(cdxComponent);
        if (cdxComponent.getComponents() != null) {
            for (final org.cyclonedx.model.Component child : cdxComponent.getComponents()) {
                collectComponentsRecursively(child, result);
            }
        }
    }

    private static void applyResolvedAnalysis(final QueryManager qm, final Component component, final Vulnerability vuln) {
        final Vulnerability refreshedVuln = qm.getObjectByUuid(Vulnerability.class, vuln.getUuid());
        Analysis analysis = qm.getAnalysis(component, refreshedVuln);
        if (analysis == null) {
            analysis = qm.makeAnalysis(component, refreshedVuln, AnalysisState.NOT_SET, null, null, null, null);
        }
        AnalysisCommentUtil.makeStateComment(qm, analysis, AnalysisState.RESOLVED, COMMENTER);
        AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, true, COMMENTER);
        qm.makeAnalysis(component, refreshedVuln, AnalysisState.RESOLVED, null, null, null, true);
        LOGGER.debug("Applied RESOLVED analysis state to component %s for vulnerability %s via pedigree patch"
                .formatted(component.getName(), vuln.getVulnId()));
    }

}
