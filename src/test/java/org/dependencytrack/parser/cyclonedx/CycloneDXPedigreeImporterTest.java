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

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Issue;
import org.cyclonedx.model.Patch;
import org.cyclonedx.model.Pedigree;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CycloneDXPedigreeImporterTest extends PersistenceCapableTest {

    private final CycloneDXPedigreeImporter pedigreeImporter = new CycloneDXPedigreeImporter();

    @Test
    void shouldApplyResolvedStateForPatchedVulnerability() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
        assertThat(analyses.getFirst().isSuppressed()).isTrue();
        assertThat(analyses.getFirst().getAnalysisComments()).satisfiesExactlyInAnyOrder(
                comment -> {
                    assertThat(comment.getCommenter()).isEqualTo(CycloneDXPedigreeImporter.COMMENTER);
                    assertThat(comment.getComment()).isEqualTo("Analysis: NOT_SET → RESOLVED");
                },
                comment -> {
                    assertThat(comment.getCommenter()).isEqualTo(CycloneDXPedigreeImporter.COMMENTER);
                    assertThat(comment.getComment()).isEqualTo("Suppressed");
                }
        );
    }

    @Test
    void shouldNotApplyStateForNonSecurityIssueType() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        // Pedigree resolves an ENHANCEMENT issue, not a SECURITY issue
        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.ENHANCEMENT));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).isEmpty();
    }

    @Test
    void shouldNotApplyStateWhenVulnerabilityNotFoundForComponent() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.createComponent(component, false);

        // Component has pedigree but no matching vuln findings
        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).isEmpty();
    }

    @Test
    void shouldNotApplyStateWhenNoPedigreePresent() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        // No pedigree set

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).isEmpty();
    }

    @Test
    void shouldApplyResolvedStateForMultipleVulnerabilities() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("CVE-2021-44228");
        vuln1.setSource(Vulnerability.Source.NVD);
        vuln1.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln1 = qm.createVulnerability(vuln1, false);
        qm.addVulnerability(persistedVuln1, persistedComponent, AnalyzerIdentity.NONE);

        final var vuln2 = new Vulnerability();
        vuln2.setVulnId("CVE-2021-45046");
        vuln2.setSource(Vulnerability.Source.NVD);
        vuln2.setSeverity(Severity.HIGH);
        final Vulnerability persistedVuln2 = qm.createVulnerability(vuln2, false);
        qm.addVulnerability(persistedVuln2, persistedComponent, AnalyzerIdentity.NONE);

        final var pedigree = new Pedigree();
        final var patch = new Patch();
        final var issue1 = new Issue();
        issue1.setId("CVE-2021-44228");
        issue1.setType(Issue.Type.SECURITY);
        final var issue2 = new Issue();
        issue2.setId("CVE-2021-45046");
        issue2.setType(Issue.Type.SECURITY);
        patch.setResolves(List.of(issue1, issue2));
        pedigree.setPatches(List.of(patch));

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(pedigree);

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(2);
        assertThat(analyses).allSatisfy(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
            assertThat(analysis.isSuppressed()).isTrue();
        });
    }

    @Test
    void shouldNotApplyStateWhenComponentNotFoundInProject() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // BOM references a different component (not in the project)
        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("other-lib");
        cdxComponent.setVersion("2.0.0");
        cdxComponent.setPurl("pkg:maven/com.other/other-lib@2.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).isEmpty();
    }

    @Test
    void shouldNotDuplicateCommentsOnRepeatedImport() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        // Apply pedigree twice (simulating two BOM re-uploads)
        pedigreeImporter.applyPedigree(qm, cdxBom, project);
        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
        // On second import the state is already RESOLVED, so no new state comment should be added.
        // But the suppression comment also won't be added again (state unchanged).
        // Only the initial two comments should exist.
        assertThat(analyses.getFirst().getAnalysisComments()).hasSize(2);
    }

    // === Map-based applyPedigree overload ===

    @Test
    void shouldApplyResolvedStateViaUuidMap() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        pedigreeImporter.applyPedigree(qm, Map.of(persistedComponent.getUuid(), Set.of("CVE-2021-44228")));

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
        assertThat(analyses.getFirst().isSuppressed()).isTrue();
    }

    @Test
    void shouldSkipComponentNotFoundInUuidMap() {
        // Should not throw even if the component UUID no longer exists
        pedigreeImporter.applyPedigree(qm, Map.of(UUID.randomUUID(), Set.of("CVE-2021-44228")));
    }

    // === extractResolvedVulnIdsByBomRef ===

    @Test
    void shouldExtractResolvedVulnIdsByBomRef() {
        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setBomRef("acme-lib-ref");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        final Map<String, Set<String>> result = CycloneDXPedigreeImporter.extractResolvedVulnIdsByBomRef(cdxBom);

        assertThat(result).containsOnlyKeys("acme-lib-ref");
        assertThat(result.get("acme-lib-ref")).containsExactly("CVE-2021-44228");
    }

    @Test
    void shouldExcludeComponentWithoutBomRefFromExtraction() {
        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        // No bomRef set
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        final Map<String, Set<String>> result = CycloneDXPedigreeImporter.extractResolvedVulnIdsByBomRef(cdxBom);

        assertThat(result).isEmpty();
    }

    // === Nested component ===

    @Test
    void shouldApplyResolvedStateForNestedComponent() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("nested-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/nested-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var cdxChild = new org.cyclonedx.model.Component();
        cdxChild.setName("nested-lib");
        cdxChild.setVersion("1.0.0");
        cdxChild.setPurl("pkg:maven/com.acme/nested-lib@1.0.0");
        cdxChild.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxParent = new org.cyclonedx.model.Component();
        cdxParent.setName("parent-lib");
        cdxParent.setVersion("2.0.0");
        cdxParent.setComponents(List.of(cdxChild));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxParent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
    }

    // === Metadata/root component ===

    @Test
    void shouldApplyResolvedStateForMetadataComponent() {
        final Project project = qm.createProject("Acme App", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-app");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-app@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var metadataComponent = new org.cyclonedx.model.Component();
        metadataComponent.setName("acme-app");
        metadataComponent.setVersion("1.0.0");
        metadataComponent.setPurl("pkg:maven/com.acme/acme-app@1.0.0");
        metadataComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var metadata = new org.cyclonedx.model.Metadata();
        metadata.setComponent(metadataComponent);

        final var cdxBom = new Bom();
        cdxBom.setMetadata(metadata);
        // No cdxBom.components — pedigree is only on the metadata component

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
    }

    // === Edge cases ===

    @Test
    void shouldNotApplyStateWhenIssueIdIsBlank() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        final var issue = new Issue();
        issue.setType(Issue.Type.SECURITY);
        issue.setId("  "); // blank ID

        final var patch = new Patch();
        patch.setResolves(List.of(issue));

        final var pedigree = new Pedigree();
        pedigree.setPatches(List.of(patch));

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(pedigree);

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).isEmpty();
    }

    @Test
    void shouldOverwriteExistingAnalysisStateWithResolved() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        final Component persistedComponent = qm.createComponent(component, false);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2021-44228");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        final Vulnerability persistedVuln = qm.createVulnerability(vuln, false);
        qm.addVulnerability(persistedVuln, persistedComponent, AnalyzerIdentity.NONE);

        // Pre-existing user-set analysis in a different state
        qm.makeAnalysis(persistedComponent, persistedVuln, AnalysisState.IN_TRIAGE, null, null, null, false);

        final var cdxComponent = new org.cyclonedx.model.Component();
        cdxComponent.setName("acme-lib");
        cdxComponent.setVersion("1.0.0");
        cdxComponent.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        cdxComponent.setPedigree(buildPedigree("CVE-2021-44228", Issue.Type.SECURITY));

        final var cdxBom = new Bom();
        cdxBom.setComponents(List.of(cdxComponent));

        pedigreeImporter.applyPedigree(qm, cdxBom, project);

        final Query<Analysis> analysisQuery = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        analysisQuery.setParameters(project);
        final List<Analysis> analyses = analysisQuery.executeList();

        assertThat(analyses).hasSize(1);
        assertThat(analyses.getFirst().getAnalysisState()).isEqualTo(AnalysisState.RESOLVED);
        assertThat(analyses.getFirst().isSuppressed()).isTrue();
    }

    private static Pedigree buildPedigree(final String vulnId, final Issue.Type issueType) {
        final var issue = new Issue();
        issue.setId(vulnId);
        issue.setType(issueType);

        final var patch = new Patch();
        patch.setResolves(List.of(issue));

        final var pedigree = new Pedigree();
        pedigree.setPatches(List.of(patch));

        return pedigree;
    }

}
