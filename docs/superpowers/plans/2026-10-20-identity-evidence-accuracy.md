# Identity Evidence Accuracy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `manifest-analysis` identity on every component with the technique and confidence that actually identified each component this tool identified, and nothing for anything else.

**Architecture:** A neutral `Identification` (technique + confidence) is added to the public `PackageComponent` model. `ArchiveAnalyzer` sets it at each discovery site; `BomRenderer` renders it verbatim when present and enabled, and renders nothing otherwise. External/embedded SBOM components are pass-through: the code that stamped identity onto them is deleted.

**Tech Stack:** Java 17, Maven, cyclonedx-core-java 13.2.0, JUnit 5, Mockito.

**Spec:** `docs/superpowers/specs/2026-10-20-identity-evidence-accuracy-design.md`

**Prior implementation:** branch `identity-evidence-accuracy` implemented an earlier revision of the spec. Several tests there are reusable; where a step says "port", read the named test with `git show identity-evidence-accuracy:<path>` and adapt it as the step says. Do not cherry-pick its commits.

## Global Constraints

- The model (`PackageComponent`, `Identification`, `Technique`, …) has zero `org.cyclonedx` imports. Mapping to CycloneDX happens only in `BomRenderer`.
- No `methods[].value` is ever emitted by this tool. No `concludedValue`.
- One element in `methods`; `identity.field = purl`; `identity.confidence` equals the method's confidence.
- Confidence values: hash match 1.0; `pom.properties`, owner unambiguous 1.0; unpacked artifact 0.8; filename-resolved owner 0.5; bundled dep (coordinates from its own `pom.properties`, whatever the owner) 1.0.
- Public API stays source- and binary-compatible: every existing `PackageComponent` constructor and `of(...)` factory keeps its signature and yields `identification() == null`.
- `matchesArchive` and the rest of the external-SBOM filter are not changed (filtering defects are the spec's Follow-up, out of scope).
- Golden: regenerate with `mvn -pl core test -Dtest=GoldenBomTest -Dgolden.regenerate=true` and review the diff; `GoldenBomTest` validates every JSON schema version ≥1.4.
- Full build check: `mvn -q verify` from the repo root.

## Review Focus

1. **The same artifact at several paths** — the renderer merges by purl and appends occurrences; if the first instance has no identification and a later one does, the identity must not be lost. Rule: the first non-null identification wins. Test in Task 3.
2. **Enrichment dropping the field** — `withLicenses`/`withNested` rebuild the record; if either forgets `identification`, license enrichment silently strips all identity. Test in Task 1.
3. **Unpacked-overlay reclassification** — `ArchiveAnalyzer` moves top-level `MavenEntry`s under an unpacked parent as `NestedMavenEntry`s; their identification must move with them. Test in Task 2.
4. **Embedded SBOM over our own identity** — in the analyzer flow, an embedded SBOM describing a component we hash-matched must not replace our identity ("absent wins" only fills gaps). Test in Task 4.
5. **Option off with upstream identity** — `identityEvidence=false` must not strip identity that came from an external/embedded SBOM or a producer. Test in Task 3 (producer) and Task 4 (external).

---

### Task 1: Identification vocabulary on the model

**Files:**
- Create: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/Technique.java`
- Create: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/Identification.java`
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/PackageComponent.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/IdentificationTest.java` (create)
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/ComponentModelTest.java`

**Interfaces:**
- Produces:
  - `public enum Technique { SOURCE_CODE_ANALYSIS, BINARY_ANALYSIS, MANIFEST_ANALYSIS, AST_FINGERPRINT, HASH_COMPARISON, INSTRUMENTATION, DYNAMIC_ANALYSIS, FILENAME, ATTESTATION, OTHER }` — constant names identical to `org.cyclonedx.model.component.evidence.Method.Technique`.
  - `public record Identification(Technique technique, double confidence)`; factories `hashMatch()` (HASH_COMPARISON, 1.0), `unpackedContentMatch()` (HASH_COMPARISON, 0.8), `pomProperties()` (MANIFEST_ANALYSIS, 1.0), `pomPropertiesFilenameOwner()` (MANIFEST_ANALYSIS, 0.5).
  - `PackageComponent` gains a 7th record component `Identification identification` (nullable, last). New factory `of(PackageRef, String archivePath, String hash, boolean dependenciesKnown, Identification)`.

- [ ] **Step 1: Write failing tests**

`IdentificationTest`:
- `factoriesCarrySpecValues` — asserts each factory's technique and confidence as listed above.
- `rejectsNullTechnique` — `assertThrows(NullPointerException.class, () -> new Identification(null, 1.0))`.
- `rejectsConfidenceOutsideUnitInterval` — `IllegalArgumentException` for `-0.01`, `1.01`, `Double.NaN`; accepts `0.0` and `1.0`.
- `producerMayUseAnyTechnique` — `new Identification(Technique.ATTESTATION, 0.9)` constructs.

`ComponentModelTest`:
- `legacyEntryPointsHaveNoIdentification` — the 5-arg and 6-arg constructors and both existing `of(...)` overloads yield `identification() == null`.
- `identificationSurvivesWithLicensesAndWithNested` — build with `Identification.hashMatch()`, call `withLicenses(List.of(LicenseInfo.spdx("MIT", null)))` then `withNested(List.of(PackageComponent.of(ArtifactCoords.of("g","n","1"), null, null)))`; assert `identification()` is still `Identification.hashMatch()`.

- [ ] **Step 2: Run, verify they fail to compile**

Run: `mvn -q -pl core test -Dtest='IdentificationTest,ComponentModelTest'`
Expected: compilation failure (`Identification` not found).

- [ ] **Step 3: Implement**

`Technique` and `Identification` as in Interfaces; `Identification`'s compact constructor rejects null technique (NPE) and NaN / out-of-range confidence (IAE). No `value` field. Javadoc on `Identification` states it is freely constructible by producers and that `null` on a component means "no identity evidence".

`PackageComponent`: add the component; keep the existing 6-arg constructor (delegating with `null`) and 5-arg constructor; existing `of(...)` overloads pass `null`; `withLicenses`/`withNested` carry `identification` through. Document the new component in the record Javadoc in the same style as `dependenciesKnown`.

- [ ] **Step 4: Run, verify pass**

Run: `mvn -q -pl core test -Dtest='IdentificationTest,ComponentModelTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/cyberstamp/maven/assembly/sbom/{Technique,Identification,PackageComponent}.java core/src/test/java/dev/cyberstamp/maven/assembly/sbom/{IdentificationTest,ComponentModelTest}.java
git commit -m "feat: add Identification to the component model"
```

---

### Task 2: Record identification at each analyzer discovery site

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/ArchiveAnalyzer.java`
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/ShadedJarDetection.java:97`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/ArchiveAnalyzerTest.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/ShadedJarDetectionTest.java`

**Interfaces:**
- Consumes: `Identification` factories, `PackageComponent.of(..., Identification)` and the 7-arg constructor (Task 1).
- Produces: `AssemblyComponentsBuilder.MavenEntry(ArtifactCoords, String, String, Identification)` and `NestedMavenEntry(ArtifactCoords, ArtifactCoords, String, String, boolean explicit, Identification)` (both package-private). `explicit` is unchanged and still governs only dependency edges.

Site → identification (line numbers at `03b5444`):

| Site | Identification |
|---|---|
| `classifyArchiveEntries` hash lookup (`:256`) | `hashMatch()` |
| `detectBundledDepsInArtifactFile` (`:615`) | `pomProperties()` |
| `tryMatchUnpackedArtifact` parent entry (`:531`) | `unpackedContentMatch()` |
| `identifyNestedArtifact` hash hit → `registerNestedArtifact` | `hashMatch()` |
| `detectBundledDependencies` → `registerBundled` (`:638`) | `pomProperties()` |
| `registerFromStandaloneProps` when called for a single descriptor (`:417`) | `pomProperties()` |
| `tryRegisterFromProps` when called for a single descriptor (`:762`) | `pomProperties()` |
| either of the above when called as `registerOwner` from `resolveAndRegisterShadedOwner` | `pomPropertiesFilenameOwner()` |
| `registerBundledDependencies` (bundled deps of a filename-resolved owner, `:488`) | `pomProperties()` |
| unpacked-overlay reclassification (`:349`) | the moved `MavenEntry`'s identification |
| `recordAllAsFileNested` / file-nested artifacts (`build()` step 3) | none (`null`) |
| `ShadedJarDetection` bundled deps (`:97`) | `pomProperties()` |

The single-vs-shaded distinction is made by the caller: give `registerFromStandaloneProps` and `tryRegisterFromProps` an `Identification` parameter; the single-descriptor callers pass `pomProperties()`, the lambdas passed as `registerOwner` pass `pomPropertiesFilenameOwner()`. Every bundled dep gets `pomProperties()` regardless of how its owner was identified, so `registerBundled` stamps it itself and takes no `Identification` parameter. `build()` passes `entry.identification()` into `PackageComponent.of(..., true, identification)` and the 7-arg constructor in `buildNestedComponentsRecursively`.

- [ ] **Step 1: Write failing tests**

Port from `identity-evidence-accuracy:core/src/test/java/dev/cyberstamp/maven/assembly/sbom/ArchiveAnalyzerTest.java`, deleting every assertion on `value()`:
- `hashMatchedEntryRecordsHashComparison` — HASH_COMPARISON, 1.0.
- `pomPropertiesIdentifiedJarRecordsManifestAnalysis` (renamed from `…WithDescriptorPath`) — MANIFEST_ANALYSIS, 1.0.
- `filenameResolvedShadedOwnerRecordsReducedConfidence` — MANIFEST_ANALYSIS, 0.5.
- `bundledDepOfFilenameResolvedOwnerHasFullConfidence` (adapted from `bundledSiblingOfFilenameResolvedOwnerInheritsReducedConfidence`) — owner MANIFEST_ANALYSIS 0.5, bundled dep MANIFEST_ANALYSIS **1.0**.
- `bundledDepOfHashMatchedOwnerKeepsFullConfidence` — MANIFEST_ANALYSIS, 1.0.
- `unpackedArtifactReducesConfidence` (renamed from `unpackedArtifactOmitsValueAndReducesConfidence`) — HASH_COMPARISON, 0.8.
- `unresolvedShadedJarContentsGetNoIdentity` — file-nested packages have `identification() == null`.
- Do not port `bundledSiblingsEachCiteTheirOwnDescriptor` (it tests `value`).

New:
- `reclassifiedUnpackedChildKeepsItsIdentification` — extend the fixture of the existing `reclassifiedUnpackedChildDoesNotCreateDependencyEdge`; assert the reclassified child `PackageComponent` has `Identification.hashMatch()`.

`ShadedJarDetectionTest`:
- `bundledDepsGetManifestAnalysis` — each nested bundled component has `Identification.pomProperties()`.

- [ ] **Step 2: Run, verify fail**

Run: `mvn -q -pl core test -Dtest='ArchiveAnalyzerTest,ShadedJarDetectionTest'`
Expected: the new/ported tests FAIL (`identification()` is null); existing tests pass.

- [ ] **Step 3: Implement the table above in `ArchiveAnalyzer` and `ShadedJarDetection`**

- [ ] **Step 4: Run, verify pass**

Run: `mvn -q -pl core test`
Expected: PASS. (Rendered output is unchanged in this task — the renderer still ignores `identification`.)

- [ ] **Step 5: Commit**

```bash
git add core/src
git commit -m "feat: record the identification technique at each analyzer discovery site"
```

---

### Task 3: Render identification; renderer and pipeline option

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/BomRenderer.java` (`createPackageComponent` `:172`, `buildMavenEvidence` `:217`, occurrence merge)
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/SbomPipeline.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/BomRendererTest.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/SbomPipelineTest.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/GoldenBomTest.java`, `core/src/test/resources/golden/assembly-golden.cdx.json`

**Interfaces:**
- Consumes: `PackageComponent.identification()` (Task 1).
- Produces: `public BomRenderer()` (identity on) and `public BomRenderer(boolean identityEvidence)`; `public SbomPipeline identityEvidence(boolean enabled)` (default `true`), passed to `new BomRenderer(identityEvidence)` in `render()`.

Rendering rule: if `identityEvidence && pkg.identification() != null`, set `evidence.identities` to one `Identity` (`field = PURL`, `confidence = c`) with one `Method` (`technique = Method.Technique.valueOf(identification.technique().name())`, `confidence = c`, no value). Otherwise no identities. No check on the ref type. Do not emit an empty `"evidence": {}`. When a later `PackageComponent` with the same purl is merged into an already-rendered component, it appends its occurrence as today and, if the rendered component has no identity and the later one has an identification, adopts it (first non-null wins).

- [ ] **Step 1: Write failing tests**

`BomRendererTest`:
- Update `testSingleMavenComponent` (`:79-83`): build the component with `Identification.hashMatch()`; assert technique `HASH_COMPARISON`, confidence 1.0 on identity and method, `methods.get(0).getValue()` null.
- `componentWithoutIdentificationHasNoIdentity` — `PackageComponent.of(coords, "lib/a.jar", "h")`; evidence has the occurrence and no identities.
- `genericComponentRendersProducerIdentification` — `GenericPackageRef` component with `new Identification(Technique.ATTESTATION, 0.9)`; identity rendered with `ATTESTATION`, 0.9.
- `everyTechniqueMapsToCycloneDx` — for each `Technique.values()`, rendering succeeds and the method technique's `name()` equals it.
- `identityEvidenceOffSuppressesIdentityKeepsOccurrence` — `new BomRenderer(false)` on a component with `hashMatch()`: occurrence present, no identities.
- `laterInstanceSuppliesIdentityWhenFirstHasNone` — same coords at `a/x.jar` (no identification) then `b/x.jar` (`hashMatch()`): one component, two occurrences, identity HASH_COMPARISON.
- `firstIdentificationWinsOverLater` — same coords, first `pomPropertiesFilenameOwner()`, then `hashMatch()`: identity confidence 0.5.

`SbomPipelineTest`:
- `identityEvidenceFalseReachesRenderer` — model with one `hashMatch()` component, `SbomPipeline.forModel(m).identityEvidence(false).render()` has no identities.
- `identityEvidenceSurvivesLicenseEnrichment` — pipeline with a `licenseSource` returning one license; rendered component still has the identity.

`GoldenBomTest.buildFixedModel`: give `alpha` (first instance) `Identification.hashMatch()`, the `bundled` component `Identification.pomProperties()`, `beta` nothing (keeps the no-identity case in the golden). Use the 7-arg constructor.

- [ ] **Step 2: Run, verify fail**

Run: `mvn -q -pl core test -Dtest='BomRendererTest,SbomPipelineTest,GoldenBomTest'`
Expected: new tests fail/compile-fail; golden byte comparison fails.

- [ ] **Step 3: Implement the rendering rule, constructors and pipeline option**

`BomRenderer` maps to CycloneDX itself (private helper); it no longer calls `SbomUtils.mavenManifestIdentity()`.

- [ ] **Step 4: Regenerate golden and review**

Run: `mvn -q -pl core test -Dtest=GoldenBomTest -Dgolden.regenerate=true && git diff core/src/test/resources/golden/`
Expected diff: alpha's identity becomes `hash-comparison` 1.0 with no `value`; the bundled component's becomes `manifest-analysis` 1.0 with no `value`; beta's identity is gone; `serialNumber` changes. Nothing else.

- [ ] **Step 5: Run, verify pass**

Run: `mvn -q -pl core test`
Expected: PASS, including `renderedBomIsSchemaValid` for 1.4–1.7 (1.4 output carries no `evidence.identity`).

- [ ] **Step 6: Commit**

```bash
git add core/src
git commit -m "feat: render identification only where a component carries one"
```

---

### Task 4: External and embedded SBOM components are pass-through

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/SbomGenerator.java` (delete `ensureMavenManifestIdentity` `:291-320` and its call `:189`)
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/SbomUtils.java` (delete `mavenManifestIdentity()` `:236-260` and constants used only by it, e.g. `MAVEN_POM_ANALYSIS`, `FULL_CONFIDENCE`)
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/ExternalSbomMergeEvidenceTest.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/BomMergerTest.java`
- Test: `core/src/test/java/dev/cyberstamp/maven/assembly/sbom/SbomUtilsTest.java` (remove tests of the deleted helper, if any)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new; `filterSbomByArchive(Bom, ArchiveIndex, String)` keeps its signature.

- [ ] **Step 1: Write failing tests**

`ExternalSbomMergeEvidenceTest`:
- Replace `matchedExternalComponentGainsManifestIdentityAndKeepsDescription` with `matchedExternalComponentWithoutIdentityGainsNoneAndKeepsDescription` — same fixture; assert description kept and identities null or empty.
- `externalComponentIdentityPassesThroughUnchanged` — upstream component carrying identity `filename` 0.3 with method value `"x.jar"`; after `filterSbomByArchive`, the identity list is the same object content: technique `FILENAME`, confidence 0.3, value `"x.jar"`.
- `unverifiedExternalComponentGainsNoIdentity` — component with no occurrences and no hash (admitted at `matchesArchive :263`); no identities.
- Keep `npmComponentDoesNotGainMavenIdentity`.

`BomMergerTest`:
- `mergeFillsAbsentIdentityFromSource` — target nested component with occurrence evidence and no identities; source component (same purl) with identity `hash-comparison` 1.0; after `mergeUnder`, target has that identity.
- `mergeKeepsTargetIdentityOverSource` — target identity `hash-comparison` 1.0, source identity `manifest-analysis` 0.4; after `mergeUnder`, target identity is still `hash-comparison` 1.0.

- [ ] **Step 2: Run, verify fail**

Run: `mvn -q -pl core test -Dtest='ExternalSbomMergeEvidenceTest,BomMergerTest'`
Expected: `matchedExternalComponentWithoutIdentityGainsNone…` and `unverifiedExternalComponentGainsNoIdentity` FAIL (manifest-analysis stamped); `BomMergerTest` cases pass already (they pin existing behaviour).

- [ ] **Step 3: Delete `ensureMavenManifestIdentity`, its call, and `SbomUtils.mavenManifestIdentity()`**

- [ ] **Step 4: Run, verify pass**

Run: `mvn -q -pl core test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src
git commit -m "fix: leave identity evidence on external SBOM components as upstream wrote it"
```

---

### Task 5: `identityEvidence` option on the plugin and handler; docs

**Files:**
- Modify: `core/src/main/java/dev/cyberstamp/maven/assembly/sbom/SbomGenerator.java` (setter, pass to pipeline `:142`)
- Modify: `maven-plugin/src/main/java/dev/cyberstamp/maven/assembly/sbom/GenerateSbomMojo.java`
- Modify: `handler/src/main/java/dev/cyberstamp/maven/assembly/sbom/SbomContainerDescriptorHandler.java`
- Modify: `README.md` (Evidence section `:464-466`, external SBOM bullet `:387`, new Release Notes section)
- Test: `maven-plugin/src/test/java/dev/cyberstamp/maven/assembly/sbom/GenerateSbomMojoTest.java`
- Test: `handler/src/test/java/dev/cyberstamp/maven/assembly/sbom/SbomContainerDescriptorHandlerTest.java`

**Interfaces:**
- Consumes: `SbomPipeline.identityEvidence(boolean)` (Task 3).
- Produces: `void SbomGenerator.setIdentityEvidence(boolean)` (default `true`; follows `setProduct`, constructor unchanged); `@Parameter(defaultValue = "true") private boolean identityEvidence` on `GenerateSbomMojo`; `public void setIdentityEvidence(boolean)` on `SbomContainerDescriptorHandler` (field default `true`, placed next to `setFailOnDuplicateHash`).

- [ ] **Step 1: Write failing tests**

Port from `identity-evidence-accuracy` (`ff5a6ac`, `cafd845`):
- `GenerateSbomMojoTest`: `identityEvidenceDefaultsToTrueInThePluginDescriptor`, `identityEvidenceEnabledEmitsIdentity`, and the disabled counterpart (identity absent, occurrence present). Additionally assert in the enabled test that the technique is `HASH_COMPARISON`.
- `SbomContainerDescriptorHandlerTest`: `identityEvidenceOnByDefaultEmitsIdentity`, `setIdentityEvidenceFalseSuppressesIdentityButKeepsOccurrences`, with helper `buildBomFor`.
- New in `SbomContainerDescriptorHandlerTest`: `setIdentityEvidenceFalseKeepsExternalSbomIdentity` — an external SBOM whose component carries identity `manifest-analysis` 0.7 and matches an archive path; with the option off, the merged component keeps exactly that identity.

- [ ] **Step 2: Run, verify fail**

Run: `mvn -q install -DskipTests -pl core && mvn -q -pl maven-plugin,handler test -Dtest='GenerateSbomMojoTest,SbomContainerDescriptorHandlerTest'`
Expected: compilation failure (`setIdentityEvidence` not found).

- [ ] **Step 3: Implement the setter, parameter and wiring**

Mojo/handler call `generator.setIdentityEvidence(identityEvidence)` right after `generator.setProduct(product)`. Parameter Javadoc: when `false`, this tool emits no identity evidence of its own; identity from external or embedded SBOMs is preserved; occurrences are unaffected.

- [ ] **Step 4: Update README**

- Evidence section: occurrences as today; identity only on components this tool identified, one method, no `value`, table of the five situations with technique and confidence from Global Constraints; components from external/embedded SBOMs carry exactly upstream's identity or none; components built through the model API carry identity only if the producer supplies an `Identification`; `identityEvidence` option.
- `:387`: replace "also gains a `manifest-analysis` identity" with "keeps exactly the identity evidence its SBOM carried, if any".
- New `## Release Notes` → `### Current Development` before `## Requirements`, listing: (1) components report the technique and confidence that actually identified them, without `value`; (2) components from external/embedded SBOMs no longer gain an invented `manifest-analysis` identity — upstream identity is never removed; (3) model-API producers (e.g. wildfly-galleon-plugins) get no identity evidence unless they supply an `Identification`; (4) new `identityEvidence` option.

- [ ] **Step 5: Full build**

Run: `mvn -q verify`
Expected: BUILD SUCCESS.

- [ ] **Step 6: Commit**

```bash
git add core maven-plugin handler README.md
git commit -m "feat: add identityEvidence option and document identity evidence"
```
