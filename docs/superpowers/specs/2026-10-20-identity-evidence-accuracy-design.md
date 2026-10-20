# Identity evidence accuracy

**Date:** 2026-10-20
**Status:** revised after a first implementation on branch
`identity-evidence-accuracy`. The revision simplifies the design (external
SBOM components are pass-through, `methods[].value` is dropped, the filtering
fix is split out as follow-up); the code does not yet reflect it.

## Intent

Every Maven component this plugin emits currently carries the same hardcoded
identity evidence:

```json
"evidence": {
  "identity": [{
    "field": "purl",
    "confidence": 1.0,
    "methods": [{"technique": "manifest-analysis", "value": "maven-pom-analysis"}]
  }]
}
```

This assertion is fabricated. It is stamped on every component regardless of
how — or whether — that component was actually identified. The goal of this
work is to make the identity evidence describe what the tool genuinely did.

There is no specific downstream consumer driving this. The reason to do it is
fidelity to the CycloneDX spec: if we record the technique at all, it should be
true. An SBOM that confidently asserts a provenance it does not have is worse
than one that asserts nothing, because a consumer cannot tell the difference
between a finding and a guess.

### Why now

A related schema-validity bug was found and fixed on 2026-10-20 (`confidence` is
required on each `methods[]` entry and was missing, making every emitted
document fail CycloneDX schema validation). That fix is commit `03b5444`.
Investigating it surfaced the accuracy problems described here.

## Goals

1. Record the technique that actually identified each component this tool
   identified, with a confidence that reflects how it was identified.
2. Emit no identity evidence for anything this tool did not identify.
3. Stop misusing `methods[].value`.
4. Let users turn this tool's identity evidence off.

## Non-goals

- Serving any particular downstream tool or workflow. No consumer has been
  identified; do not shape the output around a hypothetical one.
- Recording *multiple* techniques per component (see Decisions).
- Changing which components appear in the BOM. This work changes evidence
  only. A known filtering defect is recorded under Follow-up.
- Populating `methods[].value` or `concludedValue`.

## Anti-goals

Things that would make this a failure even if it technically works:

- **Replacing one fabrication with a subtler one.** If the builder cannot
  determine the technique for some path, the answer is to emit no identity for
  it, not to pick a plausible-looking default.
- **Confidence inflation.** `1.0` means certain. If a path is heuristic, its
  confidence must say so.
- **Making the analyzer meaningfully slower** to collect evidence nobody asked
  for. In particular, do not disable the existing short-circuiting in order to
  discover additional techniques.

## Current state

Line numbers refer to commit `03b5444`.

### The defects

1. **`value` misuses the field.** The schema defines `methods[].value` as "The
   value or contents of the evidence." `maven-pom-analysis` restates the
   technique in an invented vocabulary and carries no information.

2. **The technique is frequently wrong.** `BomRenderer` stamps
   `manifest-analysis` on every component, but `ArchiveAnalyzer` identifies most
   components by hash.

3. **It is applied to components this tool did not identify.**
   `BomRenderer.createPackageComponent()` calls `buildMavenEvidence()`
   unconditionally, so `pkg:generic` and `pkg:npm` components claim Maven POM
   analysis, as do components built by downstream producers through the model
   API. Separately, `SbomGenerator.ensureMavenManifestIdentity()` stamps the
   same identity onto components merged in from external and embedded SBOMs,
   which another tool identified.

### Where identification actually happens

The analyzer pipeline is **already ordered by accuracy and short-circuits**:
hash matching runs first, and only entries that fail it reach manifest analysis.
Each component is therefore identified by exactly one technique, already the
most accurate one available. The work is carrying that fact to the renderer,
not choosing between competing candidates.

| Path | Technique |
|---|---|
| `ArchiveAnalyzer.classifyArchiveEntries` hash lookup (`:252`) | `hash-comparison` |
| `ArchiveAnalyzer.tryMatchUnpackedArtifact` (`:515`) | `hash-comparison` (constituent files of an unpacked artifact) |
| `ArchiveAnalyzer.identifyNestedArtifact` hash hit (`:586`) | `hash-comparison` |
| `ArchiveAnalyzer.tryIdentifyFromPomProperties` (`:744`) | `manifest-analysis` |
| `ArchiveAnalyzer.detectMavenMetadataInUnmatchedJars` (`:398`) | `manifest-analysis` |
| `ArchiveAnalyzer.resolveOwnerByFilename` (`:668`) | `manifest-analysis`, low confidence (filename heuristic selected the owner) |
| `BundledArtifactScanner` bundled deps | `manifest-analysis` |

## Constraints

- CycloneDX schema 1.4–1.7, via cyclonedx-core-java (`cyclonedx.version` in the
  root POM, currently 13.2.0). `methods[]` requires both `technique` and
  `confidence`; `technique` is a closed enum.
- `evidence.identity` does not exist before CycloneDX 1.5. cyclonedx-core-java's
  version-aware serialization must drop it from 1.4 output; `GoldenBomTest`
  validates every JSON-capable schema version ≥1.4 and pins this.
- `GoldenBomTest` pins serialized bytes, including the content-derived
  `serialNumber`. Regenerate with
  `mvn -pl core test -Dtest=GoldenBomTest -Dgolden.regenerate=true` and review
  the diff.
- `PackageComponent`, `AssemblyComponents` and `BomRenderer` are public API
  (`dev.cyberstamp.maven.assembly.sbom`). Additions follow the existing
  backward-compatible-constructor pattern used for `dependenciesKnown`.
- **The model is CycloneDX-free and must stay so.** Anything added to it needs
  its own neutral vocabulary, mapped to CycloneDX in the renderer.
- Plugin configuration is Maven `@Parameter` fields on `GenerateSbomMojo`, and
  separately setters on `SbomContainerDescriptorHandler` — the assembly handler
  is a first-class entry point. `failOnDuplicateHash` exists on both.

## Design

### The model

`PackageComponent` gains a nullable `Identification`: a neutral record of
`Technique` and `confidence` (0..1, validated at construction). `Technique`
mirrors the CycloneDX technique enum in full. There is no `value`.

The analyzer sets an `Identification` at each discovery site in the table
above, as does the library's shaded-jar detection for the bundled artifacts it
adds. Everything else — non-Maven components, components built through the
pre-existing public entry points — has none.

### The renderer

`BomRenderer` renders a component's `Identification` if it has one, as a
one-element `methods` array with no `value`. Otherwise it renders no identity.
It draws no other distinctions: it does not inspect the package type, it
applies no default, and it has no option — the `identityEvidence` switch acts
where this library discovers identity (see Option shape), so it cannot touch
identification a producer supplied.

Because the analyzer never sets an `Identification` on non-Maven components,
"non-Maven components get no Maven identity" holds without a rule for it, while
a producer that attaches an `Identification` to a `GenericPackageRef` component
still gets it rendered.

### External and embedded SBOMs

`ensureMavenManifestIdentity` is deleted. Components admitted from external or
embedded SBOMs carry exactly the identity evidence upstream wrote: preserved
verbatim when present, absent when absent. `matchesArchive` and the rest of the
filter are not touched. The one exception is a merge into a component this
tool already identified (see "Identity already in the BOM wins").

## Decisions

### Made by the project owner

- **One technique per component.** Do not emit a multi-entry `methods` array.
  Populating it honestly would require defeating the analyzer's
  short-circuiting — extra I/O across a large distribution to produce
  information with no known consumer.

- **Trust upstream; external SBOM components are pass-through only.** This tool
  emits identity evidence only for components it identified itself. Filtering
  an external or embedded SBOM against the archive verifies *presence*, not
  identity: the purl and how it was determined both belong to the upstream
  tool. This tool never adds, replaces or adjusts their identity evidence.

  This supersedes an earlier revision that derived evidence from how the
  component matched the archive (`hash-comparison` for a hash match, `filename`
  for a path match, none when nothing was verified). That rule was defensible —
  a hash match against an upstream record has the same shape as the analyzer's
  hash match against a resolved artifact — but it had this tool annotating
  claims it did not make. Pass-through follows from one principle and treats
  every upstream producer — external SBOMs, embedded SBOMs and model-API
  producers like Galleon — the same way: if you did not say how you identified
  it, we do not say it for you.

  The cost: components from upstream SBOMs that carry no evidence (e.g.
  Quarkus-generated ones) lose a claim that, after a hash match, would have been
  true — that this tool confirmed the bytes match what upstream described. That
  is presence information rather than identity, has no known consumer, and can
  be added back later without a breaking change.

  A side effect: the hash-algorithm misalignment (an upstream SBOM publishing
  SHA-1 against a SHA-256 configuration is admitted unverified) no longer
  produces false evidence, since nothing is stamped on such components. Its
  filtering side is recorded under Follow-up.

- **No provenance means no identity, including through the public API.** The
  pre-existing `PackageComponent` entry points — the backward-compatible
  constructors and the `of(...)` factories without an `Identification` — emit no
  identity evidence rather than falling back to a default. Downstream producers
  lose the evidence they get today unless they opt in. That evidence was never
  true (see The Galleon case), but this is a downstream behaviour change and
  belongs in the release notes.

- **Producers may supply their own identification.** `Identification` is public
  and freely constructible, with the full CycloneDX technique vocabulary. A
  producer knows how it identified a component; this library does not, and a
  vocabulary limited to its own findings would be presumptuous. This is "trust
  upstream" applied one layer earlier.

- **Provide an option to disable identity evidence.** When off, this tool emits
  none of its own; identity authored by an upstream SBOM, or supplied by a
  producer through the model, passes through untouched. Occurrences are
  unaffected either way.

### Made by the author of this document

These are the author's calls and are open to correction.

- **Confidence values.**

  | Situation | Technique | Confidence |
  |---|---|---|
  | Archive entry's hash matched a resolved Maven artifact | `hash-comparison` | 1.0 |
  | purl read verbatim from `pom.properties`, owner unambiguous | `manifest-analysis` | 1.0 |
  | Unpacked artifact, matched on constituent member files | `hash-comparison` | 0.8 |
  | `resolveOwnerByFilename` picked the owner | `manifest-analysis` | 0.5 |
  | Bundled dep, coordinates from its own `pom.properties` | `manifest-analysis` | 1.0 |
  | Shaded jar with no resolvable owner: each descriptor, nested under the file | `manifest-analysis` | 1.0 |

  The builder should not treat the fractional numbers as precise; the
  *ordering* is the requirement.

  - **Unpacked artifact (0.8).** What was compared is a subset of the jar's
    member files, not the jar itself, and the match is partial
    (`computeUnpackPrefix()` may return null and is only logged at debug). It
    sits below an exact match.
  - **Filename-resolved owner (0.5) vs its bundled deps (1.0).**
    `resolveAndRegisterShadedOwner` (`:471`) picks the owner of a shaded jar
    heuristically, then registers the remaining descriptors as bundled
    components nested under it. The owner carries the jar's archive path and
    hash, so its claim is "this file is g:a:v" — exactly what the filename
    guess decided, hence 0.5. A bundled dep has no path or hash of its own; its
    claim is only "g:a:v is in here", read verbatim from its own
    `pom.properties`, which holds whichever descriptor was chosen as owner. The
    heuristic decides nesting, not the bundled dep's purl, so every bundled dep
    gets 1.0 regardless of how its owner was identified. An earlier revision
    gave bundled deps of a filename-resolved owner 0.5; that conflated
    placement with identity. The same reasoning covers a shaded jar whose
    owner could not be resolved at all: every descriptor is nested under the
    file, and each is still read verbatim from its own `pom.properties`.

- **No `methods[].value`.** It is optional. For `hash-comparison` the useful
  content would be the digest, which already appears in the component's own
  `hashes`; for `manifest-analysis` it would be a `pom.properties` path, which
  is not available at every discovery site. Omitting it fixes the misuse
  without plumbing content through the analyzer for no known consumer. It can
  be added later without a breaking change.

- **Option shape.** A boolean named `identityEvidence`, defaulting to `true`,
  exposed as a `@Parameter` on `GenerateSbomMojo` **and** as a setter on
  `SbomContainerDescriptorHandler`, mirroring `failOnDuplicateHash`. It acts
  where this library discovers identity, not in the renderer: `SbomGenerator`
  passes it to `ArchiveAnalyzer`, which then records no `Identification`, and
  `SbomPipeline.identityEvidence(boolean)` passes it to `ShadedJarDetection`.
  Identification a producer put on the model is rendered regardless, as the
  option decision requires.

- **Identity already in the BOM wins.** When an incoming SBOM's component
  merges with one already in the BOM, the existing identity is kept and the
  incoming one fills it only where there is none. This holds in every merge
  branch: `BomMerger.applyEvidenceIfAbsent` (`:589`, called from `:462`) for an
  existing nested component, and `migrateOccurrences` when an embedded
  component absorbs a top-level one (where the incoming identity used to win).
  The existing identity is this tool's first-hand finding about the same
  component; pass-through governs components this tool did not identify. Where
  there is none, adopting upstream's is correct — it is that tool's genuine
  claim.

## What is left to the builder

- Where `Identification` travels between discovery and `PackageComponent`
  (fields on `MavenEntry` / `NestedMavenEntry`, or otherwise).
  `NestedMavenEntry.explicit` governs dependency edges, not evidence; keep it
  separate.
- `SbomUtils.mavenManifestIdentity()` loses its second caller with
  `ensureMavenManifestIdentity`; fold it into the renderer.
- Test strategy beyond the golden: the analyzer's technique selection needs its
  own coverage.

## `attestation`

An identity known by construction — as when a provisioning tool resolves an
artifact from a repository by its coordinates — has no analysis technique to
report. CycloneDX's `attestation` ("A testimony to the accuracy of the identify
of a component made by an individual or entity", `bom-1.6.xsd`/`bom-1.7.xsd`)
fits on its wording, but the term is widely associated with *signed*
provenance (in-toto, SLSA, CycloneDX 1.6 `declarations.attestations`), and a
consumer could go looking for a signature that does not exist.

This library emits `attestation` for nothing of its own: everything it
identifies is identified by hash comparison or manifest analysis. Whether a
producer uses it is that producer's call; the vocabulary is available and this
library offers no advice.

## The Galleon case

`wildfly-galleon-plugins` (`~/git/galleon-plugins`) is the known downstream
consumer of the model API. It depends on `assembly-sbom-core` (pinned at 0.1.7)
and shades it under `org.wildfly.galleon.plugin.shaded.dev.cyberstamp.maven.assembly`.
It also produces the EAP SBOM whose 859 invalid `methods[]` entries prompted
this work.

`SbomArtifactRecorder.buildModel()` builds `AssemblyComponents` from a
provisioning record: each artifact was resolved from the Maven repository *by
its coordinates*, so its identity is known by construction. Galleon performed no
manifest analysis; the `manifest-analysis` blocks in EAP's SBOM are false, and
removing them removes a false claim.

It builds components through `PackageComponent.of(coords, path, hash, false)`
and, for each shaded component, the 6-arg constructor with a
`GenericPackageRef` and Maven dependencies nested beneath it. None of these
carries an `Identification`, so none gets identity evidence.

Galleon does not go through `filterSbomByArchive`. It merges embedded SBOMs by
calling `BomMerger.mergeUnder` directly (`SbomArtifactRecorder:469`), which adds
them as upstream wrote them. `BomMerger.applyEvidenceIfAbsent` becomes live in
its flow for the first time: once Galleon's own components carry no identity,
an embedded SBOM describing the same artifact can supply one.

galleon-plugins needs no change. Whoever bumps its `assembly-sbom-core` version
should expect identity evidence to disappear from its output, treat that as
correct, and decide whether to supply an `Identification` of Galleon's own.

## Open questions

- **Is `manifest-analysis` at 1.0 inflated for unmatched jars?**
  `detectMavenMetadataInUnmatchedJars` sees only jars that failed hash matching.
  If a jar's `pom.properties` names coordinates that *were* resolved but with
  different bytes, that suggests a rebuilt or patched jar, and 1.0 overstates
  it.

## Follow-up: `matchesArchive` filtering

Out of scope here; recorded so it is not lost. These are defects in which
external-SBOM components are admitted, independent of evidence.

- **Path-matched LIBRARY components are never compared by content.**
  `matchesArchive` (`SbomGenerator:242`) gates the hash check on
  `Component.Type.FILE` (`:244`). Every Maven dependency is a LIBRARY, so a
  component whose occurrence path exists in the archive is admitted even when
  its hash says the bytes differ. The fix removes the gate and compares the
  component's hash with the hash *at that path*, which needs a path→hash lookup
  on `ArchiveIndex` (it holds only hash→paths today) with defined behaviour on
  scoped `NestedArchiveIndex`. A mismatched component should then survive only
  if its hash is found elsewhere in the archive (the `:258` branch). This
  changes which components appear in the BOM and belongs in release notes.
- **Algorithm misalignment silently passes.** `ComponentView.hash` looks only
  for the configured algorithm, so an upstream SBOM publishing SHA-1 against a
  SHA-256 configuration has no comparable hash and its components are admitted
  unverified at `:263`. Widening algorithm support was considered and rejected
  as disproportionate: the index retains no route back to file bytes, nested
  entries have no file on disk, and `MessageDigest` cannot produce the BLAKE
  digests the CycloneDX enum allows. A one-line warning at the point of
  detection is probably the right fix; judge the noise across a large
  distribution.
- When a component's hash matches a file *other* than its recorded occurrence,
  `correctOccurrences` does not fire in the path-matched branch.

## Verification

The work is done when, in addition to the existing suite passing:

- Every row of the confidence table is covered by a test asserting the emitted
  technique and confidence for a component identified by that path, and that
  no `value` is emitted.
- **External pass-through:** an external or embedded SBOM component with
  identity evidence keeps it unchanged; one without keeps none.
- **No provenance supplied:** a component built through the pre-existing public
  entry points — `PackageComponent.of(...)` and the backward-compatible
  constructors, the Galleon shape — emits no identity evidence.
- **Producer-supplied:** a component carrying an `Identification` a producer
  built directly — including one on a `GenericPackageRef` component, and one
  using a technique this library never produces itself — renders that technique
  and confidence verbatim.
- An `Identification` with a confidence outside 0..1 is rejected at
  construction.
- `pkg:npm` and `pkg:generic` components identified by the analyzer emit no
  identity evidence.
- `BomMerger` fills a target with no identity from a source that has one.
- With the option disabled, the tool emits no identity evidence of its own,
  upstream and producer-supplied identity still pass through, and occurrences
  still appear.
- Output validates against CycloneDX 1.5 through 1.7, and 1.4 output carries no
  `evidence.identity`.
