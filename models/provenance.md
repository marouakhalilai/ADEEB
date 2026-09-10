# Model provenance and licence audit

**Status: DRAFT — blocking gate for Phase 3.** No model may be referenced from
`SecureAgent.Face` until its row here is marked `VERIFIED` with a link to the licence
text as published by the model's own repository, and the licence has been read in full
by a human.

Model weights carry terms that are **independent of the runtime that executes them**.
ONNX Runtime being MIT-licensed says nothing about the `.onnx` file you feed it. This
is the single most common way a commercial computer-vision product acquires a legal
problem, and it is cheapest to resolve now — before an accuracy baseline is calibrated
against a model we cannot ship.

## Why this file is a gate, not a formality

If a model turns out to be non-commercial after Phase 3, we do not just swap a file.
We lose the calibrated threshold (§04 of the plan), the FAR/FRR baseline, the spoof
corpus results, and the regression gate that CI enforces against that baseline. That is
a week of rework at the worst possible time.

## Required per model

| Field | Why |
|---|---|
| Source repository | The authoritative publisher, not a mirror or a re-upload |
| Exact file + SHA-256 | Mirrors and forks silently differ; pin the bytes |
| Licence | Read in full. Note any field-of-use restriction |
| Commercial use permitted | Yes / No / Ambiguous — Ambiguous is a No until resolved |
| Attribution required | Determines what ships in our third-party notices |
| Training data provenance | Some face datasets carry their own downstream restrictions |
| Verified by / date | A person, not a tool |

## Candidates

### Detection — YuNet (`face_detection_yunet`)

| Field | Value |
|---|---|
| Source | OpenCV Zoo (`opencv/opencv_zoo`) |
| Consumed via | `OpenCvSharp` → `FaceDetectorYN` |
| Size | ~1 MB |
| Licence | **TO VERIFY** — OpenCV Zoo publishes per-model licences; confirm the licence file inside the model's own directory, not the repository root |
| Commercial use | **TO VERIFY** |
| Status | `PENDING` |

### Embedding — SFace (`face_recognition_sface`)

| Field | Value |
|---|---|
| Source | OpenCV Zoo (`opencv/opencv_zoo`) |
| Consumed via | `OpenCvSharp` → `FaceRecognizerSF` |
| Output | 128-dimension embedding |
| Published thresholds | cosine 0.363 / L2 1.128 — a starting point, to be recalibrated on our own enrolment corpus |
| Licence | **TO VERIFY** — per-model licence directory |
| Commercial use | **TO VERIFY** |
| Status | `PENDING` |

### Liveness / PAD — MiniFASNet-class

| Field | Value |
|---|---|
| Source | **TO SELECT** — candidates in the Silent-Face-Anti-Spoofing lineage |
| Size | ~2 MB |
| Licence | **TO VERIFY** |
| Commercial use | **TO VERIFY** |
| Status | `PENDING` — highest licence risk of the three; several forks re-publish weights without clear terms |

### Explicitly rejected pending licence review

| Model | Reason |
|---|---|
| InsightFace ArcFace R50 (`w600k_r50`) | Higher accuracy than SFace, but several InsightFace releases are published for **non-commercial research use only**. Do not calibrate against this until the specific release's terms are confirmed in writing. |

## Fallback position

If no permissively-licensed liveness model survives review, the Standard tier ships
**without** passive liveness and is documented as deterrence-only, with challenge-response
(blink / head turn) as an interim measure and Windows Hello as the anti-spoofing path.
That is an acceptable product. Shipping unlicensed weights is not.

## Fetching

Weights are **not committed** — see `.gitignore`. `scripts/fetch-models.ps1` downloads
pinned versions and verifies SHA-256 before writing them into `models/`. A hash mismatch
is a hard failure, never a warning.
