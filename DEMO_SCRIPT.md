# Firmroot — 2-Minute Judging Pitch & Live Demo Script

**Total Time Budget:** 2 minutes (120 seconds)  
**Goal:** Hit all 6 rubric categories cleanly, show real working code, and highlight the evidence-linked Gemini architecture.

---

## 1. Opening Hook & The Real-World Problem (0:00 – 0:30)
> **Speaker (Ray):**
> "Hi everyone, we’re the Firmroot team.
> 
> Firmware powers the routers, cameras, and industrial controllers that run our critical infrastructure. But securing it requires specialized reverse-engineering skills that most IoT manufacturers simply don't have. Existing scanners dump thousands of lines of uncontextualized strings, leaving small teams overwhelmed.
> 
> In our own vulnerability research on the Lantronix EDS5000 industrial device server, we uncovered and responsibly disclosed an unauthenticated root flaw that was vendor-confirmed and patched. We built Firmroot to take that manual expert triage methodology and automate it for every engineering team."

---

## 2. Live Scan & Architecture Demonstration (0:30 – 1:15)
> **Speaker (Priyanka):**
> *(Screen shows the Firmroot single-screen review dashboard running live on Google Cloud)*
> 
> "Firmroot is deployed as a stateless container on **Google Cloud Run**, backed by **Cloud Storage** for sample rootfs images and **Firestore** for scan and review state.
> 
> Let’s run a live analysis on the Lantronix EDS5000 firmware:
> 1. In seconds, our deterministic pipeline extracts the filesystem and scans for hardcoded secrets, outdated components, and dangerous service configurations.
> 2. On the **left column**, you see the grounded, deterministic proof: extracted private keys, root shadow hashes, and unencrypted telnet and gdbserver listeners.
> 3. We feed this structured evidence payload to the **Gemini API** via Google AI Studio."

---

## 3. Google AI Depth & Evidence-Linked Triage (1:15 – 1:45)
> **Speaker (Faisal):**
> "Most AI implementations try to make the LLM act as the scanner—which leads to hallucinations and fake CVEs. Firmroot takes the opposite approach:
> 
> - **The deterministic engine discovers; Gemini contextualizes.**
> - On the **right column**, Gemini uses a strict JSON schema to group correlated evidence, assign risk-calibrated priorities (Critical, High, Medium), and draft exact remediation instructions for the build system.
> - Notice that every single finding group strictly cites its deterministic IDs—like `EVID-001` and `EVID-002`. Gemini never invents a finding without proof.
> - Crucially, we include a **Human Verification sign-off** checkbox on every group. The AI accelerates the triage; the engineer retains final authority."

---

## 4. Closing & Impact (1:45 – 2:00)
> **Speaker (Ray):**
> "Firmroot turns a multi-day specialist reverse-engineering slog into a sub-60-second, evidence-linked triage review. It bridges the security skill gap for embedded hardware manufacturers without sacrificing precision.
> 
> Thank you, and we're ready for your questions!"
