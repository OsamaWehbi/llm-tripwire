---
name: Missed leak or false alert
about: A canary leaked without being detected, or an alert fired on text that did not contain one
labels: detection
---

**What happened**
For a missed leak: how was the canary disguised (for example translated, split across lines, encoded)? For a false
alert: what text triggered it?

**Example**
A minimal example with a freshly minted canary. Never paste a canary you have actually planted.

**Expected result**
Should it be detected or not, and why?
