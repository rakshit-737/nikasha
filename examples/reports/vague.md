<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: Apache-2.0

FICTIONAL TEST FIXTURE for Nikasha. libhdr is the project's own demo library (examples/vulnlab);
this is not a report about real software. A report with no checkable specifics. Expected verdict: INSUFFICIENT, with 3 or
more questions for the reporter.
-->

# Critical memory corruption in libhdr

I found a serious memory corruption vulnerability in libhdr. When it parses certain HTTP
headers it crashes, and I believe this can lead to remote code execution. It happens
sometimes with large inputs.

This is critical and affects many users. Please fix it as soon as possible and assign a CVE.
