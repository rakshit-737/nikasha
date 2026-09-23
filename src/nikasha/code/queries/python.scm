; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; Python: functions, classes, methods and calls (SPEC §11.2).
; Capture conventions are documented in c.scm.

(function_definition name: (identifier) @name) @def.function
(class_definition name: (identifier) @name) @def.class

(call function: (_) @fn) @call
