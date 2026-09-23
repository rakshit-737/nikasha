; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; Go: functions, methods with their receiver type, type declarations and calls (SPEC §11.2).
; Method qnames follow the runtime's traceback format: (*T).M for pointer receivers, T.M for
; value receivers. Capture conventions are documented in c.scm.

(function_declaration name: (identifier) @name) @def.function
(method_declaration
  receiver: (parameter_list (parameter_declaration type: (_) @receiver))
  name: (field_identifier) @name) @def.method
(type_spec name: (type_identifier) @name) @def.type

(call_expression function: (_) @fn) @call
