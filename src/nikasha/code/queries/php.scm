; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; PHP: functions, classes, interfaces, traits, enums, methods (Class::method) and function,
; member and static calls (SPEC §11.2). Capture conventions are documented in c.scm.

(function_definition name: (name) @name) @def.function
(class_declaration name: (name) @name) @def.class
(trait_declaration name: (name) @name) @def.class
(interface_declaration name: (name) @name) @def.type
(enum_declaration name: (name) @name) @def.type
(method_declaration name: (name) @name body: (compound_statement)) @def.method

(function_call_expression function: (_) @fn) @call
(member_call_expression name: (name) @callee) @call.indirect
(nullsafe_member_call_expression name: (name) @callee) @call.indirect
(scoped_call_expression name: (name) @callee) @call.direct
(object_creation_expression [(name) (qualified_name)] @callee) @call.direct
