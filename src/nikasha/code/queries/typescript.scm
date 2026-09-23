; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; TypeScript and TSX: JavaScript's definitions plus interfaces, type aliases, enums and
; namespaces (SPEC §11.2). Capture conventions are documented in c.scm.

(function_declaration name: (identifier) @name) @def.function
(generator_function_declaration name: (identifier) @name) @def.function
(class_declaration name: (_) @name) @def.class
(abstract_class_declaration name: (_) @name) @def.class
(variable_declarator name: (identifier) @name value: (class)) @def.class
(method_definition name: (_) @name) @def.method
(variable_declarator
  name: (identifier) @name
  value: [(arrow_function) (function_expression) (generator_function)]) @def.function
(assignment_expression
  left: (member_expression property: (property_identifier) @name)
  right: [(arrow_function) (function_expression)]) @def.function
(public_field_definition name: (_) @name value: [(arrow_function) (function_expression)]) @def.method
(pair key: (_) @name value: [(arrow_function) (function_expression)]) @def.method
(interface_declaration name: (_) @name) @def.type
(type_alias_declaration name: (_) @name) @def.type
(enum_declaration name: (_) @name) @def.type
(internal_module name: (_) @name body: (statement_block)) @def.module

(variable_declarator name: (identifier) @name value: (object)) @scope

(call_expression function: (_) @fn) @call
(new_expression constructor: (_) @fn) @call
