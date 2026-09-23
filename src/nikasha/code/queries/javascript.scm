; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; JavaScript (and JSX): function declarations, methods, functions bound to names, classes and
; calls (SPEC §11.2). Capture conventions are documented in c.scm.

(function_declaration name: (identifier) @name) @def.function
(generator_function_declaration name: (identifier) @name) @def.function
(class_declaration name: (identifier) @name) @def.class
(variable_declarator name: (identifier) @name value: (class)) @def.class
(method_definition name: (_) @name) @def.method
(variable_declarator
  name: (identifier) @name
  value: [(arrow_function) (function_expression) (generator_function)]) @def.function
(assignment_expression
  left: (member_expression property: (property_identifier) @name)
  right: [(arrow_function) (function_expression)]) @def.function
(field_definition property: (_) @name value: [(arrow_function) (function_expression)]) @def.method
(pair key: (_) @name value: [(arrow_function) (function_expression)]) @def.method

(variable_declarator name: (identifier) @name value: (object)) @scope

(call_expression function: (_) @fn) @call
(new_expression constructor: (_) @fn) @call
