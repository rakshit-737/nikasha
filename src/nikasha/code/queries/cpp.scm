; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; C++: everything C has, plus namespaces, classes, methods and templates (SPEC §11.2).
; Capture conventions are documented in c.scm.

(function_definition declarator: (_) @declarator) @def.function

(preproc_def name: (identifier) @name) @def.macro
(preproc_function_def name: (identifier) @name) @def.macro.function_like

(namespace_definition name: (_) @name body: (declaration_list)) @def.module
(class_specifier name: (_) @name body: (field_declaration_list)) @def.class
(struct_specifier name: (_) @name body: (field_declaration_list)) @def.class
(union_specifier name: (_) @name body: (field_declaration_list)) @def.type
(enum_specifier name: (_) @name body: (enumerator_list)) @def.type
(type_definition declarator: (_) @declarator) @def.type
(alias_declaration name: (type_identifier) @name) @def.type

(declaration declarator: (function_declarator declarator: (identifier) @proto))
(declaration declarator: (pointer_declarator declarator: (function_declarator declarator: (identifier) @proto)))
(declaration declarator: (reference_declarator (function_declarator declarator: (identifier) @proto)))

(call_expression function: (_) @fn) @call

(argument_list (identifier) @ref)
(init_declarator value: (identifier) @ref)
(assignment_expression right: (identifier) @ref)
(return_statement (identifier) @ref)
(conditional_expression consequence: (identifier) @ref)
(conditional_expression alternative: (identifier) @ref)
(cast_expression value: (identifier) @ref)
(pointer_expression argument: (identifier) @ref)
(comma_expression (identifier) @ref)
(initializer_pair value: (identifier) @ref.init)
(initializer_list (identifier) @ref.init)
