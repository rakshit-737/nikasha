; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; C definitions, calls and address-taken candidates (SPEC §11.2).
; Capture conventions (shared by every language; see nikasha/code/symbols.py):
;   @def.<kind>[.<flag>]  definition node      @name / @declarator  its name
;   @scope                qualifying scope     @call + @fn          call, callee resolved in Python
;   @call.direct / @call.indirect + @callee    @ref / @ref.init     address-taken candidates
;   @proto                prototype name (address-taken matching)

(function_definition declarator: (_) @declarator) @def.function

(preproc_def name: (identifier) @name) @def.macro
(preproc_function_def name: (identifier) @name) @def.macro.function_like

(struct_specifier name: (type_identifier) @name body: (field_declaration_list)) @def.type
(union_specifier name: (type_identifier) @name body: (field_declaration_list)) @def.type
(enum_specifier name: (type_identifier) @name body: (enumerator_list)) @def.type
(type_definition declarator: (_) @declarator) @def.type

(declaration declarator: (function_declarator declarator: (identifier) @proto))
(declaration declarator: (pointer_declarator declarator: (function_declarator declarator: (identifier) @proto)))
(declaration
  declarator: (pointer_declarator
    declarator: (pointer_declarator declarator: (function_declarator declarator: (identifier) @proto))))

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
