; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; Rust: fn items, impl and trait methods (Type::method), macro_rules!, types, modules and
; calls (SPEC §11.2). Macro invocations such as println! are not calls, but a call written
; inside a macro's arguments (assert!(check(x))) is, up to two token-tree levels deep.
; Capture conventions are documented in c.scm; @call.token is an identifier followed by a
; parenthesised token tree.

(function_item name: (identifier) @name) @def.function
(macro_definition name: (identifier) @name) @def.macro
(struct_item name: (type_identifier) @name) @def.type
(enum_item name: (type_identifier) @name) @def.type
(union_item name: (type_identifier) @name) @def.type
(type_item name: (type_identifier) @name) @def.type
(trait_item name: (type_identifier) @name) @def.type
(mod_item name: (identifier) @name body: (declaration_list)) @def.module

(impl_item
  type: [
    (type_identifier) @name
    (generic_type type: (type_identifier) @name)
    (scoped_type_identifier name: (type_identifier) @name)
    (generic_type type: (scoped_type_identifier name: (type_identifier) @name))
  ]
  body: (declaration_list)) @scope

(call_expression function: (_) @fn) @call

(macro_invocation (token_tree (identifier) @call.token . (token_tree) @args))
(macro_invocation (token_tree (token_tree (identifier) @call.token . (token_tree) @args)))
(macro_rule right: (token_tree (identifier) @call.token . (token_tree) @args))
(macro_rule right: (token_tree (token_tree (identifier) @call.token . (token_tree) @args)))
(macro_rule right: (token_tree (token_tree (token_tree (identifier) @call.token . (token_tree) @args))))
