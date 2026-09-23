; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; Java: classes, interfaces, enums, records, methods and constructors (Class.method) and
; method invocations (SPEC §11.2). A constructor's qname is Class.Class. Capture conventions
; are documented in c.scm.

(class_declaration name: (identifier) @name) @def.class
(record_declaration name: (identifier) @name) @def.class
(interface_declaration name: (identifier) @name) @def.type
(enum_declaration name: (identifier) @name) @def.type
(annotation_type_declaration name: (identifier) @name) @def.type
(method_declaration name: (identifier) @name body: (block)) @def.method
(constructor_declaration name: (identifier) @name) @def.method.constructor
(compact_constructor_declaration name: (identifier) @name) @def.method.constructor

(method_invocation !object name: (identifier) @callee) @call.direct
(method_invocation object: (_) name: (identifier) @callee) @call.indirect
(object_creation_expression type: (type_identifier) @callee) @call.direct
(object_creation_expression type: (generic_type (type_identifier) @callee)) @call.direct
