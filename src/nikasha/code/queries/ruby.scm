; SPDX-FileCopyrightText: 2026 The Nikasha Authors
; SPDX-License-Identifier: Apache-2.0
;
; Ruby: methods, singleton methods, classes, modules and calls (SPEC §11.2). Qnames follow
; Ruby's own backtrace style: Mod::Class#method and Mod::Class.singleton_method.
; A bare identifier with no receiver, arguments or parentheses (`foo`) is indistinguishable
; from a local variable and is not recorded as a call. Capture conventions are in c.scm.

(method name: (_) @name) @def.function
(singleton_method name: (_) @name) @def.method.singleton
(class name: (_) @name) @def.class
(module name: (_) @name) @def.module

(call receiver: (_) method: (_) @callee) @call.indirect
(call !receiver method: (_) @callee) @call.direct
