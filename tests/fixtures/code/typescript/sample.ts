// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
interface Token {
  kind: string;
  text: string;
}

type Kind = 'word' | 'number';

enum Level {
  Low,
  High,
}

export function tokenize(src: string): Token[] {
  return src.split(/\s+/).map(toToken);
}

const toToken = (text: string): Token => ({ kind: classify(text), text });

export class Lexer<T> {
  private pos = 0;

  constructor(private readonly src: string) {}

  next(): Token | undefined {
    const all = tokenize(this.src);
    return all[this.pos++];
  }

  static create(src: string): Lexer<string> {
    return new Lexer(src);
  }
}
