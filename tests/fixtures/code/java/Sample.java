// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
package org.example.parse;

import java.util.ArrayList;
import java.util.List;

public class Sample {
    private final List<String> items;

    public Sample() {
        this.items = new ArrayList<>();
    }

    public void add(String s) {
        items.add(normalize(s));
    }

    private static String normalize(String s) {
        return s.trim().toLowerCase();
    }

    interface Visitor {
        void visit(String item);
    }

    enum Kind {
        A,
        B;

        boolean isA() {
            return this == A;
        }
    }

    static class Walker implements Visitor {
        @Override
        public void visit(String item) {
            System.out.println(item);
        }
    }
}
