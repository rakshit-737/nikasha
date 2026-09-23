// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Java fixture: ArrayIndexOutOfBoundsException from nested calls.
public class IndexOutOfBounds {
    static int pick(int[] values, int index) {
        return values[index];
    }

    static int last(int[] values) {
        return pick(values, values.length);
    }

    static int summarize(int[] values) {
        return last(values) * 2;
    }

    public static void main(String[] args) {
        System.out.println(summarize(new int[] {1, 2, 3}));
    }
}
