// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Java fixture: NullPointerException with the helpful message, three calls deep.
public class NullField {
    static class Session {
        String user;
    }

    static int nameLength(Session s) {
        return s.user.length();
    }

    static int describe(Session s) {
        return nameLength(s) + 1;
    }

    public static void main(String[] args) {
        System.out.println(describe(new Session()));
    }
}
