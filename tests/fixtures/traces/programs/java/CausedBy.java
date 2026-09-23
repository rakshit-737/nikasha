// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
// Java fixture: an exception wrapped with a cause, printing "Caused by:" and "... N more".
public class CausedBy {
    static class StorageException extends RuntimeException {
        StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static int parsePort(String text) {
        return Integer.parseInt(text);
    }

    static int readPort(String text) {
        try {
            return parsePort(text);
        } catch (NumberFormatException e) {
            throw new StorageException("bad port setting", e);
        }
    }

    static void start(String text) {
        System.out.println(readPort(text));
    }

    public static void main(String[] args) {
        start("80x");
    }
}
