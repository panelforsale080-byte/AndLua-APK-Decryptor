package com.andlua.decryptor;

final class LuaVm {
    private static boolean loaded;
    private static boolean available;

    static {
        try {
            System.loadLibrary("luavm");
            loaded = true;
            available = true;
        } catch (Throwable t) {
            loaded = false;
            available = false;
        }
    }

    private LuaVm() {}

    static boolean ready() {
        return available;
    }

    static byte[] undump(String libDir, byte[] lua) {
        if (!loaded || libDir == null || lua == null || lua.length == 0) {
            return null;
        }
        try {
            return undumpNative(libDir, lua);
        } catch (Throwable t) {
            return null;
        }
    }

    static String error() {
        if (!loaded) {
            return "native runtime missing";
        }
        try {
            String e = lastError();
            return e == null ? "" : e;
        } catch (Throwable t) {
            return t.getMessage();
        }
    }

    private static native byte[] undumpNative(String libDir, byte[] lua);

    private static native String lastError();
}
