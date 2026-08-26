package com.andlua.decryptor;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.archive.InputSource;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class DecryptEngine {
    static final String GATE = "com.alpprotect.GateActivity";
    private static final String TAG = "AlpDecrypt";

    interface Listener {
        void log(String line);
    }

    private DecryptEngine() {}

    static File decrypt(Context ctx, File inputApk, File outputApk, Listener listener) throws Exception {
        Listener log = listener == null ? new Listener() {
            @Override
            public void log(String line) {
            }
        } : listener;
        try {
            return decryptInner(ctx, inputApk, outputApk, log);
        } catch (Exception e) {
            log.log("ERROR " + e.getClass().getSimpleName() + ": " + e.getMessage());
            log.log(stack(e));
            throw e;
        }
    }

    private static File decryptInner(Context ctx, File inputApk, File outputApk, Listener log)
            throws Exception {
        log.log("APK " + inputApk.getAbsolutePath() + " (" + inputApk.length() + " bytes)");

        ZipScan scan = scanZip(inputApk, log);
        ArchiveInfo archive = archiveInfo(ctx, inputApk, log);

        log.log("Loading package…");
        ApkModule apk = ApkModule.loadApkFile(inputApk);
        try {
            AndroidManifestBlock manifest = apk.getAndroidManifest();
            if (manifest == null) {
                throw new IllegalStateException("No manifest in this package");
            }
            String pkg = firstNonEmpty(manifest.getPackageName(), archive.packageName);
            if (pkg == null) {
                pkg = "";
            }
            String currentLauncher = firstNonEmpty(manifest.getMainActivityClassName(), archive.mainActivity);
            boolean hasGate = GATE.equals(currentLauncher);
            log.log("Package " + pkg);
            log.log("Launcher " + currentLauncher);
            log.log("Runtime gate " + (hasGate ? "yes" : "no"));

            byte[] keyFile = readOptional(apk, "assets/alpprotect.key");
            String fileLauncher = readOptionalString(apk, "assets/alpprotect.launcher");
            log.log("Key file " + (keyFile == null ? "no" : (keyFile.length + " bytes")));
            if (fileLauncher != null && fileLauncher.length() > 0) {
                log.log("Saved launcher " + fileLauncher);
            }

            StubRef stub = scan.stub;
            if (stub == null) {
                stub = findStub(apk, log);
            }
            if (stub != null) {
                log.log("Runtime dex " + stub.name + " (" + stub.data.length + " bytes)");
            } else {
                log.log("Runtime dex not found");
            }

            byte[] sampleWrapped = scan.sampleWrapped;
            if (sampleWrapped == null) {
                sampleWrapped = firstWrapped(apk);
            }
            log.log("Sealed lua " + scan.wrappedCount + "/" + scan.luaCount);

            if (scan.luaCount == 0) {
                throw new IllegalStateException("No lua files in this package");
            }

            byte[] master = null;
            if (keyFile != null && keyFile.length == 32) {
                master = keyFile;
                log.log("Key loaded from file");
            }
            if (master == null && stub != null && sampleWrapped != null) {
                List<byte[]> certs = Signer.collectCerts(ctx, inputApk, archive.certs);
                log.log("Certs to try " + certs.size());
                master = DexSlots.recoverMaster(stub.data, pkg, certs, sampleWrapped, log);
            }
            if (master != null) {
                log.log("Runtime key recovered");
            } else {
                log.log("Runtime key not recovered");
            }

            String originalLauncher = fileLauncher;
            if ((originalLauncher == null || originalLauncher.length() == 0) && stub != null) {
                originalLauncher = DexSlots.originalLauncher(stub.data);
                if (originalLauncher != null) {
                    log.log("Launcher from runtime " + originalLauncher);
                }
            }
            if ((originalLauncher == null || originalLauncher.length() == 0)
                    && archive.originalActivity != null) {
                originalLauncher = archive.originalActivity;
                log.log("Launcher from package " + originalLauncher);
            }
            if ((originalLauncher == null || originalLauncher.length() == 0)
                    && currentLauncher != null && !GATE.equals(currentLauncher)) {
                originalLauncher = currentLauncher;
            }
            if (originalLauncher != null) {
                originalLauncher = originalLauncher.trim();
            }

            int opened = 0;
            int originalOpened = 0;
            int plainKept = 0;
            int stillWrapped = 0;
            List<String> luaPaths = luaPaths(apk);
            if (luaPaths.isEmpty()) {
                luaPaths = scan.luaPaths;
            }
            log.log("Opening lua (" + luaPaths.size() + ")…");
            for (String path : luaPaths) {
                byte[] raw = null;
                try {
                    InputSource src = apk.getInputSource(path);
                    if (src != null) {
                        raw = readSource(src);
                    }
                } catch (Exception e) {
                    log.log("Read fail " + path + " " + e.getMessage());
                }
                if (raw == null) {
                    raw = scan.dataFor(path);
                }
                if (raw == null) {
                    continue;
                }
                log.log(path + " " + OriginalLua.peek(raw));
                byte[] cur = raw;
                boolean changed = false;
                if (SealCrypto.isWrapped(cur)) {
                    if (master == null) {
                        stillWrapped++;
                        log.log("  still sealed");
                        continue;
                    }
                    try {
                        cur = SealCrypto.unwrap(master, cur);
                        changed = true;
                        log.log("  unwrapped " + cur.length + " bytes");
                    } catch (Exception e) {
                        stillWrapped++;
                        log.log("  unwrap fail " + e.getClass().getSimpleName());
                        continue;
                    }
                }
                OriginalLua.Result openedLua = OriginalLua.open(cur);
                if (openedLua != null && openedLua.changed) {
                    cur = openedLua.data;
                    changed = true;
                    originalOpened++;
                    log.log("  original " + openedLua.kind + " " + cur.length + " bytes");
                } else if (openedLua != null) {
                    plainKept++;
                    log.log("  already " + openedLua.kind);
                } else {
                    log.log("  unknown encoding, kept");
                }
                if (changed) {
                    try {
                        apk.removeInputSource(path);
                    } catch (Exception ignored) {
                    }
                    apk.add(new ByteInputSource(cur, path));
                    opened++;
                }
            }
            log.log("Opened " + opened + " original " + originalOpened
                    + " already open " + plainKept + " still sealed " + stillWrapped);

            if (stillWrapped == 0) {
                if (hasGate) {
                    if (originalLauncher == null || originalLauncher.length() == 0) {
                        log.log("Launcher unknown — keeping runtime gate");
                    } else {
                        log.log("Restoring " + originalLauncher);
                        manifest.setMainActivityClassName(originalLauncher);
                        apk.refreshManifest();
                        if (stub != null) {
                            apk.removeInputSource(stub.name);
                            log.log("Removed runtime dex");
                        }
                    }
                } else if (stub != null && opened > 0) {
                    apk.removeInputSource(stub.name);
                    log.log("Removed unused runtime dex");
                }
                apk.removeInputSource("assets/alpprotect.key");
                apk.removeInputSource("assets/alpprotect.launcher");
            } else {
                log.log("Seal still locked — using runtime decrypt");
                if (master == null) {
                    throw new IllegalStateException("Could not recover runtime key");
                }
                if (originalLauncher == null || originalLauncher.length() == 0) {
                    throw new IllegalStateException("Could not find original launcher");
                }
                byte[] stubDex = readAsset(ctx, "alpprotect-runtime.dex");
                if (stubDex.length < 64) {
                    throw new IllegalStateException("Runtime stub missing");
                }
                byte[] ourCert = Signer.certDer(ctx);
                byte[] material = SealCrypto.xor(master, SealCrypto.bindMask(pkg, ourCert));
                stubDex = patchDex(stubDex, material, originalLauncher);
                if (stub != null) {
                    apk.removeInputSource(stub.name);
                }
                injectRuntimeDex(apk, stubDex);
                manifest.setMainActivityClassName(GATE);
                apk.refreshManifest();
                log.log("Runtime gate installed");
            }

            log.log("Signing…");
            stripSignatures(apk);
            File unsigned = new File(ctx.getCacheDir(), "unsigned-" + outputApk.getName());
            if (unsigned.exists()) {
                unsigned.delete();
            }
            apk.writeApk(unsigned);
            log.log("Unsigned " + unsigned.length() + " bytes");
            Signer.sign(ctx, unsigned, outputApk);
            log.log("Signed " + outputApk.length() + " bytes");
            if (!unsigned.delete()) {
                unsigned.deleteOnExit();
            }
            return outputApk;
        } finally {
            apk.close();
        }
    }

    private static ZipScan scanZip(File apkFile, Listener log) {
        ZipScan scan = new ZipScan();
        try {
            ZipFile zip = new ZipFile(apkFile);
            try {
                Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry.isDirectory()) {
                        continue;
                    }
                    String name = entry.getName();
                    if (name.startsWith("assets/") && name.toLowerCase().endsWith(".lua")) {
                        byte[] data = readAll(zip.getInputStream(entry));
                        scan.luaCount++;
                        scan.luaPaths.add(name);
                        scan.luaData.add(data);
                        if (SealCrypto.isWrapped(data)) {
                            scan.wrappedCount++;
                            if (scan.sampleWrapped == null) {
                                scan.sampleWrapped = data;
                                log.log("Sealed sample " + name);
                            }
                        } else {
                            log.log("Lua " + name + " " + OriginalLua.peek(data));
                        }
                    } else if (name.toLowerCase().endsWith(".dex")) {
                        byte[] data = readAll(zip.getInputStream(entry));
                        if (DexSlots.looksLikeStub(data)) {
                            scan.stub = new StubRef(name, data);
                        }
                    }
                }
            } finally {
                zip.close();
            }
        } catch (Exception e) {
            log.log("Zip scan fail " + e.getMessage());
        }
        return scan;
    }

    private static ArchiveInfo archiveInfo(Context ctx, File apkFile, Listener log) {
        ArchiveInfo info = new ArchiveInfo();
        try {
            PackageManager pm = ctx.getPackageManager();
            int flags = PackageManager.GET_ACTIVITIES;
            if (Build.VERSION.SDK_INT >= 28) {
                flags |= PackageManager.GET_SIGNING_CERTIFICATES;
            } else {
                flags |= PackageManager.GET_SIGNATURES;
            }
            PackageInfo pi = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(), flags);
            if (pi == null) {
                log.log("PackageManager archive info: none");
                return info;
            }
            info.packageName = pi.packageName;
            if (pi.activities != null) {
                for (int i = 0; i < pi.activities.length; i++) {
                    ActivityInfo a = pi.activities[i];
                    if (a == null || a.name == null) {
                        continue;
                    }
                    log.log("Activity " + a.name);
                    if (GATE.equals(a.name)) {
                        info.mainActivity = GATE;
                        continue;
                    }
                    if (info.originalActivity == null) {
                        info.originalActivity = a.name;
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
                Signature[] sigs = pi.signingInfo.getApkContentsSigners();
                if (sigs != null) {
                    for (int i = 0; i < sigs.length; i++) {
                        info.certs.add(sigs[i].toByteArray());
                    }
                }
            } else if (pi.signatures != null) {
                for (int i = 0; i < pi.signatures.length; i++) {
                    info.certs.add(pi.signatures[i].toByteArray());
                }
            }
            log.log("Archive package " + info.packageName
                    + " certs " + info.certs.size());
        } catch (Exception e) {
            log.log("PackageManager fail " + e.getMessage());
        }
        return info;
    }

    private static List<String> luaPaths(ApkModule apk) {
        List<String> luaPaths = new ArrayList<>();
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name != null && name.startsWith("assets/") && name.toLowerCase().endsWith(".lua")) {
                luaPaths.add(name);
            }
        }
        return luaPaths;
    }

    private static byte[] firstWrapped(ApkModule apk) throws Exception {
        for (String path : luaPaths(apk)) {
            byte[] raw = readSource(apk.getInputSource(path));
            if (SealCrypto.isWrapped(raw)) {
                return raw;
            }
        }
        return null;
    }

    private static StubRef findStub(ApkModule apk, Listener log) throws Exception {
        StubRef found = null;
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name == null || !name.toLowerCase().endsWith(".dex")) {
                continue;
            }
            byte[] data = readSource(src);
            if (DexSlots.looksLikeStub(data)) {
                found = new StubRef(name, data);
                log.log("Stub via module " + name);
            }
        }
        return found;
    }

    private static byte[] patchDex(byte[] dex, byte[] material, String launcher) {
        if (material.length != 32) {
            throw new IllegalStateException("Bad runtime key");
        }
        byte[] a = toHex(material, 0, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] b = toHex(material, 16, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] out = dex;
        out = replaceOnce(out, DexSlots.SA.getBytes(StandardCharsets.US_ASCII), a);
        out = replaceOnce(out, DexSlots.SB.getBytes(StandardCharsets.US_ASCII), b);
        out = replaceOnce(out, DexSlots.LC.getBytes(StandardCharsets.US_ASCII),
                padAscii(launcher, DexSlots.LC.length()));
        return out;
    }

    private static byte[] replaceOnce(byte[] hay, byte[] needle, byte[] repl) {
        if (needle.length != repl.length) {
            throw new IllegalStateException("Runtime patch size mismatch");
        }
        int at = indexOf(hay, needle);
        if (at < 0) {
            throw new IllegalStateException("Runtime patch slot missing");
        }
        byte[] out = new byte[hay.length];
        System.arraycopy(hay, 0, out, 0, hay.length);
        System.arraycopy(repl, 0, out, at, repl.length);
        return out;
    }

    private static byte[] padAscii(String value, int len) {
        String trimmed = value.length() > len ? value.substring(0, len) : value;
        StringBuilder sb = new StringBuilder(len);
        sb.append(trimmed);
        while (sb.length() < len) {
            sb.append(' ');
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static String toHex(byte[] data, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", data[off + i] & 0xff));
        }
        return sb.toString();
    }

    private static int indexOf(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static void injectRuntimeDex(ApkModule apk, byte[] stubDex) {
        int max = 0;
        for (InputSource src : apk.getInputSources()) {
            int n = InputSource.getDexNumber(src.getName());
            if (n > max) {
                max = n;
            }
        }
        int next = max <= 0 ? 2 : max + 1;
        String name = "classes" + next + ".dex";
        apk.removeInputSource(name);
        apk.add(new ByteInputSource(stubDex, name));
    }

    private static void stripSignatures(ApkModule apk) {
        apk.setApkSignatureBlock(null);
        List<String> remove = new ArrayList<>();
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name == null) {
                continue;
            }
            String upper = name.toUpperCase();
            if (upper.startsWith("META-INF/") && (
                    upper.endsWith(".SF")
                            || upper.endsWith(".RSA")
                            || upper.endsWith(".DSA")
                            || upper.endsWith(".EC")
                            || upper.endsWith("MANIFEST.MF")
                            || upper.contains("SIG-"))) {
                remove.add(name);
            }
        }
        for (String name : remove) {
            apk.removeInputSource(name);
        }
    }

    private static byte[] readOptional(ApkModule apk, String path) {
        try {
            InputSource src = apk.getInputSource(path);
            if (src == null) {
                return null;
            }
            return readSource(src);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readOptionalString(ApkModule apk, String path) {
        byte[] data = readOptional(apk, path);
        if (data == null) {
            return null;
        }
        return new String(data, StandardCharsets.UTF_8).trim();
    }

    private static byte[] readSource(InputSource src) throws Exception {
        InputStream in = src.openStream();
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        in.close();
        return out.toByteArray();
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && a.trim().length() > 0) {
            return a.trim();
        }
        if (b != null && b.trim().length() > 0) {
            return b.trim();
        }
        return a;
    }

    static String stack(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String s = sw.toString();
        if (s.length() > 4000) {
            return s.substring(0, 4000);
        }
        return s;
    }

    static void androidLog(String line) {
        Log.i(TAG, line);
    }

    private static final class StubRef {
        final String name;
        final byte[] data;

        StubRef(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    private static final class ZipScan {
        int luaCount;
        int wrappedCount;
        byte[] sampleWrapped;
        StubRef stub;
        final List<String> luaPaths = new ArrayList<>();
        final List<byte[]> luaData = new ArrayList<>();

        byte[] dataFor(String path) {
            for (int i = 0; i < luaPaths.size(); i++) {
                if (path.equals(luaPaths.get(i))) {
                    return luaData.get(i);
                }
            }
            return null;
        }
    }

    private static final class ArchiveInfo {
        String packageName;
        String mainActivity;
        String originalActivity;
        final List<byte[]> certs = new ArrayList<>();
    }
}
