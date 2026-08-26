package com.andlua.decryptor;

import android.content.Context;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class Signer {
    private static final String ASSET = "signing.p12";
    private static final String ALIAS = "alp";
    private static final char[] PASS = "andlua-protect".toCharArray();

    private Signer() {}

    static void sign(Context ctx, File input, File output) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream in = ctx.getAssets().open(ASSET);
        try {
            ks.load(in, PASS);
        } finally {
            in.close();
        }
        PrivateKey key = (PrivateKey) ks.getKey(ALIAS, PASS);
        X509Certificate cert = (X509Certificate) ks.getCertificate(ALIAS);
        if (key == null || cert == null) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                "alp", key, Collections.singletonList(cert)).build();
        new ApkSigner.Builder(Collections.singletonList(config))
                .setInputApk(input)
                .setOutputApk(output)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setMinSdkVersion(21)
                .build()
                .sign();
    }

    static byte[] certDer(Context ctx) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream in = ctx.getAssets().open(ASSET);
        try {
            ks.load(in, PASS);
        } finally {
            in.close();
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(ALIAS);
        if (cert == null) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        return cert.getEncoded();
    }

    static List<byte[]> collectCerts(Context ctx, File apkFile, List<byte[]> extra) {
        List<byte[]> out = new ArrayList<>();
        addUnique(out, extra);
        try {
            addUnique(out, Collections.singletonList(certDer(ctx)));
        } catch (Exception ignored) {
        }
        try {
            ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
            List<X509Certificate> certs = result.getSignerCertificates();
            if (certs != null) {
                for (int i = 0; i < certs.size(); i++) {
                    addUnique(out, Collections.singletonList(certs.get(i).getEncoded()));
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void addUnique(List<byte[]> out, List<byte[]> extra) {
        if (extra == null) {
            return;
        }
        for (int i = 0; i < extra.size(); i++) {
            byte[] cert = extra.get(i);
            if (cert == null || cert.length == 0) {
                continue;
            }
            boolean dup = false;
            for (int j = 0; j < out.size(); j++) {
                if (java.util.Arrays.equals(out.get(j), cert)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                out.add(cert);
            }
        }
    }
}
