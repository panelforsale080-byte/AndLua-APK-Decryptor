package com.andlua.decryptor;

import android.content.Context;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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

    static byte[] apkCertDer(File apkFile) throws Exception {
        ApkVerifier.Result result = new ApkVerifier.Builder(apkFile).build().verify();
        List<java.security.cert.X509Certificate> certs = result.getSignerCertificates();
        if (certs == null || certs.isEmpty()) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        return certs.get(0).getEncoded();
    }
}
