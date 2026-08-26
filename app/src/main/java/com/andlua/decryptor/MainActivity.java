package com.andlua.decryptor;

import android.Manifest;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private static final int REQ_PICK = 41;
    private static final int REQ_APPS = 42;
    private static final int REQ_MANAGE = 44;
    private static final int REQ_WRITE = 45;
    private static final int STEP_MS = 800;

    private final Handler main = new Handler(Looper.getMainLooper());
    private File lastDecrypted;
    private String lastOutName = "decrypted.apk";
    private File pendingInput;
    private String pendingName = "app";

    private TextView status;
    private TextView logView;
    private Button pickBtn;
    private Button appsBtn;
    private ProgressBar progress;

    private volatile boolean workDone;
    private volatile Exception workError;
    private int stepIndex;
    private boolean decrypting;
    private boolean pendingSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        status = findViewById(R.id.status);
        logView = findViewById(R.id.log);
        pickBtn = findViewById(R.id.btn_pick);
        appsBtn = findViewById(R.id.btn_apps);
        progress = findViewById(R.id.progress);

        findViewById(R.id.hero).setAlpha(0f);
        findViewById(R.id.hero).animate().alpha(1f).setDuration(400).start();

        findViewById(R.id.btn_telegram).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openUrl("https://t.me/axcelLOki");
            }
        });
        findViewById(R.id.btn_youtube).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openUrl("https://www.youtube.com/@AtoomsBm");
            }
        });

        pickBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/vnd.android.package-archive");
                intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                        "application/vnd.android.package-archive",
                        "application/octet-stream",
                        "*/*"
                });
                startActivityForResult(intent, REQ_PICK);
            }
        });

        appsBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivityForResult(new Intent(MainActivity.this, InstalledAppsActivity.class), REQ_APPS);
            }
        });
    }

    private void runDecrypt() {
        if (decrypting || pendingInput == null || !pendingInput.exists()) {
            return;
        }
        decrypting = true;
        workDone = false;
        workError = null;
        stepIndex = 0;
        pendingSave = false;
        setBusy(true);
        logView.setText("");
        progress.setProgress(0);
        status.setText(getString(R.string.working));
        startWork();
        playNextStep();
    }

    private void startWork() {
        final File input = pendingInput;
        final String name = pendingName;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    lastOutName = name + "_decrypted.apk";
                    File outFile = new File(getCacheDir(), lastOutName);
                    DecryptEngine.decrypt(MainActivity.this, input, outFile,
                            new DecryptEngine.Listener() {
                                @Override
                                public void log(String line) {
                                    appendLog(line);
                                }
                            });
                    lastDecrypted = outFile;
                    workDone = true;
                } catch (Exception e) {
                    workError = e;
                    workDone = true;
                }
            }
        }).start();
    }

    private void playNextStep() {
        final String[] steps = getResources().getStringArray(R.array.decrypt_steps);
        if (stepIndex < steps.length) {
            String line = steps[stepIndex];
            logView.append(line + "\n");
            status.setText(line);
            int pct = (int) ((stepIndex + 1) * (100f / (steps.length + 1)));
            animateProgress(pct);
            stepIndex++;
            main.postDelayed(new Runnable() {
                @Override
                public void run() {
                    playNextStep();
                }
            }, STEP_MS);
            return;
        }
        waitForWork();
    }

    private void waitForWork() {
        if (!workDone) {
            status.setText(getString(R.string.finishing));
            main.postDelayed(new Runnable() {
                @Override
                public void run() {
                    waitForWork();
                }
            }, 400);
            return;
        }
        setBusy(false);
        decrypting = false;
        if (workError != null) {
            appendLog("FAILED");
            appendLog(workError.getClass().getSimpleName() + ": " + workError.getMessage());
            appendLog(DecryptEngine.stack(workError));
            status.setText(getString(R.string.failed));
            toast(getString(R.string.failed));
            return;
        }
        animateProgress(100);
        status.setText(getString(R.string.done));
        appendLog("Done.");
        askSave();
    }

    private void askSave() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.save_title)
                .setMessage(R.string.save_message)
                .setCancelable(true)
                .setPositiveButton(R.string.save_yes, new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface dialog, int which) {
                        saveToSdcard();
                    }
                })
                .setNegativeButton(R.string.save_no, null)
                .show();
    }

    private void saveToSdcard() {
        if (lastDecrypted == null || !lastDecrypted.exists()) {
            toast(getString(R.string.failed));
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                pendingSave = true;
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivityForResult(intent, REQ_MANAGE);
                } catch (Exception e) {
                    startActivityForResult(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION), REQ_MANAGE);
                }
                toast(getString(R.string.need_storage));
                return;
            }
        } else if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                pendingSave = true;
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_WRITE);
                return;
            }
        }
        writeSdcard();
    }

    private void writeSdcard() {
        try {
            File dir = new File("/sdcard");
            if (!dir.exists() || !dir.canWrite()) {
                File ext = Environment.getExternalStorageDirectory();
                if (ext != null) {
                    dir = ext;
                }
            }
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File dest = new File(dir, lastOutName);
            copyFile(lastDecrypted, dest);
            status.setText(getString(R.string.saved, dest.getAbsolutePath()));
            toast(getString(R.string.saved, dest.getAbsolutePath()));
        } catch (Exception e) {
            status.setText(getString(R.string.save_fail));
            toast(getString(R.string.save_fail));
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_WRITE && pendingSave) {
            pendingSave = false;
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                writeSdcard();
            } else {
                toast(getString(R.string.need_storage));
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_MANAGE && pendingSave) {
            pendingSave = false;
            if (Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager()) {
                writeSdcard();
            } else {
                toast(getString(R.string.need_storage));
            }
            return;
        }
        if (resultCode != RESULT_OK) {
            return;
        }
        if (requestCode == REQ_PICK && data != null && data.getData() != null) {
            Uri uri = data.getData();
            try {
                getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } catch (SecurityException ignored) {
            }
            try {
                File inFile = new File(getCacheDir(), "input.apk");
                copyUri(uri, inFile);
                pendingInput = inFile;
                pendingName = guessName(uri, "app");
                runDecrypt();
            } catch (Exception e) {
                toast(getString(R.string.failed));
            }
        } else if (requestCode == REQ_APPS && data != null) {
            String path = data.getStringExtra(InstalledAppsActivity.EXTRA_APK_PATH);
            String name = data.getStringExtra(InstalledAppsActivity.EXTRA_APP_NAME);
            if (path == null) {
                toast(getString(R.string.failed));
                return;
            }
            try {
                File src = new File(path);
                File inFile = new File(getCacheDir(), "input.apk");
                copyFile(src, inFile);
                pendingInput = inFile;
                pendingName = safeFileName(name == null ? "app" : name);
                runDecrypt();
            } catch (Exception e) {
                toast(getString(R.string.failed));
            }
        }
    }

    private void appendLog(final String line) {
        if (line == null) {
            return;
        }
        DecryptEngine.androidLog(line);
        main.post(new Runnable() {
            @Override
            public void run() {
                if (logView.getText() == null || logView.getText().length() == 0) {
                    logView.setText(line);
                } else {
                    logView.append("\n" + line);
                }
                if (logView.getParent() instanceof ScrollView) {
                    final ScrollView scroller = (ScrollView) logView.getParent();
                    scroller.post(new Runnable() {
                        @Override
                        public void run() {
                            scroller.fullScroll(View.FOCUS_DOWN);
                        }
                    });
                }
            }
        });
    }

    private void animateProgress(int to) {
        ObjectAnimator.ofInt(progress, "progress", progress.getProgress(), to)
                .setDuration(400)
                .start();
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            toast(url);
        }
    }

    private void copyUri(Uri uri, File dest) throws Exception {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new IllegalStateException("closed");
        }
        try {
            FileOutputStream out = new FileOutputStream(dest);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private static void copyFile(File src, File dest) throws Exception {
        InputStream in = new FileInputStream(src);
        try {
            OutputStream out = new FileOutputStream(dest);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private static String guessName(Uri uri, String fallback) {
        String seg = uri.getLastPathSegment();
        if (seg == null || seg.trim().isEmpty()) {
            return fallback;
        }
        int slash = Math.max(seg.lastIndexOf('/'), seg.lastIndexOf(':'));
        if (slash >= 0 && slash < seg.length() - 1) {
            seg = seg.substring(slash + 1);
        }
        if (seg.toLowerCase().endsWith(".apk")) {
            seg = seg.substring(0, seg.length() - 4);
        }
        return safeFileName(seg);
    }

    private static String safeFileName(String name) {
        String cleaned = name.replaceAll("[^a-zA-Z0-9._-]+", "_");
        if (cleaned.length() == 0) {
            return "app";
        }
        return cleaned;
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(View.VISIBLE);
        pickBtn.setEnabled(!busy);
        appsBtn.setEnabled(!busy);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
