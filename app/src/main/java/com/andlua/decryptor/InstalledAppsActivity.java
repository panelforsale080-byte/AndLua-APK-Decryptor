package com.andlua.decryptor;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class InstalledAppsActivity extends Activity {
    static final String EXTRA_APK_PATH = "apk_path";
    static final String EXTRA_APP_NAME = "app_name";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_apps);
        ListView list = findViewById(R.id.app_list);
        final List<AppRow> rows = loadApps();
        if (rows.isEmpty()) {
            Toast.makeText(this, R.string.no_apps, Toast.LENGTH_SHORT).show();
        }
        list.setAdapter(new AppAdapter(rows));
        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                AppRow row = rows.get(position);
                Intent data = new Intent();
                data.putExtra(EXTRA_APK_PATH, row.apkPath);
                data.putExtra(EXTRA_APP_NAME, row.label);
                setResult(RESULT_OK, data);
                finish();
            }
        });
    }

    private List<AppRow> loadApps() {
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> infos = pm.getInstalledApplications(0);
        List<AppRow> user = new ArrayList<>();
        List<AppRow> system = new ArrayList<>();
        String self = getPackageName();
        for (ApplicationInfo info : infos) {
            if (self.equals(info.packageName)) {
                continue;
            }
            String path = info.sourceDir;
            if (path == null || path.length() == 0) {
                continue;
            }
            File apk = new File(path);
            if (!apk.exists() || !apk.canRead()) {
                continue;
            }
            AppRow row = new AppRow();
            row.label = String.valueOf(pm.getApplicationLabel(info));
            row.pkg = info.packageName;
            row.apkPath = path;
            row.icon = pm.getApplicationIcon(info);
            if ((info.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                system.add(row);
            } else {
                user.add(row);
            }
        }
        Comparator<AppRow> byName = new Comparator<AppRow>() {
            @Override
            public int compare(AppRow a, AppRow b) {
                return a.label.compareToIgnoreCase(b.label);
            }
        };
        Collections.sort(user, byName);
        Collections.sort(system, byName);
        user.addAll(system);
        return user;
    }

    private class AppAdapter extends BaseAdapter {
        private final List<AppRow> rows;

        AppAdapter(List<AppRow> rows) {
            this.rows = rows;
        }

        @Override
        public int getCount() {
            return rows.size();
        }

        @Override
        public Object getItem(int position) {
            return rows.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.item_app, parent, false);
            }
            AppRow row = rows.get(position);
            ImageView icon = convertView.findViewById(R.id.app_icon);
            TextView label = convertView.findViewById(R.id.app_label);
            TextView pkg = convertView.findViewById(R.id.app_pkg);
            icon.setImageDrawable(row.icon);
            label.setText(row.label);
            pkg.setText(row.pkg);
            return convertView;
        }
    }

    private static class AppRow {
        String label;
        String pkg;
        String apkPath;
        Drawable icon;
    }
}
