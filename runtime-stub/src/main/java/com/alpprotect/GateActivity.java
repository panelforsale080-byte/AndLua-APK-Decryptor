package com.alpprotect;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

public class GateActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setTextColor(0xFFF3E5AB);
        view.setBackgroundColor(Color.BLACK);
        view.setPadding(48, 48, 48, 48);
        view.setText("Axcel Loki");
        setContentView(view);

        try {
            AlpRuntime.bootstrap(this);
            String launcher = AlpRuntime.originalLauncher(this);
            Intent intent = new Intent();
            intent.setClassName(getPackageName(), launcher);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        } catch (Exception e) {
            view.setText("Axcel Loki\n");
            Toast.makeText(this, "Unable to open this package", Toast.LENGTH_LONG).show();
        }
    }
}
