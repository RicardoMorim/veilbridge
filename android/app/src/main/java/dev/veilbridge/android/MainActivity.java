/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package dev.veilbridge.android;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import dev.veilbridge.protocol.ProtocolException;
import dev.veilbridge.protocol.VeilBridgeProtocol;
import java.math.BigInteger;
import java.util.Arrays;

public final class MainActivity extends Activity {
    private final VeilBridgeProtocol protocol = new VeilBridgeProtocol();
    private final byte[] conversationId = protocol.generateIdentifier();
    private final byte[] senderDeviceId = protocol.generateIdentifier();

    private EditText keyInput;
    private EditText plaintextInput;
    private EditText carrierInput;
    private TextView decryptedOutput;
    private TextView statusOutput;
    private long nextSequence = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        keyInput = findViewById(R.id.key_input);
        plaintextInput = findViewById(R.id.plaintext_input);
        carrierInput = findViewById(R.id.carrier_input);
        decryptedOutput = findViewById(R.id.decrypted_output);
        statusOutput = findViewById(R.id.status_output);

        findViewById(R.id.generate_key_button).setOnClickListener(
                view -> generateKey());
        findViewById(R.id.copy_key_button).setOnClickListener(
                view -> copyText("VeilBridge test key", keyInput.getText().toString(), true));
        findViewById(R.id.paste_key_button).setOnClickListener(
                view -> pasteInto(keyInput, "Key pasted for this session."));
        findViewById(R.id.encrypt_button).setOnClickListener(
                view -> encrypt());
        findViewById(R.id.paste_payload_button).setOnClickListener(
                view -> pasteInto(carrierInput, "Carrier payload pasted."));
        findViewById(R.id.copy_payload_button).setOnClickListener(
                view -> copyText(
                        "VeilBridge encrypted payload",
                        carrierInput.getText().toString(),
                        false));
        findViewById(R.id.share_payload_button).setOnClickListener(
                view -> sharePayload());
        findViewById(R.id.decrypt_button).setOnClickListener(
                view -> decrypt());

        generateKey();
        handleSharedText(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleSharedText(intent);
    }

    private void generateKey() {
        byte[] key = protocol.generateContentKey();
        try {
            keyInput.setText(protocol.encodeContentKey(key));
            showSuccess("Generated a new session-only test key.");
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private void encrypt() {
        byte[] key = null;
        try {
            String plaintext = plaintextInput.getText().toString();
            if (plaintext.isEmpty()) {
                throw new ProtocolException(
                        "invalid_argument",
                        "Enter private text before encrypting.");
            }

            key = protocol.decodeContentKey(keyInput.getText().toString().trim());
            VeilBridgeProtocol.MessageMetadata metadata =
                    new VeilBridgeProtocol.MessageMetadata(
                            conversationId,
                            senderDeviceId,
                            BigInteger.valueOf(nextSequence++));
            String wire = protocol.sealText(plaintext, key, metadata);
            carrierInput.setText(wire);
            decryptedOutput.setText(R.string.decrypted_empty);
            showSuccess(
                    "Encrypted locally. Only the vb1.… payload should be sent through the messenger.");
        } catch (ProtocolException error) {
            showError(error);
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private void decrypt() {
        byte[] key = null;
        try {
            key = protocol.decodeContentKey(keyInput.getText().toString().trim());
            String wire = carrierInput.getText().toString().trim();
            VeilBridgeProtocol.OpenedText opened = protocol.openText(wire, key);
            decryptedOutput.setText(opened.getPlaintext());
            showSuccess(getString(
                    R.string.status_decrypted,
                    opened.getMetadata().getSequence().toString()));
        } catch (ProtocolException error) {
            decryptedOutput.setText(R.string.decrypted_empty);
            showError(error);
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private void sharePayload() {
        String wire = carrierInput.getText().toString().trim();
        if (!wire.startsWith(VeilBridgeProtocol.WIRE_PREFIX)) {
            showError(new ProtocolException(
                    "invalid_prefix",
                    "Encrypt a message or paste a vb1.… payload before sharing."));
            return;
        }

        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_TEXT, wire);
        startActivity(Intent.createChooser(
                send,
                getString(R.string.share_chooser)));
    }

    private void handleSharedText(Intent intent) {
        if (intent == null
                || !Intent.ACTION_SEND.equals(intent.getAction())
                || !"text/plain".equals(intent.getType())) {
            return;
        }

        String shared = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (shared == null || shared.trim().isEmpty()) {
            return;
        }
        if (shared.trim().startsWith(VeilBridgeProtocol.WIRE_PREFIX)) {
            carrierInput.setText(shared.trim());
            showSuccess("Received an encrypted payload. Paste the matching key, then decrypt.");
        } else {
            plaintextInput.setText(shared);
            showSuccess("Received private text through Android Share. Tap Encrypt before sending.");
        }
    }

    private void copyText(String label, String text, boolean sensitive) {
        if (text == null || text.trim().isEmpty()) {
            showError(new ProtocolException(
                    "invalid_argument",
                    "There is nothing to copy."));
            return;
        }

        ClipData clip = ClipData.newPlainText(label, text);
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(clip);
        Toast.makeText(
                this,
                sensitive
                        ? "Test key copied. Transfer it separately from the encrypted message."
                        : "Encrypted payload copied.",
                Toast.LENGTH_SHORT)
                .show();
    }

    private void pasteInto(EditText destination, String successMessage) {
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (!clipboard.hasPrimaryClip()
                || clipboard.getPrimaryClip() == null
                || clipboard.getPrimaryClip().getItemCount() == 0) {
            showError(new ProtocolException(
                    "invalid_argument",
                    "The clipboard does not contain text."));
            return;
        }

        CharSequence text = clipboard
                .getPrimaryClip()
                .getItemAt(0)
                .coerceToText(this);
        destination.setText(text);
        showSuccess(successMessage);
    }

    private void showSuccess(String message) {
        statusOutput.setText(message);
        statusOutput.setTextColor(getColor(R.color.veilbridge_success));
    }

    private void showError(ProtocolException error) {
        statusOutput.setText(getString(
                R.string.status_error,
                error.getCode(),
                error.getMessage()));
        statusOutput.setTextColor(getColor(R.color.veilbridge_error));
    }
}
