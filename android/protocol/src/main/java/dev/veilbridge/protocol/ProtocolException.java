/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package dev.veilbridge.protocol;

public final class ProtocolException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public ProtocolException(String code, String message) {
        super(message);
        this.code = code;
    }

    public ProtocolException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
