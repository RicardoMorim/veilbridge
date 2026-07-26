/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

export type ProtocolErrorCode =
  | "invalid_argument"
  | "invalid_prefix"
  | "invalid_encoding"
  | "invalid_magic"
  | "unsupported_version"
  | "unsupported_message_type"
  | "unsupported_cipher_suite"
  | "unsupported_flags"
  | "invalid_identifier"
  | "invalid_nonce"
  | "invalid_sequence"
  | "invalid_length"
  | "oversized_ciphertext"
  | "oversized_plaintext"
  | "invalid_content_key"
  | "authentication_failed"
  | "invalid_utf8";

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}
