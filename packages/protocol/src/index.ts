/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

export {
  ProtocolError,
  type ProtocolErrorCode,
} from "./errors.js";
export {
  CipherSuite,
  IDENTIFIER_BYTES,
  MAX_CIPHERTEXT_BYTES,
  MessageType,
  NONCE_BYTES,
  PROTOCOL_VERSION,
  WIRE_PREFIX,
  decodeEnvelope,
  encodeAuthenticatedHeader,
  encodeEnvelope,
  type AuthenticatedHeader,
  type Envelope,
  type MessageMetadata,
} from "./framing.js";
export {
  generateContentKey,
  openBytes,
  openText,
  sealBytes,
  sealText,
  type OpenedBytes,
  type OpenedText,
} from "./content-key.js";
