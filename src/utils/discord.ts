import axios from "axios";

export const CHUNK_SIZE_BYTES = 20 * 1024 * 1024; // 20 MB

export type DiscordTarget =
  { webhookUrl: string } | { botToken: string; channelId: string };

export interface DiscordFile {
  uri: string;
  name: string;
  mimeType?: string;
}

export interface DiscordAttachment {
  id: string;
  filename: string;
  url: string;
  proxy_url?: string;
  size: number;
  content_type?: string;
}

export interface DiscordMessage {
  id: string;
  channel_id?: string;
  content: string;
  attachments: DiscordAttachment[];
}

export interface UploadedChunkInfo {
  index: number;
  totalChunks: number;
  partName: string;
  size: number;
  message?: DiscordMessage;
}

export interface ChunkedUploadResult {
  fileName: string;
  mimeType: string;
  totalSize: number;
  chunkSizeBytes: number;
  isChunked: boolean;
  totalChunks: number;
  chunks: UploadedChunkInfo[];
  attachments: DiscordAttachment[];
}

export interface EncryptionMetadata {
  algorithm: "AES-GCM";
  keyDerivation: "PBKDF2-SHA256" | "raw-256-bit";
  iterations?: number;
  /** Base64-encoded 16-byte salt (present when using passphrase) */
  saltBase64?: string;
  /** Base64-encoded 12-byte IV */
  ivBase64: string;
  originalSize: number;
  encryptedSize: number;
}

export interface EncryptedChunkedUploadResult extends ChunkedUploadResult {
  encryption: EncryptionMetadata;
}

export interface CdnLinkInfo {
  messageId: string;
  attachmentId: string;
  filename: string;
  url: string;
  proxyUrl?: string;
  size: number;
  contentType?: string;
  expiresAt: string | null;
  isExpired: boolean;
}

export interface GeneratedVaultKey {
  bytes: Uint8Array;
  base64: string;
  hex: string;
}

function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "Web Crypto subtle API is unavailable in this JS runtime. Install/configure a crypto polyfill (such as expo-crypto or react-native-quick-crypto) for React Native.",
    );
  }
  return subtle;
}

function getRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error(
      "crypto.getRandomValues is unavailable in this JS runtime. Initialize a crypto polyfill before generating keys or IVs.",
    );
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error("Invalid hex string.");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Generates a cryptographically random 256-bit (32-byte) key/seed for raw-256-bit mode.
 * Give the base64 or hex value to the user to back up safely.
 */
export function generateVaultSeedKey(): GeneratedVaultKey {
  const bytes = getRandomBytes(32);
  return {
    bytes,
    base64: bytesToBase64(bytes),
    hex: bytesToHex(bytes),
  };
}

async function deriveAesKeyFromSecret(
  secret: string | Uint8Array,
  salt: Uint8Array,
  iterations: number,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const keyMaterialBytes =
    typeof secret === "string" ? new TextEncoder().encode(secret) : secret;

  const baseKey = await subtle.importKey(
    "raw",
    toArrayBuffer(keyMaterialBytes),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toArrayBuffer(salt),
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

/**
 * Encrypts the entire byte array with AES-256-GCM before chunking.
 * `secret` can be a passphrase string or a 32-byte raw key (`Uint8Array`).
 */
export async function encryptWholeFileBytes(
  plainBytes: Uint8Array,
  secret: string | Uint8Array,
  iterations = 100_000,
): Promise<{ encryptedBytes: Uint8Array; encryption: EncryptionMetadata }> {
  const subtle = getSubtleCrypto();
  const iv = getRandomBytes(12);

  let key: CryptoKey;
  let saltBase64: string | undefined;
  let keyDerivation: EncryptionMetadata["keyDerivation"];

  if (typeof secret === "string") {
    const salt = getRandomBytes(16);
    saltBase64 = bytesToBase64(salt);
    keyDerivation = "PBKDF2-SHA256";
    key = await deriveAesKeyFromSecret(secret, salt, iterations, ["encrypt"]);
  } else {
    if (secret.byteLength !== 32) {
      throw new Error(
        "Raw encryption key must be exactly 32 bytes (256 bits).",
      );
    }
    keyDerivation = "raw-256-bit";
    key = await subtle.importKey(
      "raw",
      toArrayBuffer(secret),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
  }

  const cipherBuffer = await subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(plainBytes),
  );

  const encryptedBytes = new Uint8Array(cipherBuffer);

  return {
    encryptedBytes,
    encryption: {
      algorithm: "AES-GCM",
      keyDerivation,
      ...(keyDerivation === "PBKDF2-SHA256" ? { iterations, saltBase64 } : {}),
      ivBase64: bytesToBase64(iv),
      originalSize: plainBytes.byteLength,
      encryptedSize: encryptedBytes.byteLength,
    },
  };
}

/**
 * Reassembles encrypted chunks in order and decrypts the full file back into an ArrayBuffer.
 */
export async function decryptChunksToBuffer(
  encryptedChunks: ArrayBuffer[],
  secret: string | Uint8Array,
  encryption: EncryptionMetadata,
): Promise<ArrayBuffer> {
  const subtle = getSubtleCrypto();
  const totalCipherBytes = encryptedChunks.reduce(
    (sum, buf) => sum + buf.byteLength,
    0,
  );
  const combinedEncrypted = new Uint8Array(totalCipherBytes);

  let offset = 0;
  for (const chunk of encryptedChunks) {
    combinedEncrypted.set(new Uint8Array(chunk), offset);
    offset += chunk.byteLength;
  }

  const iv = base64ToBytes(encryption.ivBase64);
  let key: CryptoKey;

  if (encryption.keyDerivation === "PBKDF2-SHA256") {
    if (!encryption.saltBase64) {
      throw new Error("Missing saltBase64 for PBKDF2-SHA256 decryption.");
    }
    const salt = base64ToBytes(encryption.saltBase64);
    key = await deriveAesKeyFromSecret(
      secret,
      salt,
      encryption.iterations ?? 100_000,
      ["decrypt"],
    );
  } else {
    if (typeof secret === "string") {
      throw new Error(
        "Expected a 32-byte Uint8Array key for raw-256-bit decryption.",
      );
    }
    key = await subtle.importKey(
      "raw",
      toArrayBuffer(secret),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  return subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(combinedEncrypted),
  );
}

function buildFormData(files: DiscordFile[], content?: string): FormData {
  const formData = new FormData();
  if (content !== undefined) {
    formData.append("payload_json", JSON.stringify({ content }));
  }
  files.forEach((file, i) => {
    const part = {
      uri: file.uri,
      name: file.name,
      type: file.mimeType ?? "application/octet-stream",
    } as unknown as Blob;
    formData.append(`files[${i}]`, part, file.name);
  });
  return formData;
}

export function getCdnExpiration(url: string): Date | null {
  try {
    const parsed = new URL(url);
    const exHex = parsed.searchParams.get("ex");
    if (!exHex) return null;
    const seconds = parseInt(exHex, 16);
    if (Number.isNaN(seconds)) return null;
    return new Date(seconds * 1000);
  } catch {
    return null;
  }
}

export function isCdnUrlExpired(url: string): boolean {
  const expiresAt = getCdnExpiration(url);
  if (!expiresAt) return false;
  return expiresAt.getTime() <= Date.now();
}

// Send-only webhook upload (no bot required; cannot read messages)
export async function uploadViaWebhook(
  webhookUrl: string,
  files: DiscordFile[],
  content?: string,
): Promise<DiscordMessage | null> {
  const endpoint = webhookUrl.includes("?")
    ? `${webhookUrl}&wait=true`
    : `${webhookUrl}?wait=true`;
  const { data } = await axios.post<DiscordMessage>(
    endpoint,
    buildFormData(files, content),
  );
  return data ?? null;
}

// Bot upload
export async function uploadViaBot(
  botToken: string,
  channelId: string,
  files: DiscordFile[],
  content?: string,
): Promise<DiscordMessage> {
  const { data } = await axios.post<DiscordMessage>(
    `https://discord.com/api/v10/channels/${channelId}/messages`,
    buildFormData(files, content),
    { headers: { Authorization: `Bot ${botToken}` } },
  );
  return data;
}

async function postPart(
  target: DiscordTarget,
  formData: FormData,
): Promise<DiscordMessage | undefined> {
  if ("webhookUrl" in target) {
    const endpoint = target.webhookUrl.includes("?")
      ? `${target.webhookUrl}&wait=true`
      : `${target.webhookUrl}?wait=true`;
    const { data } = await axios.post<DiscordMessage>(endpoint, formData);
    return data;
  }

  const { data } = await axios.post<DiscordMessage>(
    `https://discord.com/api/v10/channels/${target.channelId}/messages`,
    formData,
    { headers: { Authorization: `Bot ${target.botToken}` } },
  );
  return data;
}

async function uploadByteBlocks(
  target: DiscordTarget,
  baseFileName: string,
  mimeType: string,
  bytes: Uint8Array,
  chunkSizeBytes: number,
  content?: string,
  extensionSuffix = "",
): Promise<ChunkedUploadResult> {
  const totalSize = bytes.byteLength;
  const isChunked = totalSize > chunkSizeBytes;
  const totalChunks = isChunked ? Math.ceil(totalSize / chunkSizeBytes) : 1;

  const chunks: UploadedChunkInfo[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSizeBytes;
    const end = isChunked
      ? Math.min(start + chunkSizeBytes, totalSize)
      : totalSize;
    const slice = bytes.slice(start, end);
    const blob = new Blob([toArrayBuffer(slice)], { type: mimeType });

    const partName = isChunked
      ? `${baseFileName}${extensionSuffix}.part${i + 1}of${totalChunks}`
      : `${baseFileName}${extensionSuffix}`;
    const note = isChunked
      ? content
        ? `${content} (${i + 1}/${totalChunks})`
        : partName
      : content;

    const formData = new FormData();
    if (note !== undefined) {
      formData.append("payload_json", JSON.stringify({ content: note }));
    }
    formData.append("files[0]", blob as unknown as Blob, partName);

    const message = await postPart(target, formData);

    chunks.push({
      index: i,
      totalChunks,
      partName,
      size: slice.byteLength,
      message,
    });
  }

  const attachments = chunks.flatMap((c) => c.message?.attachments ?? []);

  return {
    fileName: `${baseFileName}${extensionSuffix}`,
    mimeType,
    totalSize,
    chunkSizeBytes,
    isChunked,
    totalChunks,
    chunks,
    attachments,
  };
}

// Splits plain files > 20 MB into <= 20 MB chunks and returns one summary JSON object
export async function uploadFileInChunks(
  target: DiscordTarget,
  file: DiscordFile,
  content?: string,
  chunkSizeBytes = CHUNK_SIZE_BYTES,
): Promise<ChunkedUploadResult> {
  const mimeType = file.mimeType ?? "application/octet-stream";
  const { data: buffer } = await axios.get<ArrayBuffer>(file.uri, {
    responseType: "arraybuffer",
  });
  const bytes = new Uint8Array(buffer);

  return uploadByteBlocks(
    target,
    file.name,
    mimeType,
    bytes,
    chunkSizeBytes,
    content,
  );
}

// Encrypts the whole file first, then chunks into <= 20 MB blocks and uploads via axios
export async function encryptAndUploadFileInChunks(
  target: DiscordTarget,
  file: DiscordFile,
  secret: string | Uint8Array,
  content?: string,
  chunkSizeBytes = CHUNK_SIZE_BYTES,
): Promise<EncryptedChunkedUploadResult> {
  const { data: buffer } = await axios.get<ArrayBuffer>(file.uri, {
    responseType: "arraybuffer",
  });
  const plainBytes = new Uint8Array(buffer);

  const { encryptedBytes, encryption } = await encryptWholeFileBytes(
    plainBytes,
    secret,
  );

  const uploadResult = await uploadByteBlocks(
    target,
    file.name,
    "application/octet-stream",
    encryptedBytes,
    chunkSizeBytes,
    content,
    ".enc",
  );

  return {
    ...uploadResult,
    fileName: file.name,
    encryption,
  };
}

// Bot read messages & list file attachments
export async function fetchChannelFiles(
  botToken: string,
  channelId: string,
  limit = 20,
): Promise<DiscordAttachment[]> {
  const { data } = await axios.get<DiscordMessage[]>(
    `https://discord.com/api/v10/channels/${channelId}/messages`,
    {
      params: { limit },
      headers: { Authorization: `Bot ${botToken}` },
    },
  );
  return data.flatMap((m) => m.attachments ?? []);
}

// Fetches a single message via Bot API and returns fresh CDN links for its attachments
export async function fetchMessageCdnLinks(
  botToken: string,
  channelId: string,
  messageId: string,
): Promise<CdnLinkInfo[]> {
  const { data } = await axios.get<DiscordMessage>(
    `https://discord.com/api/v10/channels/${channelId}/messages/${messageId}`,
    {
      headers: { Authorization: `Bot ${botToken}` },
    },
  );

  return (data.attachments ?? []).map((att) => {
    const expires = getCdnExpiration(att.url);
    return {
      messageId: data.id,
      attachmentId: att.id,
      filename: att.filename,
      url: att.url,
      proxyUrl: att.proxy_url,
      size: att.size,
      contentType: att.content_type,
      expiresAt: expires ? expires.toISOString() : null,
      isExpired: isCdnUrlExpired(att.url),
    };
  });
}

// Fetches fresh CDN links across multiple message IDs (e.g., all parts of a chunked file)
export async function refreshCdnLinksForMessages(
  botToken: string,
  channelId: string,
  messageIds: string[],
): Promise<CdnLinkInfo[]> {
  const results = await Promise.all(
    messageIds.map((id) => fetchMessageCdnLinks(botToken, channelId, id)),
  );
  return results.flat();
}

export async function downloadAttachment(
  attachment: DiscordAttachment,
): Promise<ArrayBuffer> {
  const { data } = await axios.get<ArrayBuffer>(attachment.url, {
    responseType: "arraybuffer",
  });
  return data;
}
