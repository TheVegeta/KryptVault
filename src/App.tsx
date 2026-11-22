import "./global.css";

import {
  createNativeStackNavigator,
  type NativeStackScreenProps,
} from "@react-navigation/native-stack";
import axios from "axios";
import * as Clipboard from "expo-clipboard";
import * as DocumentPicker from "expo-document-picker";
import { useState } from "react";
import {
  Alert,
  Pressable,
  ScrollView,
  Text,
  TextInput,
  View,
} from "react-native";
import { AppProvider } from "./providers/AppProvider";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  CHUNK_SIZE_BYTES,
  decryptChunksToBuffer,
  downloadAttachment,
  encryptAndUploadFileInChunks,
  fetchChannelFiles,
  generateVaultSeedKey,
  hexToBytes,
  refreshCdnLinksForMessages,
  uploadFileInChunks,
  type CdnLinkInfo,
  type DiscordAttachment,
  type DiscordFile,
  type DiscordTarget,
  type EncryptedChunkedUploadResult,
  type GeneratedVaultKey,
} from "./utils/discord";

export type RootStackParamList = {
  Home: undefined;
};

declare global {
  namespace ReactNavigation {
    interface RootParamList extends RootStackParamList {}
  }
}

type HomeProps = NativeStackScreenProps<RootStackParamList, "Home">;

interface UploadUiResult extends EncryptedChunkedUploadResult {
  wasEncrypted: boolean;
}

const Stack = createNativeStackNavigator<RootStackParamList>();

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const idx = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const val = bytes / Math.pow(1024, idx);
  return `${val.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function parse256BitKeyInput(rawInput: string): GeneratedVaultKey {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error("Enter or upload a 256-bit key in Base64 or hex format.");
  }

  let unquoted = trimmed;
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    unquoted = trimmed.slice(1, -1).trim();
  }

  // Try JSON object if user uploaded a key backup JSON
  if (unquoted.startsWith("{")) {
    const parsed = JSON.parse(unquoted) as {
      keyBase64?: string;
      base64?: string;
      keyHex?: string;
      hex?: string;
    };
    const candidate =
      parsed.keyBase64 ?? parsed.base64 ?? parsed.keyHex ?? parsed.hex;
    if (!candidate) {
      throw new Error(
        "JSON key file must contain keyBase64, base64, keyHex, or hex.",
      );
    }
    return parse256BitKeyInput(candidate);
  }

  // Hex (64 hex chars, optional 0x prefix)
  const hexClean = unquoted.replace(/^0x/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(hexClean)) {
    const bytes = hexToBytes(hexClean);
    return {
      bytes,
      base64: bytesToBase64(bytes),
      hex: bytesToHex(bytes),
    };
  }

  // Base64 (32 bytes = 44 chars with '=' padding)
  const bytes = base64ToBytes(unquoted);
  if (bytes.byteLength !== 32) {
    throw new Error(
      `Invalid key length (${bytes.byteLength} bytes). A 256-bit vault key must be exactly 32 bytes.`,
    );
  }

  return {
    bytes,
    base64: bytesToBase64(bytes),
    hex: bytesToHex(bytes),
  };
}

function HomeScreen({}: HomeProps) {
  // Discord target configuration
  const [targetMode, setTargetMode] = useState<"webhook" | "bot">("webhook");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [botToken, setBotToken] = useState("");
  const [channelId, setChannelId] = useState("");
  const [note, setNote] = useState("KryptVault upload");

  // 256-bit vault key & backup state
  const [encryptBeforeUpload, setEncryptBeforeUpload] = useState(true);
  const [keySourceMode, setKeySourceMode] = useState<"generate" | "import">(
    "generate",
  );
  const [manualKeyInput, setManualKeyInput] = useState("");
  const [importedKeyFileName, setImportedKeyFileName] = useState<string | null>(
    null,
  );
  const [vaultKey, setVaultKey] = useState<GeneratedVaultKey | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [savedKeyConfirmed, setSavedKeyConfirmed] = useState(false);

  // Selected file & upload/download state
  const [selectedFile, setSelectedFile] = useState<DiscordFile | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [lastResult, setLastResult] = useState<UploadUiResult | null>(null);
  const [channelAttachments, setChannelAttachments] = useState<
    DiscordAttachment[]
  >([]);
  const [refreshedLinks, setRefreshedLinks] = useState<CdnLinkInfo[]>([]);
  const [decryptedSummary, setDecryptedSummary] = useState<string | null>(null);

  function buildTarget(): DiscordTarget | null {
    if (targetMode === "webhook") {
      const trimmed = webhookUrl.trim();
      if (!trimmed) {
        Alert.alert("Missing Webhook", "Enter a Discord Webhook URL first.");
        return null;
      }
      return { webhookUrl: trimmed };
    }

    const token = botToken.trim();
    const chId = channelId.trim();
    if (!token || !chId) {
      Alert.alert(
        "Missing Bot Details",
        "Enter both a Discord Bot Token and Channel ID.",
      );
      return null;
    }
    return { botToken: token, channelId: chId };
  }

  async function handlePickFile() {
    try {
      const res = await DocumentPicker.getDocumentAsync({
        copyToCacheDirectory: true,
        multiple: false,
      });
      if (res.canceled || !res.assets?.length) return;
      const asset = res.assets[0];
      setSelectedFile({
        uri: asset.uri,
        name: asset.name,
        mimeType: asset.mimeType ?? "application/octet-stream",
      });
      setDecryptedSummary(null);
    } catch (err) {
      Alert.alert(
        "File Picker Error",
        err instanceof Error ? err.message : "Could not pick file.",
      );
    }
  }

  function handleGenerateKey() {
    try {
      const generated = generateVaultSeedKey();
      setVaultKey(generated);
      setImportedKeyFileName(null);
      setShowKey(true);
      setSavedKeyConfirmed(false);
    } catch (err) {
      Alert.alert(
        "Key Generation Failed",
        err instanceof Error
          ? err.message
          : "Crypto API unavailable. Initialize a polyfill first.",
      );
    }
  }

  function handleApplyManualKey() {
    try {
      const parsed = parse256BitKeyInput(manualKeyInput);
      setVaultKey(parsed);
      setImportedKeyFileName(null);
      setShowKey(true);
      setSavedKeyConfirmed(true);
      Alert.alert("Key Loaded", "256-bit vault key loaded from input.");
    } catch (err) {
      Alert.alert(
        "Invalid Vault Key",
        err instanceof Error ? err.message : "Could not parse 256-bit key.",
      );
    }
  }

  async function handleUploadKeyFile() {
    try {
      const res = await DocumentPicker.getDocumentAsync({
        copyToCacheDirectory: true,
        multiple: false,
      });
      if (res.canceled || !res.assets?.length) return;
      const asset = res.assets[0];

      const { data: buffer } = await axios.get<ArrayBuffer>(asset.uri, {
        responseType: "arraybuffer",
      });
      const bytes = new Uint8Array(buffer);

      let parsed: GeneratedVaultKey;
      if (bytes.byteLength === 32) {
        parsed = {
          bytes,
          base64: bytesToBase64(bytes),
          hex: bytesToHex(bytes),
        };
      } else {
        const text = new TextDecoder().decode(bytes);
        parsed = parse256BitKeyInput(text);
        setManualKeyInput(text.trim());
      }

      setVaultKey(parsed);
      setImportedKeyFileName(asset.name);
      setShowKey(true);
      setSavedKeyConfirmed(true);
      Alert.alert(
        "Key File Loaded",
        `Loaded 256-bit key from "${asset.name}".`,
      );
    } catch (err) {
      Alert.alert(
        "Key File Error",
        err instanceof Error ? err.message : "Could not read 256-bit key file.",
      );
    }
  }

  async function handleCopyValue(label: string, value: string) {
    await Clipboard.setStringAsync(value);
    Alert.alert("Copied", `${label} copied to clipboard.`);
  }

  async function handleUpload() {
    const target = buildTarget();
    if (!target) return;

    if (!selectedFile) {
      Alert.alert("No File Selected", "Pick a file before uploading.");
      return;
    }

    setIsBusy(true);
    setDecryptedSummary(null);

    try {
      if (encryptBeforeUpload) {
        let activeKey = vaultKey;
        if (!activeKey && keySourceMode === "import" && manualKeyInput.trim()) {
          activeKey = parse256BitKeyInput(manualKeyInput);
          setVaultKey(activeKey);
          setSavedKeyConfirmed(true);
        }

        if (!activeKey) {
          Alert.alert(
            "Vault Key Required",
            "Generate a 256-bit vault key or paste/upload an existing one first.",
          );
          return;
        }
        if (!savedKeyConfirmed) {
          Alert.alert(
            "Confirm Key Backup",
            "Please check that you have saved your 256-bit vault key before uploading.",
          );
          return;
        }
        const result = await encryptAndUploadFileInChunks(
          target,
          selectedFile,
          activeKey.bytes,
          note || undefined,
          CHUNK_SIZE_BYTES,
        );
        setLastResult({
          ...result,
          wasEncrypted: true,
        });
      } else {
        const plainResult = await uploadFileInChunks(
          target,
          selectedFile,
          note || undefined,
          CHUNK_SIZE_BYTES,
        );
        setLastResult({
          ...plainResult,
          wasEncrypted: false,
          encryption: {
            algorithm: "AES-GCM",
            keyDerivation: "raw-256-bit",
            ivBase64: "",
            originalSize: plainResult.totalSize,
            encryptedSize: plainResult.totalSize,
          },
        });
      }

      Alert.alert("Upload Complete", "File uploaded to Discord.");
    } catch (err) {
      Alert.alert(
        "Upload Failed",
        err instanceof Error ? err.message : "Unknown upload error.",
      );
    } finally {
      setIsBusy(false);
    }
  }

  async function handleFetchChannelFiles() {
    if (!botToken.trim() || !channelId.trim()) {
      Alert.alert(
        "Bot Required",
        "Reading channel messages requires a Bot Token and Channel ID.",
      );
      return;
    }

    setIsBusy(true);
    try {
      const files = await fetchChannelFiles(
        botToken.trim(),
        channelId.trim(),
        20,
      );
      setChannelAttachments(files);
    } catch (err) {
      Alert.alert(
        "Fetch Failed",
        err instanceof Error ? err.message : "Could not fetch channel files.",
      );
    } finally {
      setIsBusy(false);
    }
  }

  async function handleRefreshCdnLinks() {
    if (!botToken.trim() || !channelId.trim()) {
      Alert.alert(
        "Bot Required",
        "Refreshing CDN links requires a Bot Token and Channel ID.",
      );
      return;
    }

    const messageIds =
      lastResult?.chunks
        .map((c) => c.message?.id)
        .filter((id): id is string => Boolean(id)) ?? [];

    if (messageIds.length === 0) {
      Alert.alert(
        "No Message IDs",
        "Upload a file first so message IDs are available to refresh.",
      );
      return;
    }

    setIsBusy(true);
    try {
      const links = await refreshCdnLinksForMessages(
        botToken.trim(),
        channelId.trim(),
        messageIds,
      );
      setRefreshedLinks(links);
    } catch (err) {
      Alert.alert(
        "Refresh Failed",
        err instanceof Error ? err.message : "Could not refresh CDN links.",
      );
    } finally {
      setIsBusy(false);
    }
  }

  async function handleDownloadAndDecryptLastUpload() {
    if (!lastResult || lastResult.attachments.length === 0) {
      Alert.alert("Nothing to Download", "No uploaded attachments found.");
      return;
    }

    setIsBusy(true);
    try {
      const buffers: ArrayBuffer[] = [];
      for (const att of lastResult.attachments) {
        const buf = await downloadAttachment(att);
        buffers.push(buf);
      }

      if (!lastResult.wasEncrypted) {
        const total = buffers.reduce((sum, b) => sum + b.byteLength, 0);
        setDecryptedSummary(
          `Downloaded ${buffers.length} plain chunk(s), total ${formatBytes(total)}.`,
        );
        return;
      }

      let activeKey = vaultKey;
      if (!activeKey && manualKeyInput.trim()) {
        activeKey = parse256BitKeyInput(manualKeyInput);
        setVaultKey(activeKey);
      }

      if (!activeKey?.bytes) {
        Alert.alert(
          "Missing Vault Key",
          "Generate, paste, or upload the matching 256-bit vault key to decrypt.",
        );
        return;
      }

      const decryptedBuf = await decryptChunksToBuffer(
        buffers,
        activeKey.bytes,
        lastResult.encryption,
      );
      setDecryptedSummary(
        `Decrypted "${lastResult.fileName}" (${formatBytes(decryptedBuf.byteLength)}) successfully.`,
      );
    } catch (err) {
      Alert.alert(
        "Download / Decrypt Failed",
        err instanceof Error ? err.message : "Decryption or download error.",
      );
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <ScrollView
      className="flex-1 bg-neutral-950"
      contentContainerClassName="p-4 pb-12 gap-4"
      keyboardShouldPersistTaps="handled"
    >
      {/* Header */}
      <View className="pt-2">
        <Text className="text-2xl font-bold text-white">KryptVault</Text>
        <Text className="text-sm text-neutral-400">
          AES-256-GCM 256-bit vault key + 20 MB Discord chunked uploads
        </Text>
      </View>

      {/* 1. Target Mode Card */}
      <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-3">
        <Text className="text-base font-semibold text-white">
          1. Discord Target
        </Text>

        <View className="flex-row gap-2">
          <Pressable
            onPress={() => setTargetMode("webhook")}
            className={`flex-1 rounded-xl py-2.5 items-center border ${
              targetMode === "webhook"
                ? "bg-indigo-600 border-indigo-500"
                : "bg-neutral-800 border-neutral-700"
            }`}
          >
            <Text className="text-sm font-semibold text-white">
              Webhook (Send)
            </Text>
          </Pressable>
          <Pressable
            onPress={() => setTargetMode("bot")}
            className={`flex-1 rounded-xl py-2.5 items-center border ${
              targetMode === "bot"
                ? "bg-indigo-600 border-indigo-500"
                : "bg-neutral-800 border-neutral-700"
            }`}
          >
            <Text className="text-sm font-semibold text-white">
              Bot (Read + Send)
            </Text>
          </Pressable>
        </View>

        {targetMode === "webhook" ? (
          <TextInput
            value={webhookUrl}
            onChangeText={setWebhookUrl}
            placeholder="https://discord.com/api/webhooks/..."
            placeholderTextColor="#737373"
            autoCapitalize="none"
            className="rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm text-white"
          />
        ) : (
          <View className="gap-2.5">
            <TextInput
              value={botToken}
              onChangeText={setBotToken}
              placeholder="Discord Bot Token"
              placeholderTextColor="#737373"
              secureTextEntry
              autoCapitalize="none"
              className="rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm text-white"
            />
            <TextInput
              value={channelId}
              onChangeText={setChannelId}
              placeholder="Channel ID (e.g. 123456789012345678)"
              placeholderTextColor="#737373"
              keyboardType="number-pad"
              className="rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm text-white"
            />
          </View>
        )}

        <TextInput
          value={note}
          onChangeText={setNote}
          placeholder="Optional message note"
          placeholderTextColor="#737373"
          className="rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm text-white"
        />
      </View>

      {/* 2. 256-Bit Vault Key (Generate or Upload/Paste) */}
      <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-3">
        <View className="flex-row items-center justify-between">
          <Text className="text-base font-semibold text-white">
            2. 256-Bit Vault Key
          </Text>
          <Pressable
            onPress={() => setEncryptBeforeUpload((prev) => !prev)}
            className={`rounded-full px-3 py-1 border ${
              encryptBeforeUpload
                ? "bg-emerald-950 border-emerald-600"
                : "bg-neutral-800 border-neutral-700"
            }`}
          >
            <Text
              className={`text-xs font-semibold ${
                encryptBeforeUpload ? "text-emerald-300" : "text-neutral-300"
              }`}
            >
              {encryptBeforeUpload ? "AES-256-GCM ON" : "PLAIN UPLOAD"}
            </Text>
          </Pressable>
        </View>

        {encryptBeforeUpload && (
          <View className="gap-3 rounded-xl border border-amber-700/50 bg-amber-950/25 p-3">
            <Text className="text-xs font-semibold text-amber-300">
              Choose How to Provide Your 256-Bit Vault Key
            </Text>

            <View className="flex-row gap-2">
              <Pressable
                onPress={() => setKeySourceMode("generate")}
                className={`flex-1 rounded-xl py-2 items-center border ${
                  keySourceMode === "generate"
                    ? "bg-amber-500 border-amber-400"
                    : "bg-neutral-800 border-neutral-700"
                }`}
              >
                <Text
                  className={`text-xs font-bold ${
                    keySourceMode === "generate"
                      ? "text-neutral-950"
                      : "text-white"
                  }`}
                >
                  Generate Key
                </Text>
              </Pressable>
              <Pressable
                onPress={() => setKeySourceMode("import")}
                className={`flex-1 rounded-xl py-2 items-center border ${
                  keySourceMode === "import"
                    ? "bg-amber-500 border-amber-400"
                    : "bg-neutral-800 border-neutral-700"
                }`}
              >
                <Text
                  className={`text-xs font-bold ${
                    keySourceMode === "import"
                      ? "text-neutral-950"
                      : "text-white"
                  }`}
                >
                  Upload / Paste Key
                </Text>
              </Pressable>
            </View>

            {keySourceMode === "generate" ? (
              <View className="gap-2.5">
                <Text className="text-xs text-neutral-300">
                  Losing this 256-bit key means permanent data loss for files
                  encrypted with it. Save it separately from your Discord
                  credentials.
                </Text>
                <Pressable
                  onPress={handleGenerateKey}
                  className="rounded-xl bg-amber-500 py-2.5 items-center"
                >
                  <Text className="text-xs font-bold text-neutral-950">
                    {vaultKey
                      ? "Generate New 256-Bit Key"
                      : "Generate 256-Bit Key"}
                  </Text>
                </Pressable>
              </View>
            ) : (
              <View className="gap-2.5">
                <Pressable
                  onPress={handleUploadKeyFile}
                  disabled={isBusy}
                  className="rounded-xl bg-amber-500 py-2.5 items-center"
                >
                  <Text className="text-xs font-bold text-neutral-950">
                    Upload Key File (.key / .txt / .json / 32B)
                  </Text>
                </Pressable>

                {importedKeyFileName && (
                  <Text className="text-xs text-emerald-300">
                    Loaded file: {importedKeyFileName}
                  </Text>
                )}

                <TextInput
                  value={manualKeyInput}
                  onChangeText={setManualKeyInput}
                  placeholder="Or paste 256-bit key (Base64 or 64-char hex)"
                  placeholderTextColor="#737373"
                  autoCapitalize="none"
                  className="rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 text-xs font-mono text-white"
                />

                <Pressable
                  onPress={handleApplyManualKey}
                  disabled={isBusy}
                  className="rounded-xl border border-neutral-600 bg-neutral-800 py-2 items-center"
                >
                  <Text className="text-xs font-semibold text-white">
                    Use Pasted Key
                  </Text>
                </Pressable>
              </View>
            )}

            {vaultKey && (
              <View className="gap-2 pt-1">
                <View className="rounded-lg border border-neutral-700 bg-neutral-950 p-2.5">
                  <Text className="text-xs font-mono text-white">
                    {showKey
                      ? vaultKey.base64
                      : "•".repeat(Math.min(vaultKey.base64.length, 32))}
                  </Text>
                </View>

                <View className="flex-row gap-2">
                  <Pressable
                    onPress={() => setShowKey((prev) => !prev)}
                    className="flex-1 rounded-lg border border-neutral-700 bg-neutral-800 py-2 items-center"
                  >
                    <Text className="text-xs font-semibold text-white">
                      {showKey ? "Hide Key" : "Show Key"}
                    </Text>
                  </Pressable>
                  <Pressable
                    onPress={() =>
                      handleCopyValue("Vault Key (Base64)", vaultKey.base64)
                    }
                    className="flex-1 rounded-lg border border-neutral-700 bg-neutral-800 py-2 items-center"
                  >
                    <Text className="text-xs font-semibold text-white">
                      Copy Base64
                    </Text>
                  </Pressable>
                </View>

                <Pressable
                  onPress={() => setSavedKeyConfirmed((prev) => !prev)}
                  className="flex-row items-center gap-2 pt-1"
                >
                  <View
                    className={`h-5 w-5 rounded border items-center justify-center ${
                      savedKeyConfirmed
                        ? "bg-emerald-500 border-emerald-400"
                        : "border-neutral-500 bg-neutral-950"
                    }`}
                  >
                    {savedKeyConfirmed && (
                      <Text className="text-xs font-bold text-neutral-950">
                        ✓
                      </Text>
                    )}
                  </View>
                  <Text className="flex-1 text-xs text-neutral-200">
                    I have saved this 256-bit key safely and understand it
                    cannot be recovered if lost.
                  </Text>
                </Pressable>
              </View>
            )}
          </View>
        )}
      </View>

      {/* 3. File Picker & Chunked Upload */}
      <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-3">
        <Text className="text-base font-semibold text-white">
          3. Select & Upload File (20 MB Chunks)
        </Text>

        <Pressable
          onPress={handlePickFile}
          disabled={isBusy}
          className="rounded-xl border border-neutral-700 bg-neutral-800 py-3 items-center"
        >
          <Text className="text-sm font-semibold text-white">
            {selectedFile ? "Change Selected File" : "Pick File from Device"}
          </Text>
        </Pressable>

        {selectedFile && (
          <View className="rounded-xl bg-neutral-950 border border-neutral-800 p-3 gap-1">
            <Text className="text-sm font-medium text-white">
              {selectedFile.name}
            </Text>
            <Text className="text-xs text-neutral-400">
              {selectedFile.mimeType ?? "application/octet-stream"}
            </Text>
          </View>
        )}

        <Pressable
          onPress={handleUpload}
          disabled={isBusy}
          className={`rounded-xl py-3.5 items-center ${
            isBusy ? "bg-indigo-900" : "bg-indigo-600"
          }`}
        >
          <Text className="text-sm font-bold text-white">
            {isBusy ? "Working..." : "Encrypt & Upload in 20 MB Blocks"}
          </Text>
        </Pressable>
      </View>

      {/* 4. Bot Read, CDN Refresh & Download/Decrypt */}
      <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-2.5">
        <Text className="text-base font-semibold text-white">
          4. Vault Read, CDN Refresh & Decrypt
        </Text>

        <View className="flex-row gap-2">
          <Pressable
            onPress={handleFetchChannelFiles}
            disabled={isBusy}
            className="flex-1 rounded-xl border border-neutral-700 bg-neutral-800 py-2.5 items-center"
          >
            <Text className="text-xs font-semibold text-white">
              List Channel Files
            </Text>
          </Pressable>
          <Pressable
            onPress={handleRefreshCdnLinks}
            disabled={isBusy}
            className="flex-1 rounded-xl border border-neutral-700 bg-neutral-800 py-2.5 items-center"
          >
            <Text className="text-xs font-semibold text-white">
              Refresh CDN Links
            </Text>
          </Pressable>
        </View>

        <Pressable
          onPress={handleDownloadAndDecryptLastUpload}
          disabled={isBusy || !lastResult}
          className={`rounded-xl py-2.5 items-center border ${
            lastResult
              ? "border-emerald-700 bg-emerald-950/60"
              : "border-neutral-800 bg-neutral-900"
          }`}
        >
          <Text className="text-xs font-semibold text-emerald-300">
            Download & Decrypt Last Upload
          </Text>
        </Pressable>

        {decryptedSummary && (
          <Text className="text-xs text-emerald-300">{decryptedSummary}</Text>
        )}
      </View>

      {/* 5. JSON Result & Metadata Output */}
      {lastResult && (
        <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-2.5">
          <View className="flex-row items-center justify-between">
            <Text className="text-base font-semibold text-white">
              Upload Result JSON
            </Text>
            <Pressable
              onPress={() =>
                handleCopyValue(
                  "Upload Metadata JSON",
                  JSON.stringify(lastResult, null, 2),
                )
              }
              className="rounded-lg border border-neutral-700 bg-neutral-800 px-3 py-1"
            >
              <Text className="text-xs font-semibold text-white">
                Copy JSON
              </Text>
            </Pressable>
          </View>

          <Text className="text-xs text-neutral-300">
            Chunks: {lastResult.totalChunks} (chunked:{" "}
            {String(lastResult.isChunked)}) • Encrypted:{" "}
            {formatBytes(lastResult.encryption.encryptedSize)}
          </Text>

          <ScrollView
            horizontal
            className="rounded-xl border border-neutral-800 bg-neutral-950 p-3"
          >
            <Text className="text-xs font-mono text-neutral-200">
              {JSON.stringify(lastResult, null, 2)}
            </Text>
          </ScrollView>
        </View>
      )}

      {/* Refreshed CDN Links */}
      {refreshedLinks.length > 0 && (
        <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-2">
          <Text className="text-sm font-semibold text-white">
            Refreshed CDN Links ({refreshedLinks.length})
          </Text>
          {refreshedLinks.map((item) => (
            <View
              key={item.attachmentId}
              className="rounded-xl border border-neutral-800 bg-neutral-950 p-2.5 gap-1"
            >
              <Text className="text-xs font-semibold text-white">
                {item.filename} ({formatBytes(item.size)})
              </Text>
              <Text className="text-xs text-neutral-400">
                Expires: {item.expiresAt ?? "Unknown"} • Expired:{" "}
                {String(item.isExpired)}
              </Text>
              <Text
                numberOfLines={1}
                className="text-xs font-mono text-indigo-300"
              >
                {item.url}
              </Text>
            </View>
          ))}
        </View>
      )}

      {/* Channel Attachments */}
      {channelAttachments.length > 0 && (
        <View className="rounded-2xl border border-neutral-800 bg-neutral-900 p-4 gap-2">
          <Text className="text-sm font-semibold text-white">
            Channel Attachments ({channelAttachments.length})
          </Text>
          {channelAttachments.map((att) => (
            <View
              key={att.id}
              className="rounded-xl border border-neutral-800 bg-neutral-950 p-2.5"
            >
              <Text className="text-xs font-medium text-white">
                {att.filename} • {formatBytes(att.size)}
              </Text>
            </View>
          ))}
        </View>
      )}
    </ScrollView>
  );
}

function RootNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Home"
      screenOptions={{ headerShown: false }}
    >
      <Stack.Screen name="Home" component={HomeScreen} />
    </Stack.Navigator>
  );
}

export default function App() {
  return (
    <AppProvider>
      <RootNavigator />
    </AppProvider>
  );
}
