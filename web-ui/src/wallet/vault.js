// CONFIDIS Vault — IndexedDB-backed Ed25519 signing-key store.
//
// The vault is the only place a CONFIDIS end-user's or operator's private key
// exists outside their hand-written BIP39 mnemonic. It is persisted as
// Argon2id-derived password-wrapped ciphertext; the plaintext key bytes appear
// only inside an in-memory "session handle" while the user is actively logged
// in.
//
// ## Storage schema
//
// We use a single IndexedDB database `confidis-vault` with one object store
// `vaults` keyed by `vaultId` (string, application-chosen). Each record has:
//
//   {
//     vaultId:       string,                 // primary key
//     role:          "end-user" | "operator",
//     publicKeyHex:  string,                 // Ed25519 public key, safe to leak
//     ciphertext:    Uint8Array,             // ChaCha20-Poly1305(seal(signing_key))
//     salt:          Uint8Array,             // 16 random bytes
//     kdfParams: {                            // Argon2id parameters used at seal
//       algo:        "argon2id",
//       memoryKib:   number,
//       iterations:  number,
//       parallelism: number,
//       outputLen:   number,
//     },
//     createdAt:     ISO 8601 string,
//     lastUnlockedAt: ISO 8601 string | null,
//   }
//
// The record is intentionally simple — version migrations are handled by an
// `onupgradeneeded` callback that bumps the database version.
//
// ## Session handle lifetime
//
// `unlockVault()` returns a `Session` object with:
//
//   - `vaultId`, `publicKeyHex`, `role`,
//   - `sign(messageBytes): Promise<string>`,
//   - `lock(): void`,
//   - `expiresAt: Date`.
//
// The signing-key hex is passed once to a dedicated `signingWorker.js` Web
// Worker and never returned to the main thread. `sign()` sends the payload
// bytes to the Worker and awaits the signature hex via postMessage. The session
// lifetime is bounded by `SESSION_IDLE_MS` (15 minutes, matching §14).
// After idle timeout `sign()` throws and the caller must re-unlock.

import { loadCrypto } from "./cryptoBridge";

const DB_NAME = "confidis-vault";
const DB_VERSION = 1;
const STORE_NAME = "vaults";
export const SESSION_IDLE_MS = 15 * 60 * 1000; // 15 minutes.

// --------------------------------------------------------------------------
// IndexedDB plumbing
// --------------------------------------------------------------------------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "vaultId" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("Échec de l’ouverture IndexedDB"));
  });
}

async function withStore(mode, action) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    let result;
    tx.oncomplete = () => {
      db.close();
      resolve(result);
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error("Échec de la transaction IndexedDB"));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error("Transaction IndexedDB interrompue"));
    };
    try {
      result = action(store);
    } catch (err) {
      tx.abort();
      reject(err);
    }
  });
}

function reqAsPromise(idbRequest) {
  return new Promise((resolve, reject) => {
    idbRequest.onsuccess = () => resolve(idbRequest.result);
    idbRequest.onerror = () => reject(idbRequest.error ?? new Error("Échec de la requête IndexedDB"));
  });
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

/**
 * Returns the list of vault records currently in IndexedDB, without sensitive
 * fields (no ciphertext). Used by the wallet landing screen to know whether a
 * vault already exists for the current browser/profile.
 */
export async function listVaults() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const req = store.getAll();
    req.onsuccess = () => {
      db.close();
      const rows = req.result ?? [];
      resolve(
        rows.map((r) => ({
          vaultId: r.vaultId,
          role: r.role,
          publicKeyHex: r.publicKeyHex,
          createdAt: r.createdAt,
          lastUnlockedAt: r.lastUnlockedAt,
        }))
      );
    };
    req.onerror = () => {
      db.close();
      reject(req.error ?? new Error("Échec de la liste des coffres"));
    };
  });
}

/**
 * Create a new vault.
 *
 * @param {Object} args
 * @param {"end-user" | "operator"} args.role
 * @param {string} args.vaultId          - caller-chosen primary key (e.g. "end-user-default").
 * @param {string} args.mnemonic         - 24-word BIP39 phrase.
 * @param {string} args.password         - user-chosen password.
 * @param {string} [args.bip39Passphrase] - optional additional passphrase mixed into BIP39 → seed.
 *
 * Returns `{ publicKeyHex }`. The signing key never leaves this function.
 *
 * Throws if `vaultId` already exists.
 */
export async function createVault({ role, vaultId, mnemonic, password, bip39Passphrase = "" }) {
  const crypto = await loadCrypto();

  if (!crypto.isMnemonicValid(mnemonic)) {
    throw new Error("phrase mnémonique invalide — vérifiez l’orthographe et le nombre de mots");
  }
  if (typeof password !== "string" || password.length < 8) {
    throw new Error("le mot de passe doit contenir au moins 8 caractères");
  }

  // 1. Derive signing key from mnemonic. Hex string — keep in closure scope only.
  const signingKeyHex = crypto.signingKeyFromMnemonic(mnemonic, bip39Passphrase);
  const publicKeyHex = crypto.verifyingKeyFromSigningKey(signingKeyHex);

  // 2. Seal the 32-byte signing key with password-derived Argon2id key.
  const signingKeyBytes = crypto.hexToBytes(signingKeyHex);
  const salt = crypto.generateVaultSalt();
  const passwordBytes = new TextEncoder().encode(password);
  const ciphertext = crypto.vaultSeal(passwordBytes, salt, signingKeyBytes);

  // 3. Persist. Conflict check is delegated to IndexedDB via `add()` which
  //    fails if the keyPath already exists.
  const record = {
    vaultId,
    role,
    publicKeyHex,
    ciphertext,
    salt,
    kdfParams: {
      algo: "argon2id",
      memoryKib: crypto.defaultArgon2MemoryKib(),
      iterations: crypto.defaultArgon2Iterations(),
      parallelism: crypto.defaultArgon2Parallelism(),
      outputLen: crypto.defaultArgon2OutputLen(),
    },
    createdAt: new Date().toISOString(),
    lastUnlockedAt: null,
  };

  await withStore("readwrite", (store) => reqAsPromise(store.add(record)));
  return { publicKeyHex };
}

/**
 * Unlock a vault by its `vaultId` and password. Returns a `Session` whose
 * `sign(messageBytes)` re-uses the unlocked key for at most `SESSION_IDLE_MS`
 * of idle time.
 *
 * On wrong password / tampered ciphertext the underlying WASM throws an opaque
 * decryption error — we re-wrap it so the caller cannot distinguish the two.
 */
export async function unlockVault({ vaultId, password }) {
  const crypto = await loadCrypto();
  const record = await withStore("readonly", (store) =>
    reqAsPromise(store.get(vaultId))
  );
  if (!record) {
    throw new Error("coffre introuvable");
  }

  const passwordBytes = new TextEncoder().encode(password);
  let signingKeyBytes;
  try {
    signingKeyBytes = crypto.vaultOpen(passwordBytes, record.salt, record.ciphertext);
  } catch {
    // Intentionally generic: do not distinguish wrong-password from tampered ciphertext.
    throw new Error("impossible de déverrouiller le coffre");
  }
  const signingKeyHex = crypto.bytesToHex(signingKeyBytes);
  // Overwrite the decrypted bytes immediately; signingKeyHex is the last
  // reference that stays alive (inside the Worker after the next line).
  signingKeyBytes.fill(0);

  // Spin up a dedicated Worker that will hold the key in isolation. The main
  // thread passes `signingKeyHex` to the Worker and then forgets it.
  const worker = new Worker(
    new URL("./signingWorker.js", import.meta.url),
    { type: "module" }
  );

  // Wait for the Worker's WASM module to finish loading before we hand over
  // the key. This avoids a race where a sign() arrives before init() completes.
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("le worker de signature n’a pas été prêt à temps")),
      15_000
    );
    worker.onmessage = (e) => {
      if (e.data.type === "ready") {
        clearTimeout(timeout);
        resolve();
      } else if (e.data.type === "error" && e.data.id === "__init__") {
        clearTimeout(timeout);
        reject(new Error(`échec d’initialisation du worker de signature : ${e.data.message}`));
      }
    };
    worker.onerror = (e) => {
      clearTimeout(timeout);
      reject(new Error(e.message || "erreur du worker de signature"));
    };
  });

  // Transfer the key into the Worker. After this postMessage the main thread
  // drops its last reference; GC can reclaim it.
  worker.postMessage({ type: "unlock", signingKeyHex });

  // Pending sign() calls indexed by a per-request UUID.
  const pendingMap = new Map();

  worker.onmessage = (e) => {
    const msg = e.data;
    if (msg.type !== "signed" && msg.type !== "error") return;
    const pending = pendingMap.get(msg.id);
    if (!pending) return;
    pendingMap.delete(msg.id);
    if (msg.type === "signed") pending.resolve(msg.signature);
    else pending.reject(new Error(msg.message));
  };

  let lastActivity = Date.now();
  let locked = false;

  // Update `lastUnlockedAt` best-effort. Failure is non-fatal.
  withStore("readwrite", (store) => {
    record.lastUnlockedAt = new Date().toISOString();
    return reqAsPromise(store.put(record));
  }).catch(() => {});

  const session = {
    vaultId,
    role: record.role,
    publicKeyHex: record.publicKeyHex,

    async sign(messageBytes) {
      if (locked) {
        throw new Error("session verrouillée — déverrouillez à nouveau le coffre pour signer");
      }
      const idleFor = Date.now() - lastActivity;
      if (idleFor > SESSION_IDLE_MS) {
        session.lock();
        throw new Error("session expirée — déverrouillez à nouveau le coffre pour signer");
      }
      lastActivity = Date.now();
      const id = globalThis.crypto.randomUUID();
      return new Promise((resolve, reject) => {
        pendingMap.set(id, { resolve, reject });
        worker.postMessage({ type: "sign", id, payload: messageBytes });
      });
    },

    lock() {
      if (locked) return;
      locked = true;
      worker.postMessage({ type: "lock" });
      // Reject any in-flight sign() calls so they do not hang.
      for (const p of pendingMap.values()) {
        p.reject(new Error("session verrouillée"));
      }
      pendingMap.clear();
      // Terminate the Worker; the OS reclaims its memory.
      worker.terminate();
    },

    get expiresAt() {
      return new Date(lastActivity + SESSION_IDLE_MS);
    },
    get isLocked() {
      return locked;
    },
  };
  return session;
}

/**
 * Permanently delete a vault from IndexedDB. The mnemonic remains the only
 * recovery path; this action cannot be undone from the wallet UI.
 */
export async function wipeVault(vaultId) {
  await withStore("readwrite", (store) => reqAsPromise(store.delete(vaultId)));
}

/**
 * Test helper: delete the entire vault database. Not exposed in the
 * production UI; useful for development/testing only.
 */
export async function _wipeAllVaultsUnsafe() {
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error("échec de suppression de la base locale"));
    req.onblocked = () => reject(new Error("suppression de la base locale bloquée"));
  });
}
