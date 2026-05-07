## 🌐 Live Interactive Demo

**Try the full CQRCrypto Level‑5 system right in your browser – no server, no installation:**  
👉 **[https://m-z-developer.github.io/CQRCrypto/](https://m-z-developer.github.io/CQRCrypto/)**

The demo lets you generate quantum‑safe identities, sign messages, create DID documents, encrypt/decrypt secret payloads, and verify signatures – all client‑side using the same library you can embed in your own projects.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](./LICENSE) file for details.  
© 2026 M‑Z‑Developer.xmr

---

## 📖 What is CQRCrypto Level 5?

CQRCrypto is a **pure JavaScript** library (and companion offline web app) that implements the highest NIST‑standardised post‑quantum cryptographic algorithms:

- **ML‑DSA‑87** (FIPS 204) – Module Lattice Digital Signature Algorithm, security category 5
- **ML‑KEM‑1024** (FIPS 203) – Module Lattice Key Encapsulation Mechanism, security category 5

All symmetric operations use **AES‑256‑GCM** and key derivation uses **PBKDF2‑SHA512 with 600,000 iterations**.  
The entire library has **zero external dependencies** and runs in any modern browser or Node.js environment straight from the source file.

### Why “Level 5”?

NIST defines five security levels for post‑quantum algorithms. Level 5 is the strongest, comparable to AES‑256 in the quantum era. CQRCrypto exclusively uses Level‑5 constructions, making it suitable for:

- Top‑secret government / military communication
- Long‑term identity management (DIDs)
- Satellite, radio, and air‑gapped systems
- Offline signing and quantum‑resistant key exchange

---

## ✨ Features

- **Pure JavaScript** – No WebAssembly, no native modules, no bundler required
- **ML‑DSA‑87 signatures** – Verifyable, short (post‑quantum) signatures
- **ML‑KEM‑1024 key encapsulation** – Shared secret generation for hybrid encryption
- **AES‑256‑GCM authenticated encryption** – Encrypt any payload with the derived quantum‑safe shared key
- **PBKDF2‑SHA512 (600k rounds)** – Encrypt your identity file with a strong passphrase
- **CQR packed keys** – Combines ML‑DSA and ML‑KEM keys into a single base64url string
- **Canonical JSON signing** – Reproducible hashing for DID documents and data integrity proofs
- **Browser & Node.js** – Use `<script src="CQRCrypto.js"></script>` or `require()`
- **Air‑gapped ready** – No network calls, perfect for offline devices

---

## 📦 Quick Start

### 1. Include the library

**Browser**
```html
<script src="./CQRCrypto.js"></script>
<script>
  const cqr = new CQRCrypto();
  // ...
</script>
```

**Node.js**
```javascript
const { CQRCrypto } = require('./CQRCrypto.js');
const cqr = new CQRCrypto();
```

### 2. Generate a Level‑5 identity

```javascript
const identity = cqr.generateIdentity();
console.log(identity.cqrPublicKey);   // Give this to your contacts
console.log(identity.cqrPrivateKey);  // Keep this absolutely secret!
```

### 3. Sign a message

```javascript
const signed = cqr.signMessage('Hello, quantum world!', identity.cqrPrivateKey);
// signed contains { system, type, content, signatureBase64url }
```

### 4. Encrypt a secret message for a recipient

```javascript
const encrypted = await cqr.encryptSecretMessage(
  'Top secret data',
  recipientPublicKey,                // Receiver's CQR public key
  identity.cqrPrivateKey             // Your private key (for signing)
);
// encrypted contains { encapsulatedKey, iv, ciphertext }
```

### 5. Decrypt and verify a secret message

```javascript
const result = await cqr.decryptSecretMessage(
  encrypted,                         // The received JSON payload
  senderPublicKey,                   // Sender's CQR public key
  myPrivateKey                       // Your private key
);
if (result.isValid) {
  console.log('Secure message:', result.message);
}
```

### 6. Encrypt your identity to a file (secure export)

```javascript
const encryptedFile = await cqr.encryptIdentity(
  { cqrPrivateKey, cqrPublicKey },
  'MyStr0ngP@ssphr@se!'
);
// Save `encryptedFile` as JSON – only the passphrase can unlock it
```

### 7. Load and decrypt your identity from the file

```javascript
const keys = await cqr.decryptIdentity(encryptedFile, 'MyStr0ngP@ssphr@se!');
// keys.cqrPrivateKey and keys.cqrPublicKey are ready to use
```

---

## 🔐 API Reference

### `CQRCrypto` constructor

```javascript
const cqr = new CQRCrypto();
```

Instantiates the library and exposes the underlying `dsa` and `kem` engines if needed.

#### Identity Management
- **`generateIdentity()`** → `{ cqrPrivateKey, cqrPublicKey, raw }`  
  Creates a new random CQR identity (ML-DSA-87 + ML-KEM-1024). The `raw` object contains the separate key buffers.

- **`packCQRKeys(dsaKeyBytes, kemKeyBytes)`** → `Uint8Array`  
- **`unpackCQRKeys(buffer)`** → `{ dsaKey, kemKey }`  
  Low-level routines that combine/split the two keys into a single binary format.

#### Cleartext Signing & Verification
- **`signMessage(text, senderPrivateKey)`** → `{ system, type, content, signatureBase64url }`  
  Signs a plain text message.

- **`signDID(didId, serviceEndpoint, senderPrivateKey, senderPublicKey)`** → signed DID document  
  Creates and signs a W3C-compatible DID document with a `CQRDataIntegrityProof`.

- **`verifyCleartextMessage(parsedDoc, senderPublicKey)`** → `boolean`  
  Verifies either a `StandardMessage` or a signed DID document.

#### Encrypted (Secret) Messages
- **`async encryptSecretMessage(text, receiverPublicKey, senderPrivateKey)`** → `{ encapsulatedKey, iv, ciphertext }`  
  Encrypts and signs a message for a specific recipient. Internally:  
  1. Signs the plaintext with sender’s ML-DSA key.  
  2. Encapsulates a shared secret using the receiver’s ML-KEM‑1024 public key.  
  3. Encrypts the inner payload (message + signature) with AES‑256‑GCM.

- **`async decryptSecretMessage(parsedDoc, senderPublicKey, receiverPrivateKey)`** → `{ isValid, message }`  
  Reverses the process: decapsulates the shared secret, decrypts the payload, and verifies the sender’s signature. Throws descriptive errors on failure.

#### Secure Storage (AES‑256‑GCM + PBKDF2‑SHA512)
- **`async encryptIdentity(keysObj, password)`** → encrypted JSON object  
- **`async decryptIdentity(encryptedObj, password)`** → original keys object  
  Password‑based encryption of the full identity file using PBKDF2‑SHA512 (600,000 rounds) and AES‑256‑GCM. The output is safe to store in a file or database.

#### Low‑Level AES‑GCM Helpers
- **`async encryptAESGCM(sharedSecret, payloadBytes)`** → `{ iv, ciphertext }`  
- **`async decryptAESGCM(sharedSecret, iv, ciphertext)`** → plaintext `Uint8Array`  
  Direct symmetric encryption using a 32‑byte key (from ML‑KEM or other source).

---

## 🧪 Live Demo (Web Interface)

The included `index.html` is a fully offline, bilingual (English / العربية) interface that wraps the library. It runs entirely in the browser and requires no build step.

**Open the live version here:** [https://m-z-developer.github.io/CQRCrypto/](https://m-z-developer.github.io/CQRCrypto/)

Key capabilities of the demo:
- Generate / import quantum‑resistant identities
- Encrypt identity file with password rules (length, numbers, symbols, emoji)
- Three transmission modes: cleartext message, encrypted message, DID document
- Copy & paste payloads for verification / decryption
- Real‑time signature and decryption feedback
- Language toggle: English ⇄ العربية

---

## 🧱 Architecture & Security

```
┌─────────────────────────────────────┐
│         CQRCrypto (Public API)      │
├─────────────────────────────────────┤
│  ML‑DSA‑87  │  ML‑KEM‑1024  │  AES  │
│  (sign)     │  (encapsulate) │  GCM  │
├─────────────────────────────────────┤
│         SHA‑3 / SHAKE (Noble)       │
│         Internal KDF & PRF         │
└─────────────────────────────────────┘
```

- **ML‑DSA‑87** and **ML‑KEM‑1024** are implemented in pure JavaScript following the FIPS standards.
- Cryptographic randomness is sourced from `crypto.getRandomValues()` (browser) or Node’s `crypto` module.
- All intermediate buffers are securely zeroed after use.
- The CQR packed key format embeds a version byte (`2` for Level 5) to prevent accidental misuse of other security levels.
- The library is deliberately **single‑file** and **dependency‑free**, making it auditable and deployable in air‑gapped environments.

> **⚠️ Important:** This library has not been formally audited against side-channel attacks. It is however built according to NIST’s reference implementations for ML‑DSA and ML‑KEM. Use at your own risk for production military systems; always combine it with hardware security modules (HSM) if available.

---

## 🔬 Testing & Validation

The library passes round‑trip test vectors for:
- ML‑DSA‑87 key generation, signing, and verification
- ML‑KEM‑1024 key generation, encapsulation, and decapsulation
- AES‑256‑GCM encryption/decryption
- PBKDF2‑SHA512 key derivation
- CQR key packing / unpacking

To run a quick smoke test in your browser’s console:

```javascript
const cqr = new CQRCrypto();
const id = cqr.generateIdentity();
const signed = cqr.signMessage('Test', id.cqrPrivateKey);
const ok = cqr.verifyCleartextMessage(signed, id.cqrPublicKey);
console.assert(ok, 'Self‑verification failed!');
console.log('✅ Internal Test Passed');
```

---

## 🛠️ Developer

Developed by **M‑Z‑Developer.xmr**  
GitHub: [https://github.com/M-Z-Developer](https://github.com/M-Z-Developer)

---

## 📄 License

MIT License – see [LICENSE](./LICENSE) for full text.

---


<br/>

# CQRCrypto بالعربية

## 🌐 معاينة تفاعلية مباشرة

جرب النظام بالكامل في متصفحك دون تثبيت:  
👇
**[https://m-z-developer.github.io/CQRCrypto/](https://m-z-developer.github.io/CQRCrypto/)**

---

## 📖 ما هي مكتبة CQRCrypto Level 5؟

**CQRCrypto** هي مكتبة JavaScript نقية (مع تطبيق ويب تفاعلي مرفق) تنفذ أقوى خوارزميات التشفير ما بعد الكمي المعتمدة من NIST:

- **ML‑DSA‑87** (التوقيع الرقمي الآمن بعد الكمي – مستوى الأمان 5)
- **ML‑KEM‑1024** (آلية تغليف المفتاح – مستوى الأمان 5)

جميع العمليات المتماثلة تستخدم **AES‑256‑GCM**، واشتقاق المفاتيح يستخدم **PBKDF2‑SHA512 مع 600,000 تكرار**. المكتبة **لا تعتمد على أي مكتبات خارجية** وتعمل في أي متصفح حديث أو بيئة Node.js مباشرة.

### لماذا المستوى 5؟

يُعرِّف NIST خمسة مستويات أمان لخوارزميات ما بعد الكمية. المستوى الخامس هو الأعلى ويكافئ AES‑256 في العصر الكمي. تستخدم CQRCrypto هذا المستوى حصرياً مما يجعلها مناسبة لـ:

- الاتصالات الحكومية / العسكرية فائقة السرية
- إدارة الهويات الرقمية طويلة الأمد (DID)
- الأقمار الصناعية وأجهزة الاتصال المعزولة (air‑gapped)
- التوقيع دون اتصال وتبادل المفاتيح المقاوم للكمبيوتر الكمي

---

## ✨ الميزات

- **JavaScript نقي** – بدون WebAssembly أو وحدات محلية
- **توقيع ML‑DSA‑87** – توقيعات قصيرة قابلة للتحقق
- **تغليف مفاتيح ML‑KEM‑1024** – إنتاج أسرار مشتركة للتشفير الهجين
- **تشفير AES‑256‑GCM** – تشفير أي حمولة بالمفتاح المشترك الكمي
- **PBKDF2‑SHA512 (600 ألف جولة)** – تشفير ملف الهوية بكلمة مرور قوية
- **مفاتيح CQR مدمجة** – دمج مفتاحي التوقيع والتشفير في نص base64url واحد
- **توقيع JSON القياسي** – تجزئة قابلة للتكرار لتوقيع وثائق الهوية
- **دعم المتصفح و Node.js**
- **جاهز للأجهزة المعزولة** – لا اتصال بالشبكة

---

## 📦 البداية السريعة

### 1. تضمين المكتبة

**المتصفح**
```html
<script src="./CQRCrypto.js"></script>
<script>
  const cqr = new CQRCrypto();
</script>
```

**Node.js**
```javascript
const { CQRCrypto } = require('./CQRCrypto.js');
const cqr = new CQRCrypto();
```

### 2. توليد هوية من المستوى 5

```javascript
const identity = cqr.generateIdentity();
console.log(identity.cqrPublicKey);   // يُعطى لجهات الاتصال
console.log(identity.cqrPrivateKey);  // سري للغاية!
```

### 3. توقيع رسالة

```javascript
const signed = cqr.signMessage('مرحباً بالعالم الكمي', identity.cqrPrivateKey);
```

### 4. تشفير رسالة سرية لمستلم

```javascript
const encrypted = await cqr.encryptSecretMessage(
  'بيانات بالغة السرية',
  recipientPublicKey,
  identity.cqrPrivateKey
);
```

### 5. فك تشفير الرسالة السرية والتحقق منها

```javascript
const result = await cqr.decryptSecretMessage(
  encrypted,
  senderPublicKey,
  myPrivateKey
);
if (result.isValid) console.log('الرسالة الأصلية:', result.message);
```

### 6. تصدير الهوية بشكل آمن

```javascript
const encryptedFile = await cqr.encryptIdentity(
  { cqrPrivateKey, cqrPublicKey },
  'كلمة_مرور_قوية@123'
);
// احفظ encryptedFile بصيغة JSON
```

### 7. استيراد الهوية من الملف المشفر

```javascript
const keys = await cqr.decryptIdentity(encryptedFile, 'كلمة_مرور_قوية@123');
```

---

## 🔐 دليل API الكامل

مطابق تقريباً للنسخة الإنجليزية أعلاه. جميع التواقيع والوظائف متاحة باللغتين مع نفس الأسماء البرمجية.

---

## 🧪 الواجهة الحية (التطبيق العملي)

ملف `index.html` المرفق هو واجهة مستخدم كاملة **بدون اتصال بالإنترنت** تدعم العربية والإنجليزية. كل شيء يعمل محلياً في المتصفح.

**افتح النسخة الحية:** [https://m-z-developer.github.io/CQRCrypto/](https://m-z-developer.github.io/CQRCrypto/)

الوظائف الرئيسية:
- توليد الهويات الكمومية واستيرادها
- تشفير ملف الهوية بكلمة مرور ذات قواعد أمان صارمة
- ثلاثة أوضاع إرسال: رسالة عادية، رسالة مشفرة، وثيقة هوية DID
- نسخ ولصق الحزم للتحقق أو فك التشفير
- تغذية راجعة فورية للتوقيع وفك التشفير
- زر تبديل اللغة: العربية ⇄ English

---

## 🧱 الهندسة الأمنية

```
┌─────────────────────────────────────┐
│           CQRCrypto API             │
├─────────────────────────────────────┤
│  ML‑DSA‑87  │  ML‑KEM‑1024  │  AES  │
│  (توقيع)    │  (تغليف مفتاح) │  GCM  │
├─────────────────────────────────────┤
│         SHA‑3 / SHAKE               │
│         وظائف الاشتقاق الداخلية      │
└─────────────────────────────────────┘
```

- التنفيذ يعتمد على معايير FIPS 203 و FIPS 204 تماماً.
- العشوائية من `crypto.getRandomValues()` في المتصفحات.
- يتم تصفير جميع الذواكر المؤقتة بعد الاستخدام.
- صيغة المفتاح المدمج CQR تحتوي على بايت نسخة لمنع إساءة استخدام مستويات أخرى.

> **⚠️ تنبيه أمني:** لم تخضع المكتبة بعد لتدقيق مستقل ضد الهجمات الجانبية. استخدمها في الأنظمة العسكرية الفعلية مع وحدات أمان مادية (HSM) إن أمكن.

---

## 🛠️ المطور

**M‑Z‑Developer.xmr**  
GitHub: [https://github.com/M-Z-Developer](https://github.com/M-Z-Developer)

---

## 📄 الرخصة

MIT License – راجع ملف [LICENSE](./LICENSE) للتفاصيل.
```
