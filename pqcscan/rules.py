from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

SEVERITIES = ("low", "medium", "high", "critical")

KEM_FIX = (
    "Migrate key establishment to ML-KEM-768 (NIST FIPS 203); during the transition use a hybrid "
    "such as X25519MLKEM768. Data encrypted today can be recorded and decrypted later (harvest now, decrypt later)."
)
SIG_FIX = (
    "Migrate signatures to ML-DSA-65 (NIST FIPS 204), or SLH-DSA (FIPS 205) for long-lived roots of trust. "
    "Plan for hybrid or dual signatures where verifiers cannot upgrade at once."
)
RSA_FIX = "Replace RSA: use ML-KEM (FIPS 203) for encryption/key transport and ML-DSA (FIPS 204) for signatures."
ECC_FIX = "Replace elliptic-curve keys: use ML-KEM (FIPS 203) for key agreement and ML-DSA (FIPS 204) for signatures."
AES_FIX = "Use AES-256. Grover's algorithm halves effective symmetric key strength, leaving AES-128 with ~64-bit security."
HASH_FIX = "Use SHA-256 or stronger (SHA-384 / SHA3-384 for long-term integrity). MD5 and SHA-1 are already broken classically."
CIPHER_FIX = "Use AES-256-GCM or ChaCha20-Poly1305. DES, 3DES and RC4 are already broken classically."
DEP_FIX = "This library only offers quantum-vulnerable public-key algorithms. Plan a move to a library with ML-KEM / ML-DSA support (e.g. liboqs bindings, OpenSSL 3.5+, BoringSSL, Bouncy Castle)."
SSH_FIX = "Plan migration to post-quantum SSH: use the hybrid key exchange mlkem768x25519-sha256 (OpenSSH 9.9+) and track PQ signature support for host/user keys."
KEYFILE_FIX = "Remove private keys from source control and rotate them. Re-issue keys with ML-KEM / ML-DSA (or hybrid) when your PKI supports it."
CERT_FIX = "Plan re-issuance with ML-DSA (FIPS 204) or hybrid certificates; inventory which clients must support them first."

ALL = "*"


@dataclass
class Rule:
    id: str
    title: str
    family: str
    severity: str
    category: str
    threat: str
    recommendation: str
    patterns: dict[str, str] = field(default_factory=dict)
    algorithm: str | Callable[[re.Match], str] = ""
    compiled: dict[str, re.Pattern] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self.compiled = {lang: re.compile(p) for lang, p in self.patterns.items()}

    def algorithm_for(self, match: re.Match | None) -> str:
        if callable(self.algorithm):
            return self.algorithm(match)
        return self.algorithm

    def search(self, language: str, line: str) -> re.Match | None:
        for lang in (language, ALL):
            pattern = self.compiled.get(lang)
            if pattern:
                m = pattern.search(line)
                if m:
                    return m
        return None


def _ssh_algorithm(m: re.Match) -> str:
    kind = m.group(1)
    if kind == "ssh-rsa":
        return "RSA"
    if kind == "ssh-dss":
        return "DSA"
    if kind == "ssh-ed25519":
        return "Ed25519"
    return "ECDSA"


RULES: list[Rule] = [
    Rule(
        "PQC001", "RSA encryption / key transport", "RSA", "critical", "key-establishment", "Shor", RSA_FIX,
        {
            "python": r"PKCS1_OAEP|padding\.OAEP\(|\brsa\.encrypt\(|\.encrypt\([^)]*padding\.PKCS1v15",
            "javascript": r"publicEncrypt\(|privateDecrypt\(|[\"']RSA-OAEP|RSA_PKCS1_OAEP_PADDING",
            "go": r"rsa\.(EncryptOAEP|DecryptOAEP|EncryptPKCS1v15|DecryptPKCS1v15)\(",
            "java": r"Cipher\.getInstance\(\s*\"RSA",
            "c": r"RSA_(public|private)_(encrypt|decrypt)\(|RSA_PKCS1_OAEP_PADDING",
            "csharp": r"RSAEncryptionPadding\.",
            "ruby": r"\.(public|private)_(encrypt|decrypt)\(",
            "php": r"openssl_(public|private)_(encrypt|decrypt)\(",
            "rust": r"\bOaep::new|Pkcs1v15Encrypt",
        },
        "RSA",
    ),
    Rule(
        "PQC002", "RSA signature", "RSA", "high", "signature", "Shor", SIG_FIX,
        {
            ALL: r"[\"'](RS|PS)(256|384|512)[\"']",
            "python": r"pkcs1_15\.new\(|from Crypto\.Signature import (pkcs1_15|pss)|padding\.PSS\(|\brsa\.sign\(",
            "javascript": r"[\"']RSASSA-PKCS1-v1_5[\"']|[\"']RSA-PSS[\"']|createSign\(\s*[\"']RSA-",
            "go": r"rsa\.(SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)\(",
            "java": r"Signature\.getInstance\(\s*\"[^\"]*withRSA",
            "c": r"\bRSA_(sign|verify)\(",
            "csharp": r"RSASignaturePadding\.",
            "rust": r"rsa::(pkcs1v15::SigningKey|pss::)",
        },
        "RSA",
    ),
    Rule(
        "PQC003", "RSA key usage", "RSA", "high", "public-key", "Shor", RSA_FIX,
        {
            "python": r"rsa\.generate_private_key\(|RSA\.(generate|import_key|importKey)\(|\brsa\.newkeys\(|from Crypto(dome)?\.PublicKey import RSA|^\s*import rsa\b",
            "javascript": r"generateKeyPair(Sync)?\(\s*[\"']rsa|new NodeRSA\b|[\"']node-rsa[\"']",
            "go": r"rsa\.GenerateKey\(|\"crypto/rsa\"",
            "java": r"(KeyPairGenerator|KeyFactory)\.getInstance\(\s*\"RSA\"",
            "c": r"RSA_generate_key(_ex)?\(|\bEVP_PKEY_RSA\b|\bRSA_new\(",
            "csharp": r"\bRSA\.Create\(|RSACryptoServiceProvider|\bRSACng\b",
            "rust": r"RsaPrivateKey::new|\buse rsa::",
            "ruby": r"OpenSSL::PKey::RSA",
            "php": r"OPENSSL_KEYTYPE_RSA|Crypt\\RSA",
            "swift": r"kSecAttrKeyTypeRSA",
        },
        "RSA",
    ),
    Rule(
        "PQC004", "Elliptic-curve Diffie-Hellman key agreement", "ECC", "critical", "key-establishment", "Shor", KEM_FIX,
        {
            "python": r"ec\.ECDH\(|X25519PrivateKey|X448PrivateKey",
            "javascript": r"createECDH\(|[\"']ECDH[\"']|[\"'][Xx](25519|448)[\"']",
            "go": r"ecdh\.(P256|P384|P521|X25519)\(|\bcurve25519\.|\"crypto/ecdh\"",
            "java": r"KeyAgreement\.getInstance\(\s*\"(ECDH|X25519|X448|XDH)\"",
            "c": r"ECDH_compute_key|\bEVP_PKEY_X(25519|448)\b|\bX25519\(",
            "csharp": r"ECDiffieHellman",
            "rust": r"x25519_dalek|p256::ecdh|p384::ecdh",
            "swift": r"(Curve25519|P256|P384|P521)\.KeyAgreement",
        },
        lambda m: "X25519/X448" if m and ("25519" in m.group(0) or "448" in m.group(0)) else "ECDH",
    ),
    Rule(
        "PQC005", "Finite-field Diffie-Hellman key agreement", "DH", "critical", "key-establishment", "Shor", KEM_FIX,
        {
            "python": r"dh\.generate_parameters\(|asymmetric import dh\b",
            "javascript": r"(create|get)DiffieHellman(Group)?\(",
            "java": r"KeyAgreement\.getInstance\(\s*\"DH\"|KeyPairGenerator\.getInstance\(\s*\"(DH|DiffieHellman)\"",
            "c": r"\bDH_generate_key\(|\bDH_new\(|\bEVP_PKEY_DH\b",
            "csharp": r"(?<!EC)DiffieHellman",
        },
        "DH",
    ),
    Rule(
        "PQC006", "ECDSA signature", "ECC", "high", "signature", "Shor", SIG_FIX,
        {
            ALL: r"[\"']ES(256|384|512)K?[\"']",
            "python": r"ec\.ECDSA\(|from ecdsa import|\bDSS\.new\(",
            "javascript": r"name:\s*[\"']ECDSA[\"']|new\s+(EC|ec)\(\s*[\"'](secp256k1|p256|p384|p521)[\"']",
            "go": r"ecdsa\.(GenerateKey|Sign|SignASN1|Verify|VerifyASN1)\(|\"crypto/ecdsa\"",
            "java": r"Signature\.getInstance\(\s*\"[^\"]*withECDSA|KeyPairGenerator\.getInstance\(\s*\"(EC|ECDSA)\"",
            "c": r"ECDSA_(sign|do_sign|verify|do_verify)\(|EC_KEY_generate_key|EC_KEY_new_by_curve_name",
            "csharp": r"\bECDsa",
            "rust": r"(p256|p384|k256)::ecdsa|ecdsa::SigningKey",
            "swift": r"(P256|P384|P521)\.Signing|kSecAttrKeyTypeEC",
        },
        "ECDSA",
    ),
    Rule(
        "PQC007", "EdDSA signature (Ed25519 / Ed448)", "ECC", "high", "signature", "Shor", SIG_FIX,
        {
            ALL: r"[\"']EdDSA[\"']",
            "python": r"Ed(25519|448)PrivateKey|nacl\.signing",
            "javascript": r"[\"'][Ee]d(25519|448)[\"']|tweetnacl|nacl\.sign",
            "go": r"ed25519\.(GenerateKey|Sign|Verify|NewKeyFromSeed)\(|\"crypto/ed25519\"",
            "java": r"\"Ed(25519|448)\"",
            "c": r"\bEVP_PKEY_ED(25519|448)\b|ED25519_sign",
            "rust": r"ed25519_dalek",
            "swift": r"Curve25519\.Signing",
        },
        "EdDSA",
    ),
    Rule(
        "PQC008", "DSA signature", "DSA", "high", "signature", "Shor", SIG_FIX,
        {
            "python": r"dsa\.generate_private_key\(|from Crypto(dome)?\.PublicKey import DSA",
            "go": r"\"crypto/dsa\"|\bdsa\.GenerateKey\(",
            "java": r"KeyPairGenerator\.getInstance\(\s*\"DSA\"|withDSA\"",
            "c": r"\bDSA_(generate_key|new|sign)\(",
            "csharp": r"DSACryptoServiceProvider|\bDSA\.Create\(",
        },
        "DSA",
    ),
    Rule(
        "PQC009", "Elliptic-curve key or curve parameter", "ECC", "high", "public-key", "Shor", ECC_FIX,
        {
            ALL: r"\b(secp(256|384|521)r1|secp256k1|prime256v1|NIST ?P-(256|384|521)|P-(256|384|521))\b",
            "python": r"ec\.generate_private_key\(|ec\.SECP(256R1|384R1|521R1|256K1)\(|from Crypto(dome)?\.PublicKey import ECC",
            "javascript": r"generateKeyPair(Sync)?\(\s*[\"']ec[\"']|namedCurve",
            "go": r"elliptic\.P(224|256|384|521)\(",
            "ruby": r"OpenSSL::PKey::EC",
        },
        "ECC",
    ),
    Rule(
        "PQC010", "SSH key using a quantum-vulnerable algorithm", "SSH", "high", "public-key", "Shor", SSH_FIX,
        {ALL: r"\b(ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|ssh-ed25519)\s+AAAA"},
        _ssh_algorithm,
    ),
    Rule(
        "PQC011", "AES with a 128-bit key", "AES", "low", "symmetric", "Grover", AES_FIX,
        {
            ALL: r"(?i)(?<![\w])aes[-_]?128(?:[-_](?:cbc|gcm|ctr|ecb|cfb|ofb|ccm))?\b",
            "python": r"algorithms\.AES128\(",
        },
        "AES-128",
    ),
    Rule(
        "PQC012", "Broken hash function (MD5 / SHA-1)", "HASH", "medium", "hash", "classical", HASH_FIX,
        {
            "python": r"hashlib\.(md5|sha1)\(|hashes\.(MD5|SHA1)\(|\b(MD5|SHA1?)\.new\(",
            "javascript": r"createHash\(\s*[\"'](md5|sha1)[\"']",
            "go": r"\b(md5|sha1)\.(New|Sum)\(",
            "java": r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"",
            "c": r"\b(MD5|SHA1)_Init\(|EVP_(md5|sha1)\(",
            "csharp": r"\b(MD5|SHA1)\.Create\(|MD5CryptoServiceProvider|SHA1Managed",
            "php": r"\b(md5|sha1)\(",
            "ruby": r"Digest::(MD5|SHA1)",
            "rust": r"\b(md5|sha1)::",
        },
        lambda m: "SHA-1" if m and "1" in m.group(0) else "MD5",
    ),
    Rule(
        "PQC013", "Broken cipher (DES / 3DES / RC4)", "CIPHER", "medium", "symmetric", "classical", CIPHER_FIX,
        {
            ALL: r"(?i)\b(des-ede3(-cbc)?|3des|tripledes|rc4|arcfour)\b",
            "python": r"\bDES3?\.new\(",
            "java": r"Cipher\.getInstance\(\s*\"(DES|DESede)",
        },
        lambda m: "RC4" if m and re.search(r"(?i)rc4|arcfour", m.group(0)) else "DES/3DES",
    ),
    Rule(
        "PQC014", "Dependency that only provides quantum-vulnerable public-key crypto", "DEP", "medium", "dependency", "Shor", DEP_FIX,
        {
            "manifest": r"(?:^|[\"'\s])(node-rsa|elliptic|tweetnacl|jsrsasign|ecdsa|ed25519-dalek|x25519-dalek|rsa|p256|p384|k256|ed25519|pynacl|rbnacl)[\"']?\s*(?:[=:<>~^!,]|$)",
        },
        lambda m: f"library: {m.group(1)}" if m else "library",
    ),
]

FILE_RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule("PQC100", "Private key committed with a quantum-vulnerable algorithm", "KEYFILE", "critical",
             "key-material", "Shor", KEYFILE_FIX),
        Rule("PQC101", "Certificate with a quantum-vulnerable public key", "KEYFILE", "high",
             "key-material", "Shor", CERT_FIX),
        Rule("PQC102", "Public key with a quantum-vulnerable algorithm", "KEYFILE", "high",
             "key-material", "Shor", CERT_FIX),
    )
}

ALL_RULES: dict[str, Rule] = {**{r.id: r for r in RULES}, **FILE_RULES}
