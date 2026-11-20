const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ecdh = crypto.createECDH("prime256v1");

function issueToken(user) {
  return jwt.sign({ sub: user.id }, privateKey, { algorithm: "RS256" });
}

function encryptSecret(secret) {
  return crypto.publicEncrypt(publicKey, Buffer.from(secret));
}

const cipher = crypto.createCipheriv("aes-128-gcm", crypto.randomBytes(16), crypto.randomBytes(12));
