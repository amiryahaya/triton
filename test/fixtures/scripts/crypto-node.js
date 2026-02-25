const crypto = require('crypto');

const hash = crypto.createHash('sha256').update('data').digest('hex');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
