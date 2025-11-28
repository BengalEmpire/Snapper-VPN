const net = require('net');
const crypto = require('crypto');
require('dotenv').config();

// Encryption configuration
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'utf-8');
const iv = Buffer.from(process.env.IV, 'utf-8');

const client = net.createConnection({ host: process.env.SERVER_HOST, port: process.env.SERVER_PORT }, () => {
  console.log('Connected to VPN server');
  const message = 'Hello, VPN Server!';
  const encryptedMessage = encrypt(message);
  client.write(encryptedMessage);
});

// Encryption function
function encrypt(data) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Decryption function
function decrypt(data) {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Handle incoming data
client.on('data', (data) => {
  const decryptedData = decrypt(data.toString());
  console.log('Received from server:', decryptedData);
  client.end();
});

client.on('end', () => {
  console.log('Disconnected from VPN server');
});