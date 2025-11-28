const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

require('dotenv').config();

// Encryption configuration
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'utf-8');
const iv = Buffer.from(process.env.IV, 'utf-8');

const server = net.createServer((socket) => {
  console.log('Client connected.');

  // Encryption and Decryption functions
  function encrypt(data) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  function decrypt(data) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // Handle incoming data (decrypt it and process)
  socket.on('data', (data) => {
    const decryptedData = decrypt(data.toString());
    console.log('Received data:', decryptedData);

    // Encrypt a response and send it back
    const encryptedResponse = encrypt('Response from VPN server');
    socket.write(encryptedResponse);
  });

  socket.on('end', () => {
    console.log('Client disconnected.');
  });

  socket.on('error', (err) => {
    console.error('Error:', err);
  });
});

// Start the server
const port = process.env.PORT || 1337;
server.listen(port, () => {
  console.log(`VPN Server running on port ${port}`);
});