require('dotenv').config();
const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5001;

app.use(express.urlencoded({ extended: true }));

// ------------------------------
// SSH Key Endpoint
// ------------------------------
const AUTHORIZED_KEYS_FILE = path.join(os.homedir(), '.ssh', 'authorized_keys');

app.post('/add_ssh_key', (req, res) => {
  const key = req.body.key?.trim();

  if (!key) {
    return res.status(400).json({ status: 'error', message: 'Missing SSH key.' });
  }

  if (
    !(
      key.startsWith('ssh-rsa') ||
      key.startsWith('ssh-ed25519') ||
      key.startsWith('ecdsa-sha2-nistp256')
    )
  ) {
    return res.status(400).json({ status: 'error', message: 'Invalid SSH public key format.' });
  }

  try {
    const sshDir = path.dirname(AUTHORIZED_KEYS_FILE);
    if (!fs.existsSync(sshDir)) {
      fs.mkdirSync(sshDir, { mode: 0o700, recursive: true });
    }

    const existingKeys = fs.existsSync(AUTHORIZED_KEYS_FILE)
      ? fs.readFileSync(AUTHORIZED_KEYS_FILE, 'utf8').split('\n').filter(Boolean)
      : [];

    if (existingKeys.includes(key)) {
      return res.json({
        status: 'already_exists',
        message: 'Key is already in authorized_keys.',
      });
    }

    fs.appendFileSync(AUTHORIZED_KEYS_FILE, key + '\n');
    fs.chmodSync(AUTHORIZED_KEYS_FILE, 0o600);

    res.json({ status: 'success', message: 'Key added to authorized_keys.' });
  } catch (err) {
    console.error('Error adding SSH key:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

app.listen(PORT, () => {
  console.log(`SSH Key API running at http://localhost:${PORT}`);
});
