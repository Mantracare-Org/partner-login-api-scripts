import crypto from 'node:crypto';
import axios from 'axios';

// 1. Partner Credentials & Info

const PARTNER_KEY_ID = 123;

// The 32-byte AES key

const SYMMETRIC_KEY_BASE64 = 'YOUR_BASE64_ENCODED_KEY';

const ALGORITHM = 'aes-256-gcm';

// 2. Data to Send

const plaintextData = JSON.stringify({
	user_identifier: 'EMP-ABC-123',

	invite_code: 'SBI-CORP-SPECIAL',
});

// 3. Perform Encryption

const keyBuffer = Buffer.from(SYMMETRIC_KEY_BASE64, 'base64');

const ivBuffer = crypto.randomBytes(12);

const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, ivBuffer);

let encryptedBase64 = cipher.update(plaintextData, 'utf8', 'base64');

encryptedBase64 += cipher.final('base64');

const authTagBase64 = cipher.getAuthTag().toString('base64');

// 4. Send API Request

const payload = {
	key_id: PARTNER_KEY_ID,

	iv: ivBuffer.toString('base64'),

	auth_tag: authTagBase64,

	encrypted_data: encryptedBase64,
};

// Fire via Axios

axios
	.post('https://api.mantracare.com/partners/sbi/user', payload)

	.then((response) => {
		// Will return a standard response object tracking the magic-link or verification route:

		// { "redirect_url": "https://web.mantracare.com/login/magic-link?token=..." }

		console.log('Success! Redirect User To:', response.data.redirect_url);
	})

	.catch((error) => {
		console.error('Failed to authenticate user.', error.response.data);
	});
