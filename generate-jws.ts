import { SignJWT, importPKCS8 } from 'jose';

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------

// 1. Your Partner Private Key (PEM format)
// You generated this and shared the Public Key with MantraCare.
const PARTNER_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
YOUR_PARTNER_PRIVATE_KEY_GOES_HERE
...
-----END PRIVATE KEY-----`;

// 2. The Key ID (kid) you assigned to this key
// This must match what is configured in MantraCare's system for your partner account.
const PARTNER_KEY_ID = 'YOUR_PARTNER_KEY_ID'; // e.g., 'partner-key-rsa-2024'

// 3. The User Identifier you want to sign in
const USER_IDENTIFIER = 'test-user-unique-id',
	INVITE_CODE = 'invite-code/program-code';

// ------------------------------------------------------------------
// GENERATION
// ------------------------------------------------------------------

async function generateJWS() {
	if (PARTNER_PRIVATE_KEY.includes('YOUR_PARTNER_PRIVATE_KEY_GOES_HERE')) {
		console.error('Error: Please replace PARTNER_PRIVATE_KEY with your actual private key.');
		return;
	}

	try {
		// Import the Private Key
		const privateKey = await importPKCS8(PARTNER_PRIVATE_KEY, 'RS256');

		// Define the Payload
		const payload = {
			user_identifier: USER_IDENTIFIER,
			invite_code: INVITE_CODE,
		};

		// Sign the JWT (JWS)
		const jws = await new SignJWT(payload)
			.setProtectedHeader({ alg: 'RS256', kid: PARTNER_KEY_ID })
			.setIssuedAt()
			.setExpirationTime('1h') // Token validity
			.sign(privateKey);

		console.log('--- Generated JWS ---');
		console.log(jws);
	} catch (error) {
		console.error('Failed to generate JWS:', error);
	}
}

generateJWS().catch(console.error);
