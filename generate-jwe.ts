import { CompactEncrypt, SignJWT, importPKCS8, importSPKI, base64url } from 'jose';
import { createPrivateKey, webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
	globalThis.crypto = webcrypto as Crypto;
}

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------

// 1. Your Partner Private Key (PEM format)
// Used to SIGN the inner token so MantraCare knows it came from you.
const PARTNER_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
YOUR_PARTNER_PRIVATE_KEY_GOES_HERE
-----END RSA PRIVATE KEY-----`;

const PARTNER_KEY_ID = 'key-id';

// 2. Server Encryption Public Key (RSA)
// The public key provided by MantraCare to encrypt the content for them.
const SERVER_ENCRYPTION_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
YOUR_SERVER_ENCRYPTION_PUBLIC_KEY_GOES_HERE
-----END PUBLIC KEY-----`;

// 3. The User Data
const USER_DATA = {
	user_identifier: 'your-unique-user-identifier',
	invite_code: 'invite-code/program-code',
};

// ------------------------------------------------------------------
// GENERATION
// ------------------------------------------------------------------

async function generateJWE() {
	if (
		PARTNER_PRIVATE_KEY.includes('YOUR_PARTNER_PRIVATE_KEY_GOES_HERE') ||
		SERVER_ENCRYPTION_PUBLIC_KEY.includes('YOUR_SERVER_ENCRYPTION_PUBLIC_KEY_GOES_HERE')
	) {
		console.error('Error: Please replace the Key placeholders with your actual keys.');
		return;
	}

	try {
		// --- Step A: Sign the Data (JWS) ---

		// Import Partner's Private Key
		const signingKey = createPrivateKey(PARTNER_PRIVATE_KEY);

		const jws = await new SignJWT(USER_DATA)
			.setProtectedHeader({ alg: 'RS256', kid: PARTNER_KEY_ID })
			.setIssuedAt()
			.setExpirationTime('5m') // Short expiration for the inner token
			.sign(signingKey);

		console.log('Step A: Generated Signed JWS (Internal)');

		// --- Step B: Encrypt the JWS (JWE) using RSA-OAEP-256 + AES-GCM ---

		// Import Server's Public Key
		const encryptionKey = await importSPKI(SERVER_ENCRYPTION_PUBLIC_KEY, 'RSA-OAEP-256');

		const encoder = new TextEncoder();

		// Encrypt the JWS string
		// alg: 'RSA-OAEP-256' for Key Encryption
		// enc: 'A256GCM'(AES-GCM 256-bit encryption) for Content Encryption
		const jwe = await new CompactEncrypt(encoder.encode(jws))
			.setProtectedHeader({
				alg: 'RSA-OAEP-256',
				enc: 'A256GCM',
				kid: PARTNER_KEY_ID,
				cty: 'JWT',
			})
			.encrypt(encryptionKey);

		console.log('--- Generated JWE ---');
		console.log(jwe);
	} catch (error) {
		console.error('Failed to generate JWE:', error);
	}
}

generateJWE().catch(console.error);
