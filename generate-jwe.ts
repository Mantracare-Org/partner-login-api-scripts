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
MIIEogIBAAKCAQEAz7kTcWuEhvkgcS7Gebwdd04H5bx77dfdBAMuSjPAAzuQviGr
EUT/VAudQJRL/WBATnmxhpgpuddt28n2e5iNfUMGKXcsxKfFvwxtcSALsDSwprOo
7Xi5QsH0wEekYbRwTkEUVM2VcgbS15NPTwt4/s/2qXzZCr3BMhTbPcE0zYoB02gy
OIAXPEJ8PWp8THh4rmURfRxREbK4QK098+96lA6nL0Nh5ockJL8QmGj6GuFrikA7
8/WUW5l7sbR8z9ZQb7xKNaCmvrhURL+8ofRdz4BPJCK8ldYlkJPLgn7+0Bbr8sJ+
sPpreW7aeYYQ9y0sAgG11iDd5Gs1GprGGAu45wIDAQABAoIBABp6nbC2GMvkgvmv
5utgCvjehgwyNYaxSde37hUrDp164NhpI0ziw5ImSYfmFN+6KXMMzo/5N/ccL+wL
YokJKR7Kxe965RvhGnM1oC0s/WsbSa9ztHjSYaSnDnjaSRPkCUg4bIvjibA3kCCc
gx4bjh4b9XX6gmennl0wzRfMrVtL3bpcw7YnQ3biILYZpBWU9Ug7pc0b5BcoY+8N
Rkeu7JkpIXRAoe/KCUFWznla6y1rYQzyNaY+p/kJS4rJXbV26pu0/SJnDqmPI2nN
Y9XFgj+gbYni+Ywj8q+njEadaKBjFsWvL2ng1VZrxPKyxabneliFJUYXFO0vzxhF
s1f1wXECgYEA6DcZc43lP2lmkhSrepheAs12b6KXbyLgIOXgMZ8eLnbUZIQhjf+l
Q9ccyKybSnlAc4dcp/r3Cib8Q53KtQZgt54lO7t2Kh2qjQWIxKMVSj6e6c/ke/tT
k3Egk6elqXfGpq6NJmFe4dKu8ccuQ5kG5i/G59TbByj7lXi1HY1RQrECgYEA5P/E
HKBumHLZuIUlRKmoY7YivYL4WdgXRozCNe5W/ay5O5/EEYiDALztxtNk6QLOtcfs
UZR8HWuymHQv9YMX20kZ9wH4uu29ardGxXrpEMiQdihxcbTASrnIj+n0omTR1g7t
CfQw1f3YWJJRqa2alRCpKGqK2jEW103Jihz7KxcCgYAMyowyW0yXc5zcyxqvBBmZ
meu+NnyU+JzT8xWoZhVphc4pQ0X95mkaFY1WWHutXIR6WKh38FEPVBptNxHlataF
BscSRT87DqtIXVetTTZtAooKYxM46R0vb/nVaFStwxVENTU9OfvaAJr2Ynxf6NwC
bftM5eKywEUrdJy1ZgVl4QKBgHGXwbMljdbHWeKjAUqfEe1sQq1ZE1KV023mksvn
z3UEQdomtT6xRbKPBS/UWsEO6HTZmAsbqbl6W9wt/kA96A6Zo2yYqMYo+gW+pjd9
cbEmnCpQg32Q2LX4lFl3Byeq9T/GpaSDYdo0kiXVZvbRK9X3rsFioD/9i8P/TRLa
r2i/AoGAYy2pDAyuvPh+4Dllno6Ksa+jK8RqGNP1KS55fRdwnThZMpERboyu+fEf
XoAXNw3rKRQjFq8nq+afjdL4DXFon+eOzjaH3p6/wg1k4ncd4AYJd90HOjc/83ju
S4TboNQAi2eclgIMiaf3ZevcqBbxTfvuVHgPsWEjrQ73usBiZ/c=
-----END RSA PRIVATE KEY-----`;

const PARTNER_KEY_ID = '1';

// 2. Server Encryption Public Key (RSA)
// The public key provided by MantraCare to encrypt the content for them.
const SERVER_ENCRYPTION_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1fdMORWBZJq1vYARn5Kb
tiQQhc4vOp4H1XGSjQGMt24G3viwFn+9k8rAJe1aEGZSEYGnFDyxbk15m4PVD9tB
ZyqQFqQIsaFSIH9px4cbLfFVWaMeK8FWuCyj6ttmRIk+qri90i2t/ePAQUJMRg8U
N1H+rHFyHMOGzMhw7aL7UCipHtW2Ahgy1Csmy4GgdCRfhFsJ7LGjXB7jh1Dr+ljw
hVKZmeOu2MqkjMiK8gjdBY0ZGTeBVCyYZb6P0Namfy5s6jLWnXqKImTTOZ1iO2L5
Pp3hNh16QBfY+CORtWLZE4OtMMJYXMzFMsTNlD33iNGixLo8YGCMcBWiFCi13F+3
4wIDAQAB
-----END PUBLIC KEY-----`;

// 3. The User Data
const USER_DATA = {
	user_identifier: 'sbigplan2',
	invite_code: 'mantrainternal',
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
