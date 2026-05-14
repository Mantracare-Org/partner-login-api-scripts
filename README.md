# Partner Login API Scripts

This repository contains scripts for generating secure payloads for the Partner Login API. It uses [Bun](https://bun.sh/) as the runtime and package manager.

## Prerequisites

1. Ensure you have [Bun](https://bun.sh/docs/installation) installed on your system.
   ```bash
   curl -fsSL https://bun.sh/install | bash
   ```

## Setup

1. Clone or download this project.
2. Install the dependencies by running:
   ```bash
   bun install
   ```

## Configuration

Before running the scripts, you must configure them with your actual partner keys and data. Each file contains a `CONFIGURATION` section at the top. 

Please replace the placeholder values (e.g., `YOUR_BASE64_ENCODED_KEY`, `YOUR_PARTNER_PRIVATE_KEY_GOES_HERE`) with your actual keys and key IDs:

- **`aes-256-gcm.ts`**: Replace `SYMMETRIC_KEY_BASE64` and adjust `PARTNER_KEY_ID`.
- **`generate-jwe.ts`**: Replace `PARTNER_PRIVATE_KEY`, `SERVER_ENCRYPTION_PUBLIC_KEY`, and adjust `PARTNER_KEY_ID`.
- **`generate-jws.ts`**: Replace `PARTNER_PRIVATE_KEY` and adjust `PARTNER_KEY_ID`.

## Running the Scripts

You can run the individual scripts using the commands defined in `package.json`:

### 1. AES-256-GCM Payload Generation
Generates an AES-256-GCM encrypted payload and sends it to the partner login endpoint.
```bash
bun run run:aes
```

### 2. JWE (JSON Web Encryption) Generation
Generates a signed JWS that is then encrypted as a JWE payload using RSA-OAEP-256 and AES-GCM.
```bash
bun run run:jwe
```

### 3. JWS (JSON Web Signature) Generation
Generates a signed JSON Web Signature (JWS) payload.
```bash
bun run run:jws
```

### Type Checking
To run TypeScript type checks over the codebase without emitting files, use:
```bash
bun run check
```
