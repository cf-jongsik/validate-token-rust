# Token Validation Rust Worker

A Cloudflare Workers service written in Rust that provides HMAC-based token validation for login requests. This worker acts as a middleware to validate time-sensitive tokens before forwarding requests to the origin server.

## Features

- **HMAC Token Validation**: Validates tokens using HMAC-SHA256 with client IP and timestamp
- **Time-based Expiration**: Configurable token validity period (default: 300 seconds)
- **Client IP Extraction**: Supports both `CF-Connecting-IP` and `X-Forwarded-For` headers
- **Selective Processing**: Only processes `APPS_LOGIN_DEFAULT` function requests
- **Access Token Handling**: Sets secure HTTP-only cookies for access tokens
- **Request Forwarding**: Transparently forwards validated requests to origin

## Architecture

The worker intercepts incoming requests and:

1. Extracts the `oait` parameter containing token data
2. Parses tokens in format: `forms_token++cloudflare_token++access_token`
3. Validates the Cloudflare token using HMAC-SHA256 with client IP and timestamp
4. Removes the validation token and forwards the request with the forms token
5. Sets access token as a secure cookie if provided

## Configuration

### Environment Variables

| Variable                 | Description                      | Default            |
| ------------------------ | -------------------------------- | ------------------ |
| `HMAC_SECRET`            | Secret key for HMAC validation   | `"default-secret"` |
| `TOKEN_VALIDITY_SECONDS` | Token validity period in seconds | `300`              |

### Wrangler Configuration

```toml
name = "validate-token-rust"
main = "build/worker/shim.mjs"
compatibility_date = "2025-08-26"

[build]
command = "cargo install -q worker-build && worker-build --release"
```

## Token Format

The `oait` parameter should contain tokens separated by `++`:

```
forms_token++cloudflare_token++access_token
```

Where:

- **forms_token**: Token to be forwarded to the origin server
- **cloudflare_token**: HMAC validation token in format `timestamp-hash`
- **access_token**: Optional token to be set as a secure cookie

### Cloudflare Token Structure

The Cloudflare token must be in the format: `{timestamp}-{base64_hash}`

Where:

- `timestamp`: Unix timestamp when the token was generated
- `base64_hash`: Base64-encoded HMAC-SHA256 hash of `{client_ip}:{timestamp}`

## Development

### Prerequisites

- Rust 1.70+
- Node.js 18+
- Wrangler CLI

### Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd validate-token-rust
```

2. Install dependencies:

```bash
cargo build
npm install -g @cloudflare/wrangler
```

3. Configure secrets:

```bash
wrangler secret put HMAC_SECRET
```

### Building

```bash
cargo install -q worker-build
worker-build --release
```

### Testing

The project includes a comprehensive test suite in `test.sh` that validates the worker's functionality.

#### Running Tests

1. Start the worker locally:

```bash
pnpm dlx wrangler dev
```

2. Run the test suite:

```bash
./test.sh
```

#### Test Script Options

```bash
./test.sh [options]

Options:
  -v, --verbose       Show detailed response output
  -h, --host HOST     Set host header (default: reflector.cloudflareapp.cc)
  -p, --port PORT     Set port (default: 8787)
  -s, --secret KEY    Set HMAC secret (default: default-secret)
  --help              Show help message
```

#### Environment Variables

You can also configure the test script using environment variables:

```bash
HOST=myhost.example.com PORT=3000 SECRET=mysecret ./test.sh
```

#### Test Coverage

The test suite includes 12 test cases covering:

- **Bypass scenarios**: Missing or non-login function_id
- **Error handling**: Missing oait, invalid token formats, expired tokens
- **Valid requests**: Proper token validation with various configurations
- **Header support**: CF-Connecting-IP and X-Forwarded-For headers
- **Additional features**: Access token handling, query parameter preservation

Each test provides colored output indicating success (✓) or failure (✗), with a final summary showing total tests run, passed, and failed.

**Note:** The test script uses a default token validity of 300 seconds (5 minutes) for testing purposes, while the worker defaults to 300 seconds (5 minutes) in production.

### Deployment

```bash
wrangler deploy
```

## Usage Example

### Request Flow

1. **Incoming Request**:

```
GET /login?function_id=APPS_LOGIN_DEFAULT&oait=form123++1693123456-dGVzdGhhc2g%3D++access789
```

2. **Token Validation**:

   - Extracts client IP from headers
   - Validates `1693123456-dGVzdGhhc2g=` against client IP and timestamp
   - Checks if token is within validity period

3. **Forwarded Request**:

```
GET /login?function_id=APPS_LOGIN_DEFAULT&oait=form123
Set-Cookie: CF_Authorization=access789; Path=/; HttpOnly; Secure; SameSite=Strict
```

### Generating Valid Tokens

To generate a valid Cloudflare token:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::prelude::*;

fn generate_token(client_ip: &str, secret: &str, timestamp: f64) -> String {
    let message = format!("{}:{}", client_ip, timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let hash = BASE64_STANDARD.encode(mac.finalize().into_bytes());
    format!("{}-{}", timestamp, hash)
}
```

## Security Features

- **Constant-time Comparison**: Prevents timing attacks during hash comparison
- **IP-based Validation**: Tokens are bound to specific client IPs
- **Time-based Expiration**: Tokens automatically expire after configured period
- **Secure Cookies**: Access tokens are set with security flags (HttpOnly, Secure, SameSite)

## Error Handling

The worker returns the following HTTP status codes for different error scenarios:

- `400 Bad Request`: Missing secret or invalid parameters
- `401 Unauthorized`: Invalid or missing `oait` parameter
- `403 Forbidden`: Invalid or expired tokens
- `500 Internal Server Error`: Unexpected errors during token validation or request forwarding
- Forwards original response for valid requests

## Dependencies

- `worker` (v0.0.18+): Cloudflare Workers runtime
- `hmac` (v0.12+): HMAC implementation
- `sha2` (v0.10+): SHA-256 hashing
- `base64` (v0.21+): Base64 encoding/decoding
- `url` (v2.4+): URL parsing and manipulation
- `urlencoding` (v2.1+): URL encoding/decoding
- `js-sys` (v0.3+): JavaScript interop for timestamps
- `wasm-bindgen` (v0.2+): WebAssembly bindings
