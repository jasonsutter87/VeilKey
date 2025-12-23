# VeilKey REST API

A production-ready REST API service for threshold cryptography operations using Fastify.

## Features

- **Fast & Lightweight**: Built on Fastify for high performance
- **Type-Safe**: Full TypeScript support with Zod validation
- **Secure**: API key authentication, rate limiting, CORS
- **Well-Documented**: OpenAPI schemas for all endpoints
- **Tested**: Comprehensive integration tests

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm run start:api
```

The server will start on `http://localhost:3000`

### 3. Test the API

```bash
# Health check (no auth required)
curl http://localhost:3000/health

# Create a key group (requires API key)
curl -X POST http://localhost:3000/v1/groups \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "threshold": 2,
    "parties": 3,
    "algorithm": "RSA-2048"
  }'
```

## API Reference

### Authentication

All endpoints (except `/health`) require an API key:

```bash
-H "X-API-Key: your-api-key"
```

**Demo API Keys:**
- `demo-api-key-12345`
- `test-api-key-67890`

### Endpoints

#### Health Check

```http
GET /health
```

Returns server health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-22T12:00:00.000Z",
  "version": "0.1.0"
}
```

---

#### Create Key Group

```http
POST /v1/groups
```

Generate a new threshold key group.

**Request:**
```json
{
  "threshold": 2,
  "parties": 3,
  "algorithm": "RSA-2048"
}
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "a1b2c3d4...:10001",
  "algorithm": "RSA-2048",
  "threshold": 2,
  "parties": 3,
  "shares": [
    {
      "index": 1,
      "value": "abc123...",
      "verificationKey": "def456..."
    }
  ],
  "delta": "02",
  "createdAt": "2025-12-22T12:00:00.000Z"
}
```

**Note:** The `shares` array is only returned on creation. Store these securely!

---

#### Get Key Group

```http
GET /v1/groups/:id
```

Retrieve public information about a key group.

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "a1b2c3d4...:10001",
  "algorithm": "RSA-2048",
  "threshold": 2,
  "parties": 3,
  "shareInfo": [
    {
      "index": 1,
      "verificationKey": "def456..."
    }
  ],
  "delta": "02",
  "createdAt": "2025-12-22T12:00:00.000Z"
}
```

**Note:** Share values are NOT included for security.

---

#### Create Partial Signature

```http
POST /v1/groups/:id/sign/partial
```

Create a partial signature using a share.

**Request:**
```json
{
  "message": "Hello, VeilKey!",
  "shareIndex": 1
}
```

**Response:**
```json
{
  "index": 1,
  "partial": "a1b2c3d4..."
}
```

---

#### Combine Signatures

```http
POST /v1/groups/:id/sign/combine
```

Combine partial signatures into a complete signature.

**Request:**
```json
{
  "message": "Hello, VeilKey!",
  "partials": [
    { "index": 1, "partial": "a1b2..." },
    { "index": 2, "partial": "c3d4..." }
  ]
}
```

**Response:**
```json
{
  "signature": "e5f6g7h8..."
}
```

---

#### Verify Signature

```http
POST /v1/groups/:id/verify
```

Verify a signature.

**Request:**
```json
{
  "message": "Hello, VeilKey!",
  "signature": "e5f6g7h8..."
}
```

**Response:**
```json
{
  "valid": true
}
```

---

## Complete Example: Threshold Signing

```bash
# 1. Create a 2-of-3 key group
GROUP_RESPONSE=$(curl -X POST http://localhost:3000/v1/groups \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "threshold": 2,
    "parties": 3,
    "algorithm": "RSA-2048"
  }')

GROUP_ID=$(echo $GROUP_RESPONSE | jq -r '.id')
echo "Created group: $GROUP_ID"

# 2. Create partial signature with share 1
PARTIAL1=$(curl -X POST http://localhost:3000/v1/groups/$GROUP_ID/sign/partial \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 1
  }')

# 3. Create partial signature with share 2
PARTIAL2=$(curl -X POST http://localhost:3000/v1/groups/$GROUP_ID/sign/partial \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 2
  }')

# 4. Combine signatures
SIGNATURE=$(curl -X POST http://localhost:3000/v1/groups/$GROUP_ID/sign/combine \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d "{
    \"message\": \"Hello, VeilKey!\",
    \"partials\": [
      $(echo $PARTIAL1),
      $(echo $PARTIAL2)
    ]
  }" | jq -r '.signature')

# 5. Verify signature
curl -X POST http://localhost:3000/v1/groups/$GROUP_ID/verify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d "{
    \"message\": \"Hello, VeilKey!\",
    \"signature\": \"$SIGNATURE\"
  }"
```

## Configuration

### Environment Variables

```bash
PORT=3000           # Server port
HOST=0.0.0.0        # Server host
```

### Server Options

```typescript
import { createServer } from './api/server.js';

const server = await createServer({
  port: 3000,
  host: '0.0.0.0',
  enableCors: true,
  enableRateLimit: true,
  enableAuth: true,
  logger: true,
});
```

## Testing

Run the test suite:

```bash
npm test src/api/api.test.ts
```

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "message": "Error description",
    "code": "ERROR_CODE",
    "statusCode": 400
  }
}
```

### Common Error Codes

- `VALIDATION_ERROR` (400): Invalid request data
- `UNAUTHORIZED` (401): Missing or invalid API key
- `NOT_FOUND` (404): Resource not found
- `RATE_LIMIT_EXCEEDED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error

## Security Considerations

### Production Checklist

- [ ] Replace demo API keys with secure keys
- [ ] Store API keys in environment variables or key management service
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS for specific origins
- [ ] Adjust rate limits based on usage patterns
- [ ] Replace in-memory storage with a database
- [ ] Add request logging and monitoring
- [ ] Implement proper key rotation
- [ ] Add request/response encryption for sensitive data

### In-Memory Storage

The current implementation uses in-memory storage for simplicity. For production:

1. Replace `storage.ts` with a database (PostgreSQL, Redis, etc.)
2. Implement proper access control
3. Add encryption at rest for sensitive data
4. Implement backup and recovery

## Architecture

```
/src/api/
├── server.ts          # Fastify server factory
├── types.ts           # Request/response types & Zod schemas
├── storage.ts         # In-memory key group storage
├── middleware/
│   ├── auth.ts        # API key authentication
│   ├── error-handler.ts
│   └── index.ts
├── routes/
│   ├── health.ts      # Health check
│   ├── groups.ts      # Key group management
│   └── index.ts
└── api.test.ts        # Integration tests
```

## License

BSL-1.1
