# VeilKey API - Quick Start Guide

## Installation & Setup

```bash
# 1. Install dependencies
npm install

# 2. Start the API server
npm run start:api

# Server will be running at http://localhost:3000
```

## Authentication

All endpoints (except `/health`) require an API key:

```bash
-H "X-API-Key: demo-api-key-12345"
```

## Quick Examples

### 1. Health Check

```bash
curl http://localhost:3000/health
```

### 2. Create a Key Group

```bash
curl -X POST http://localhost:3000/v1/groups \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "threshold": 2,
    "parties": 3,
    "algorithm": "RSA-2048"
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "...",
  "shares": [
    {"index": 1, "value": "...", "verificationKey": "..."},
    {"index": 2, "value": "...", "verificationKey": "..."},
    {"index": 3, "value": "...", "verificationKey": "..."}
  ],
  ...
}
```

**IMPORTANT:** Save the group ID and shares! Shares are only returned once.

### 3. Create Partial Signatures

```bash
# With Share 1
curl -X POST http://localhost:3000/v1/groups/{GROUP_ID}/sign/partial \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 1
  }'

# With Share 2
curl -X POST http://localhost:3000/v1/groups/{GROUP_ID}/sign/partial \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "shareIndex": 2
  }'
```

### 4. Combine Signatures

```bash
curl -X POST http://localhost:3000/v1/groups/{GROUP_ID}/sign/combine \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "partials": [
      {"index": 1, "partial": "..."},
      {"index": 2, "partial": "..."}
    ]
  }'
```

### 5. Verify Signature

```bash
curl -X POST http://localhost:3000/v1/groups/{GROUP_ID}/verify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-12345" \
  -d '{
    "message": "Hello, VeilKey!",
    "signature": "..."
  }'
```

## Complete Workflow Script

```bash
# Run the included shell script for a complete demo
chmod +x src/api/api-examples.sh
./src/api/api-examples.sh
```

## Testing

```bash
# Run API tests
npm test src/api/api.test.ts

# Run example code
npx tsx src/api/example.ts
```

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (no auth) |
| POST | `/v1/groups` | Create key group |
| GET | `/v1/groups/:id` | Get key group info |
| POST | `/v1/groups/:id/sign/partial` | Create partial signature |
| POST | `/v1/groups/:id/sign/combine` | Combine signatures |
| POST | `/v1/groups/:id/verify` | Verify signature |

## Configuration

### Environment Variables

```bash
PORT=3000          # API server port
HOST=0.0.0.0       # API server host
```

### Programmatic Usage

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

await server.listen({ port: 3000 });
```

## Error Handling

All errors return this format:

```json
{
  "error": {
    "message": "Description of the error",
    "code": "ERROR_CODE",
    "statusCode": 400
  }
}
```

Common status codes:
- `200` - Success
- `400` - Bad Request (validation error)
- `401` - Unauthorized (missing/invalid API key)
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

## Security Notes

1. **API Keys**: Replace demo keys in production
2. **HTTPS**: Always use HTTPS in production
3. **Share Storage**: Store shares securely, they're only returned once
4. **Rate Limiting**: 100 requests/minute by default
5. **CORS**: Configure allowed origins in production

## Next Steps

- Read the full documentation: `src/api/README.md`
- Review the example code: `src/api/example.ts`
- Run the test suite: `npm test src/api/api.test.ts`
- Check the implementation summary: `PHASE_2.3_SUMMARY.md`

## Support

For issues or questions:
- Check the README: `src/api/README.md`
- Review tests: `src/api/api.test.ts`
- See examples: `src/api/example.ts`

## License

BSL-1.1
