# x402 Compliance Validator

Grades any [x402](https://x402.org)-gated HTTP endpoint **A–F** against the V2 protocol specification.

Maintained by [SolSigs](https://solsigs.com).

---

## What it does

The validator sends a live probe to any URL you supply and runs up to 15 checks across three tiers:

| Tier | Meaning |
|---|---|
| NORMATIVE | Required by the x402 V2 spec — failure lowers the grade |
| RECOMMENDED | Strongly encouraged — failure is a warning, not a hard fail |
| BEST-PRACTICE | Practical for real-world deployments (CORS, UA tolerance, etc.) |

It detects whether the server declares **x402Version 1 or 2** and applies the appropriate field rules, so V1 servers still grade correctly.

Spec authority: [x402-foundation/x402](https://github.com/x402-foundation/x402), commit `b32a7023`, as of 2026-06-14.

The x402 specification is evolving; grades reflect the spec as of this commit and may change as the standard develops.

---

## Check table

| # | ID | What it checks | Tier | V1 | V2 |
|---|---|---|---|---|---|
| 1 | reachable | Endpoint responds within the timeout | BEST-PRACTICE | ✓ | ✓ |
| 2 | status402 | Response is HTTP 402 when unpaid | NORMATIVE | ✓ | ✓ |
| 3 | json402 | 402 body is valid JSON | NORMATIVE | ✓ | ✓ |
| 4 | version | x402Version field declared in body | NORMATIVE | ✓ | ✓ |
| 5 | accepts | Non-empty accepts[] array present | NORMATIVE | ✓ | ✓ |
| 6 | acceptFields | accepts[0] has scheme, network, payTo, asset, and amount | NORMATIVE | ✓ | ✓ |
| 7 | amountStr | amount (V2) / maxAmountRequired (V1) is an atomic-unit string | NORMATIVE | ✓ | ✓ |
| 8 | resourceField | Resource URL declared — body.resource.url in V2; accepts[0].resource in V1 | RECOMMENDED | ✓ | ✓ |
| 9 | descField | Resource description present — body.resource.description in V2; accepts[0].description in V1 | RECOMMENDED | ✓ | ✓ |
| 10 | timeoutField | maxTimeoutSeconds declared in accepts[0] | NORMATIVE | ✓ | ✓ |
| 11 | network | Network identifier valid — V2 enforces CAIP-2 (namespace:reference); V1 accepts known bare names | NORMATIVE | ✓ | ✓ |
| 12 | paymentRequiredHeader | PAYMENT-REQUIRED header with base64 PaymentRequired JSON | NORMATIVE (V2) / RECOMMENDED (V1) | warn | ✓ |
| 13 | discovery | Serves /.well-known/x402.json discovery document | BEST-PRACTICE | ✓ | ✓ |
| 14 | discoveryEndpoints | Discovery doc lists at least one endpoint (only emitted when check 13 passes) | BEST-PRACTICE | ✓ | ✓ |
| 15 | cors | CORS headers present for browser and embedded-agent access | BEST-PRACTICE | ✓ | ✓ |

> **Note:** NORMATIVE indicates a check the x402 V2 spec requires. Some normative checks are evaluated at warn-level (amountStr, resourceField, descField, timeoutField, and paymentRequiredHeader on V1) — they reduce the score but do not cause a hard fail. Discovery checks use the /.well-known/x402.json convention, which is common practice rather than a V2 spec mechanism (V2 defines a separate Bazaar discovery API).

---

## Grading

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | < 40 |

Hard-fail checks (NORMATIVE) reduce the score by their weight. RECOMMENDED checks trigger warnings. BEST-PRACTICE checks have no grade impact.

---

## Requirements

- Node.js 20+
- npm

---

## Quick start

```bash
git clone https://github.com/gra-kir/x402-validator.git
cd x402-validator
npm install
npm start
# Open http://localhost:3000/validate
```

Set a custom port:

```bash
PORT=8080 npm start
```

---

## API

### POST /validate/api

**Request:**
```json
{ "url": "https://example.com/paid-endpoint" }
```

**Response:**
```json
{
  "grade": "A",
  "score": 100,
  "specVersion": "x402v2",
  "checks": [
    { "id": "reachable", "pass": true, "detail": "...", "level": "pass", "rating": "NORMATIVE" },
    ...
  ],
  "checkedAt": "2026-06-14T00:00:00.000Z"
}
```

---

## Use as an Express router

```js
const validateRouter = require('./validate-router');
app.use('/validate', validateRouter);
// UI at GET /validate
// API at POST /validate/api
```

---

## Security

- **SSRF guard**: Private/loopback addresses are always rejected (no env override).
- No secrets, no external dependencies beyond Express.
- Each probe makes at most 3 outbound HTTP calls (GET, OPTIONS, and the header-decode).

---

## License

MIT — see [LICENSE](LICENSE).
