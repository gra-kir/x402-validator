/**
 * SolSigs x402 Compliance Checker — drop-in Express router
 *
 * Mount in your existing server:
 *   const validateRouter = require('./validator/validate-router');
 *   app.use('/validate', validateRouter);
 *
 * Serves the UI at GET /validate and the probe API at POST /validate/api
 *
 * Spec authority: x402-foundation/x402, commit b32a7023, protocol V2.
 * Dual-mode: detects body.x402Version and applies V1 or V2 field rules.
 * Output includes specVersion so callers know which rules were applied.
 */
const express = require('express');
const path = require('path');
const router = express.Router();

router.use(express.json());
router.use(express.static(path.join(__dirname, 'public')));

const TIMEOUT_MS = 10000;

// SSRF guard — always on, no env bypass.
const PRIVATE_HOST_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[::1\])/;

// CAIP-2 format per V2 §11.1: namespace:reference (e.g. eip155:8453, solana:5eykt4...)
const CAIP2_RE = /^[a-z][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9-]*$/;

function check(id, label, pass, detail, weight = 1, level = 'fail', rating = 'NORMATIVE') {
  return { id, label, pass: !!pass, detail, weight, level: pass ? 'pass' : level, rating };
}

async function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...opts,
      headers: { 'User-Agent': 'SolSigs-x402-validator/1.0', ...(opts.headers || {}) },
      signal: ctrl.signal,
      redirect: 'follow',
    });
  } finally {
    clearTimeout(t);
  }
}

router.post('/api', async (req, res) => {
  const { url } = req.body || {};
  const checks = [];
  let parsed;

  try {
    parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error('bad protocol');
  } catch {
    return res.status(400).json({ error: 'Provide a valid http(s) endpoint URL.' });
  }

  if (PRIVATE_HOST_RE.test(parsed.hostname)) {
    return res.status(400).json({ error: 'Private/loopback hosts are not allowed.' });
  }

  // ---- 1. Unpaid probe: expect HTTP 402 ----
  let probe, body402 = null;
  try {
    probe = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
  } catch (e) {
    return res.json({
      url, grade: 'F', score: 0, specVersion: 'unknown',
      checks: [check('reachable', 'Endpoint reachable [best-practice, non-normative]', false,
        `Request failed: ${e.message}`, 3, 'fail', 'BEST-PRACTICE')]
    });
  }

  checks.push(check('reachable', 'Endpoint reachable [best-practice, non-normative]', true,
    `Responded in time with HTTP ${probe.status}`, 3, 'fail', 'BEST-PRACTICE'));

  checks.push(check('status402', 'Returns HTTP 402 when unpaid', probe.status === 402,
    probe.status === 402
      ? 'Correct Payment Required status'
      : `Got HTTP ${probe.status} — unpaid requests must return 402`,
    3, 'fail', 'NORMATIVE'));

  try { body402 = await probe.json(); } catch { /* not JSON */ }
  checks.push(check('json402', '402 body is valid JSON', !!body402,
    body402 ? 'Parsed successfully' : 'Body is not parseable JSON — x402 clients will reject it',
    3, 'fail', 'NORMATIVE'));

  // Detect protocol version for dual-mode grading.
  // Default to V1 if field is absent (older servers that predate V2).
  const specVer = (body402 && typeof body402.x402Version === 'number') ? body402.x402Version : 1;
  const isV2 = specVer >= 2;

  // ---- 2. Schema checks on the 402 body ----
  if (body402) {
    const hasVersion = body402.x402Version !== undefined;
    checks.push(check('version', 'Declares x402Version', hasVersion,
      hasVersion ? `x402Version: ${body402.x402Version}` : 'Missing x402Version field',
      2, 'fail', 'NORMATIVE'));

    const accepts = Array.isArray(body402.accepts) ? body402.accepts : null;
    checks.push(check('accepts', 'Has non-empty accepts[] array', !!(accepts && accepts.length),
      accepts ? `${accepts.length} payment option(s) offered` : 'Missing or empty accepts array',
      3, 'fail', 'NORMATIVE'));

    if (accepts && accepts.length) {
      const a = accepts[0];

      // Check 6: required core fields (label now uses "amount" per V2)
      const required = ['scheme', 'network', 'payTo', 'asset'];
      const missing = required.filter(k => a[k] === undefined || a[k] === '');
      const amountMissing = a.maxAmountRequired === undefined && a.amount === undefined;
      checks.push(check('acceptFields', 'accepts[0] has scheme, network, payTo, amount, asset',
        missing.length === 0 && !amountMissing,
        missing.length ? `Missing: ${missing.join(', ')}` : 'All core payment fields present',
        3, 'fail', 'NORMATIVE'));

      // Check 7: amount field — V2 uses `amount`; V1 uses `maxAmountRequired`.
      // Resolve the correct field for this version, never silently pass the wrong one.
      const amountVal = isV2
        ? (a.amount !== undefined ? a.amount : a.maxAmountRequired)
        : (a.maxAmountRequired !== undefined ? a.maxAmountRequired : a.amount);
      const amountFieldName = isV2
        ? (a.amount !== undefined ? 'amount' : 'maxAmountRequired (V1 field — V2 expects "amount")')
        : (a.maxAmountRequired !== undefined ? 'maxAmountRequired' : 'amount');
      const amountPass = typeof amountVal === 'string' && /^\d+$/.test(amountVal);
      checks.push(check('amountStr', 'amount is an atomic-unit string',
        amountPass,
        `${amountFieldName}: ${JSON.stringify(amountVal)} — spec expects a string of base units (e.g. "2000" = 0.002 USDC)`,
        1, 'warn', 'NORMATIVE'));

      // Checks 8 & 9: resource / description.
      // V2: moved to top-level body.resource (ResourceInfo object) per V2 §5.1.2.
      // V1: lived inside each accepts[] entry.
      if (isV2) {
        const ri = (body402.resource && typeof body402.resource === 'object') ? body402.resource : null;
        checks.push(check('resourceField', 'body.resource.url present (V2: top-level ResourceInfo)',
          !!(ri && typeof ri.url === 'string' && ri.url.length > 0),
          ri && ri.url
            ? ri.url
            : 'Missing body.resource.url — V2 §5.1.2 moves resource out of accepts[] to a top-level ResourceInfo object',
          1, 'warn', 'RECOMMENDED'));

        checks.push(check('descField', 'body.resource.description present (V2: top-level ResourceInfo)',
          !!(ri && typeof ri.description === 'string' && ri.description.length > 0),
          ri && ri.description
            ? 'Present — helps agents choose the right endpoint'
            : 'Missing body.resource.description — optional in V2 but improves agent discoverability',
          1, 'warn', 'RECOMMENDED'));
      } else {
        checks.push(check('resourceField', 'accepts[0] declares resource URL (V1)',
          typeof a.resource === 'string' && a.resource.length > 0,
          a.resource
            ? a.resource
            : 'No resource field — recommended so clients can verify what they are paying for',
          1, 'warn', 'RECOMMENDED'));

        checks.push(check('descField', 'accepts[0] has a description (V1)',
          typeof a.description === 'string' && a.description.length > 0,
          a.description
            ? 'Present — helps agents choose the right endpoint'
            : 'No description — agents rank described endpoints higher',
          1, 'warn', 'RECOMMENDED'));
      }

      checks.push(check('timeoutField', 'Declares maxTimeoutSeconds', a.maxTimeoutSeconds !== undefined,
        a.maxTimeoutSeconds !== undefined
          ? `${a.maxTimeoutSeconds}s`
          : 'Missing — clients use this to bound the pay-and-retry window',
        1, 'warn', 'NORMATIVE'));

      // Check 11: network identifier.
      // V2 §11.1: MUST be CAIP-2 "namespace:reference" — bare names like "base" fail.
      // V1: permissive regex (no spec mandate for CAIP-2).
      const net = String(a.network || '');
      if (isV2) {
        const caip2Pass = CAIP2_RE.test(net);
        checks.push(check('network', 'Network is valid CAIP-2 format (V2: namespace:reference required)',
          caip2Pass,
          caip2Pass
            ? `network: ${net}`
            : `"${net}" is not CAIP-2 — V2 §11.1 requires "namespace:reference" (e.g. eip155:8453, solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp)`,
          2, 'fail', 'NORMATIVE'));
      } else {
        checks.push(check('network', 'Network identifier looks valid (V1)',
          /solana|base|polygon|avalanche|sei|ethereum|^eip155:|^solana:/i.test(net),
          net ? `network: ${net}` : 'Empty network field',
          2, 'fail', 'NORMATIVE'));
      }

      // Check 15 (new): PAYMENT-REQUIRED response header.
      // V2 transports-v2/http.md §"Payment Required Signaling": canonical wire location
      // is base64-encoded PaymentRequired JSON in the PAYMENT-REQUIRED header.
      // NORMATIVE for V2; informational/forward-compat for V1.
      const prHeader = probe.headers.get('payment-required');
      if (isV2) {
        let prValid = false;
        let prDetail = 'Missing PAYMENT-REQUIRED header — V2 transports-v2/http.md §"Payment Required Signaling" designates this as the canonical wire location (base64-encoded PaymentRequired JSON)';
        if (prHeader) {
          try {
            const decoded = JSON.parse(Buffer.from(prHeader, 'base64').toString('utf8'));
            prValid = typeof decoded === 'object' && decoded !== null;
            prDetail = prValid
              ? `Present and decodes to valid JSON (x402Version: ${decoded.x402Version})`
              : 'Present but base64 does not decode to valid JSON';
          } catch {
            prDetail = 'Present but base64 does not decode to valid JSON';
          }
        }
        checks.push(check('paymentRequiredHeader', 'PAYMENT-REQUIRED header present and valid (V2)',
          prValid, prDetail, 2, 'fail', 'NORMATIVE'));
      } else {
        checks.push(check('paymentRequiredHeader', 'PAYMENT-REQUIRED header (V2 feature)',
          !!prHeader,
          prHeader
            ? 'Present (forward-compatible with V2 clients)'
            : 'Absent — not required for V1, but V2 clients will look here first',
          1, 'warn', 'RECOMMENDED'));
      }
    }
  }

  // ---- 3. Discovery document ----
  // NOTE: /.well-known/x402.json is a SolSigs convention, NOT in the V2 spec.
  // V2 §8 defines a Bazaar /discovery/resources REST API instead.
  // These checks are best-practice only and do NOT affect normative compliance.
  try {
    const dUrl = `${parsed.protocol}//${parsed.host}/.well-known/x402.json`;
    const d = await fetchWithTimeout(dUrl);
    const okStatus = d.ok;
    let dBody = null;
    try { dBody = await d.json(); } catch {}
    checks.push(check('discovery', 'Serves /.well-known/x402.json [best-practice, non-normative]',
      okStatus && !!dBody,
      okStatus && dBody
        ? 'Discovery document found and parses as JSON'
        : `HTTP ${d.status} or invalid JSON at ${dUrl}`,
      2, 'fail', 'BEST-PRACTICE'));

    if (dBody) {
      const servers = dBody.servers || dBody.resources || dBody.endpoints;
      const count = Array.isArray(servers)
        ? servers.reduce((n, s) => n + (Array.isArray(s.endpoints) ? s.endpoints.length : 1), 0)
        : 0;
      checks.push(check('discoveryEndpoints', 'Discovery doc lists endpoints [best-practice, non-normative]',
        count > 0,
        count > 0 ? `${count} endpoint(s) declared` : 'No endpoints found in discovery document',
        1, 'warn', 'BEST-PRACTICE'));
    }
  } catch (e) {
    checks.push(check('discovery', 'Serves /.well-known/x402.json [best-practice, non-normative]',
      false, `Fetch failed: ${e.message}`, 2, 'fail', 'BEST-PRACTICE'));
  }

  // ---- 4. CORS for browser-based agent clients ----
  // NOTE: Not in the V2 spec. Practical requirement for browser wallets and embedded agents.
  try {
    const opt = await fetchWithTimeout(url, { method: 'OPTIONS' });
    const acao = opt.headers.get('access-control-allow-origin');
    checks.push(check('cors', 'CORS enabled for browser clients [best-practice, non-normative]',
      !!acao,
      acao
        ? `Access-Control-Allow-Origin: ${acao}`
        : 'No CORS headers — browser agents and embedded wallets cannot call this',
      1, 'warn', 'BEST-PRACTICE'));
  } catch {
    checks.push(check('cors', 'CORS enabled for browser clients [best-practice, non-normative]',
      false, 'OPTIONS preflight failed', 1, 'warn', 'BEST-PRACTICE'));
  }

  // ---- Grade ----
  const earned = checks.filter(c => c.pass).reduce((s, c) => s + c.weight, 0);
  const total = checks.reduce((s, c) => s + c.weight, 0);
  const score = Math.round((earned / total) * 100);
  const hardFails = checks.filter(c => !c.pass && c.level === 'fail').length;
  const grade = hardFails === 0 && score >= 90 ? 'A'
    : hardFails <= 1 && score >= 75 ? 'B'
    : score >= 60 ? 'C'
    : score >= 40 ? 'D' : 'F';

  res.json({ url, grade, score, specVersion: `x402v${specVer}`, checks, checkedAt: new Date().toISOString() });
});

module.exports = router;
