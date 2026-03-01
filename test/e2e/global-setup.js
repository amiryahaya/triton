// global-setup.js — Seeds the test database with 4 scans for E2E tests.
const { request } = require('@playwright/test');

const BASE_URL = 'http://localhost:8080';

function makeScan(id, hostname, safe, trans, dep, unsafe) {
  const total = safe + trans + dep + unsafe;
  const findings = [];
  let idx = 0;

  const add = (count, status, algo) => {
    for (let i = 0; i < count; i++) {
      findings.push({
        id: `f-${id}-${idx}`,
        category: 5,
        source: { type: 'file', path: `/test/path/${status}/${idx}` },
        cryptoAsset: {
          algorithm: algo,
          pqcStatus: status,
          keySize: 256,
          function: 'encryption',
        },
        module: 'certificates',
        confidence: 0.95,
        timestamp: new Date().toISOString(),
      });
      idx++;
    }
  };

  add(safe, 'SAFE', 'ML-KEM-768');
  add(trans, 'TRANSITIONAL', 'RSA-2048');
  add(dep, 'DEPRECATED', 'SHA-1');
  add(unsafe, 'UNSAFE', 'DES');

  return {
    id,
    metadata: {
      timestamp: new Date().toISOString(),
      hostname,
      os: 'linux',
      scanProfile: 'quick',
      toolVersion: '2.4.0-e2e',
    },
    findings,
    summary: {
      totalFindings: total,
      totalCryptoAssets: total,
      safe,
      transitional: trans,
      deprecated: dep,
      unsafe,
    },
  };
}

async function globalSetup() {
  const ctx = await request.newContext({ baseURL: BASE_URL });

  const scans = [
    makeScan('scan-e2e-001', 'web-server-01', 10, 5, 3, 2),
    makeScan('scan-e2e-002', 'web-server-01', 12, 6, 2, 1),
    makeScan('scan-e2e-003', 'db-server-01', 8, 4, 5, 3),
    makeScan('scan-e2e-004', 'db-server-01', 10, 3, 4, 2),
  ];

  for (const scan of scans) {
    const resp = await ctx.post('/api/v1/scans', { data: scan });
    if (resp.status() !== 201) {
      throw new Error(`Failed to seed scan ${scan.id}: ${resp.status()} ${await resp.text()}`);
    }
  }

  await ctx.dispose();
}

module.exports = globalSetup;
