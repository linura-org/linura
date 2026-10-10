/** Runtime entrypoint. Start ONLY from a trusted host/systemd, never Actions. */
import http from 'node:http';
import { configuration, verifyWebhook, GitHubClient, Publisher, FileApprovalJournal, trustedDecision } from './publisher.mjs';

const MAX_WEBHOOK_BYTES = 1024 * 1024;
const SWEEP_MS = 10 * 60 * 1000;

export function createServer(config, publisher, { maxBytes = MAX_WEBHOOK_BYTES } = {}) {
  const deliveries = new Set();
  return http.createServer(async (req, res) => {
    const respond = (status, message) => {
      res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      res.end(`${message}\n`);
    };
    if (req.method === 'GET' && req.url === '/health/live') return respond(200, 'alive');
    if (req.method === 'GET' && req.url === '/health/ready') {
      const age = publisher.lastCompleted ? Date.now() - Date.parse(publisher.lastCompleted) : NaN;
      const healthy = config.enabled && !publisher.lastError && !publisher.reconciling &&
        !publisher.pendingSweep && !publisher.epoch && Number.isFinite(age) &&
        age >= 0 && age < 2 * SWEEP_MS;
      return respond(healthy ? 200 : 503, healthy ? 'ready' : 'not ready');
    }
    if (req.method !== 'POST' || req.url !== '/github/webhook') return respond(404, 'not found');
    const pieces = [];
    let size = 0;
    try {
      for await (const part of req) {
        size += part.length;
        if (size > maxBytes) return respond(413, 'payload too large');
        pieces.push(part);
      }
      const raw = Buffer.concat(pieces);
      if (!verifyWebhook(config.webhookSecret, raw, req.headers['x-hub-signature-256'])) {
        return respond(401, 'invalid signature');
      }
      const delivery = req.headers['x-github-delivery'];
      if (typeof delivery !== 'string' || !/^[0-9a-f-]{36}$/i.test(delivery)) {
        return respond(400, 'invalid delivery ID');
      }
      let event;
      try { event = JSON.parse(raw.toString('utf-8')); }
      catch { return respond(400, 'invalid JSON'); }
      if (event?.repository?.full_name !== config.repository) return respond(403, 'repository mismatch');
      const kind = req.headers['x-github-event'];
      if (!['pull_request', 'push', 'workflow_run', 'check_run', 'installation'].includes(kind)) {
        return respond(202, 'ignored event');
      }
      // Our own Check Runs emit check_run webhooks. Re-enqueuing on those
      // would create an unbounded self-triggered check-run storm.
      if (kind === 'check_run' && event.check_run?.app?.id === config.appId &&
          event.action !== 'rerequested') {
        // Normal created/completed webhooks must never recursively schedule
        // another check. A maintainer's explicit rerequest still deserves a
        // fresh independent decision even if the normal scan has not run.
        return respond(202, 'self-generated check ignored');
      }
      if (deliveries.has(delivery)) return respond(202, 'duplicate delivery');
      deliveries.add(delivery);
      if (deliveries.size > 8192) deliveries.delete(deliveries.values().next().value);
      publisher.schedule(); // GitHub payload never supplies an authorization verdict.
      return respond(202, 'accepted for independent reconciliation');
    } catch {
      return respond(400, 'invalid webhook request');
    }
  });
}

export async function runServer(env = process.env) {
  // The operator must deploy the same security-reviewed Node build as CI;
  // do not silently run a stale distribution-managed binary.
  if (process.versions.node !== '22.23.3') {
    throw new Error('qualification publisher requires pinned Node.js 22.23.3');
  }
  const config = configuration(env);
  // STATE_DIRECTORY is provisioned with 0700 permissions by systemd.
  // A missing journal during an enabled rollout is a security incident: a
  // previously green App check could outlive a lost local authorization log.
  // Bootstrap is an explicit *disabled-mode*, one-time operator action.
  const allowInitialization = env.PUBLISHER_LEDGER_INIT === 'true' && !config.enabled;
  const journal = new FileApprovalJournal(env.STATE_DIRECTORY, {
    initialize: allowInitialization,
  });
  const client = new GitHubClient(config);
  const publisher = new Publisher({ client, journal, enabled: config.enabled,
    decide: (token, head, signal) => trustedDecision(config, token, head, signal) });
  const server = createServer(config, publisher);
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.maxRequestsPerSocket = 100;
  server.listen(config.port, config.host);
  // Recovery independent of webhooks: a GitHub delivery can be delayed or
  // lost; a trusted host must poll current open PR inventory on startup.
  publisher.schedule();
  const interval = setInterval(() => publisher.schedule({ periodic: true }), SWEEP_MS);
  const shutdown = () => {
    clearInterval(interval);
    server.close(() => process.exit(0));
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return { server, publisher };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runServer().catch(error => {
    console.error(`qualification publisher startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}
