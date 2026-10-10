import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, createVerify } from 'node:crypto';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, mkdirSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { createServer } from '../server.mjs';
import { GitHubClient, Publisher, MemoryApprovalJournal, FileApprovalJournal, configuration,
  MAX_HEADS, MAX_PARALLEL_HEADS, API_TIMEOUT_MS, DECISION_TIMEOUT_MS, HEAD_TIMEOUT_MS, SWEEP_TIMEOUT_MS,
  createAppJwt, secureSecretFile, verifyTrustedSourceTree, validateDecision,
  verifyWebhook, trustedDecision, runSanitizedVerifier } from '../publisher.mjs';

const head = 'a'.repeat(40);
const base = 'b'.repeat(40);
const base2 = 'c'.repeat(40);
const repository = 'linura-org/linura';
const mergeSha = pr => pr.number.toString(16).padStart(40, 'f');
const PR = (number = 7, baseSha = base, headSha = head) => ({
  number, head: { sha: headSha }, base: { ref: 'main', sha: baseSha },
});
function valid(prs = [PR()]) {
  return { schema_version: 1, repository, head_sha: head, state: 'success',
    prs: prs.map(p => ({ number: p.number, head_sha: p.head.sha, base_sha: p.base.sha,
      base_ref: 'main', required_gate_ids: ['canonical-ci', 'security-rustsec', 'codeql', 'v010-workstation'],
      accepted_gate_ids: ['canonical-ci', 'security-rustsec', 'codeql', 'v010-workstation'] })) };
}
function fakeClient(inventories) {
  const calls = [], queue = [...inventories];
  return { config: { repository }, calls,
    pulls: async () => structuredClone(queue.length > 1 ? queue.shift() : queue[0] || []),
    createCheck: async (sha) => { calls.push(['start', sha]); return calls.length; },
    mergeTarget: async pr => mergeSha(pr),
    concludeCheck: async (id, conclusion, explanation) => calls.push([conclusion, id, explanation]),
    token: async kind => { calls.push(['token', kind]); return `${kind}-limited-token`; },
  };
}

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });

// App identity and secret-handling tests.
test('App JWT is RS256 signed and short lived with clock skew', () => {
  const jwt = createAppJwt(41, privateKey, Date.UTC(2026, 9, 9));
  const [header, claims, signature] = jwt.split('.');
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'RS256');
  const payload = JSON.parse(Buffer.from(claims, 'base64url'));
  assert.equal(payload.iss, '41');
  assert.equal(payload.exp - payload.iat, 540);
  assert.equal(createVerify('RSA-SHA256').update(`${header}.${claims}`).end()
    .verify(publicKey, Buffer.from(signature, 'base64url')), true);
});
test('HMAC webhook signature cannot be spoofed by untrusted payloads', () => {
  const secret = Buffer.from('a sufficiently long webhook secret');
  const body = Buffer.from('{"repository":{"full_name":"linura-org/linura"}}');
  const signature = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
  assert.equal(verifyWebhook(secret, body, signature), true);
  assert.equal(verifyWebhook(secret, Buffer.concat([body, Buffer.from('!')]), signature), false);
  assert.equal(verifyWebhook(secret, body, 'sha256=' + 'f'.repeat(64)), false);
  assert.equal(verifyWebhook(secret, body, ''), false);
  assert.equal(verifyWebhook(secret, body, 'sha256=ab'), false);
});
test('private keys must be private regular files, not symlinks', () => {
  const root = mkdtempSync(join(tmpdir(), 'linura-app-'));
  const path = join(root, 'secret');
  writeFileSync(path, privatePem, { mode: 0o600 });
  assert.equal(secureSecretFile(path).toString(), privatePem);
  chmodSync(path, 0o640);
  assert.throws(() => secureSecretFile(path), /non-symlink regular file/);
  chmodSync(path, 0o600);
  const link = join(root, 'link');
  symlinkSync(path, link);
  assert.throws(() => secureSecretFile(link), /non-symlink regular file/);
});
test('entire immutable trusted source tree rejects writable ancestors, helpers, and symlinks', () => {
  const root = mkdtempSync(join(tmpdir(), 'linura-trusted-tree-'));
  const tools = join(root, 'tools');
  const contracts = join(root, 'contracts');
  mkdirSync(tools, { mode: 0o700 });
  mkdirSync(contracts, { mode: 0o700 });
  const script = join(tools, 'applicable_qualification.py');
  const helper = join(tools, 'imported_helper.py');
  const matrix = join(contracts, 'qualification-gate-matrix.toml');
  writeFileSync(script, 'import imported_helper\\n', { mode: 0o600 });
  writeFileSync(helper, 'TRUSTED = True\\n', { mode: 0o600 });
  writeFileSync(matrix, 'schema_version = 1\\n', { mode: 0o600 });
  const uid = process.getuid();
  assert.equal(verifyTrustedSourceTree(root, uid), script);
  chmodSync(tools, 0o770);
  assert.throws(() => verifyTrustedSourceTree(root, uid), /root-owned immutable verifier/);
  chmodSync(tools, 0o700);
  assert.equal(verifyTrustedSourceTree(root, uid), script);
  chmodSync(helper, 0o666);
  assert.throws(() => verifyTrustedSourceTree(root, uid), /root-owned immutable verifier/);
  chmodSync(helper, 0o600);
  chmodSync(matrix, 0o620);
  assert.throws(() => verifyTrustedSourceTree(root, uid), /root-owned immutable verifier/);
  chmodSync(matrix, 0o600);
  assert.equal(verifyTrustedSourceTree(root, uid), script);

  // The attacker's directory cannot substitute for the verifier itself.
  const substitute = join(root, 'substitute');
  mkdirSync(substitute, { mode: 0o700 });
  symlinkSync(script, join(substitute, 'replacement.py'));
  assert.throws(() => verifyTrustedSourceTree(root, uid), /root-owned immutable verifier/);

  const fresh = mkdtempSync(join(tmpdir(), 'linura-parent-drift-'));
  const nested = join(fresh, 'checkout');
  mkdirSync(nested, { mode: 0o700 });
  mkdirSync(join(nested, 'tools'), { mode: 0o700 });
  writeFileSync(join(nested, 'tools', 'applicable_qualification.py'), 'pass\\n',
    { mode: 0o600 });
  assert.equal(verifyTrustedSourceTree(nested, uid),
    join(nested, 'tools', 'applicable_qualification.py'));
  chmodSync(fresh, 0o777);
  assert.throws(() => verifyTrustedSourceTree(nested, uid), /root-owned immutable verifier/);
});

test('service rejects unsafely enabled config and wrong repository', () => {
  const root = mkdtempSync(join(tmpdir(), 'linura-config-'));
  const pem = join(root, 'key'); const secret = join(root, 'webhook');
  writeFileSync(pem, privatePem, { mode: 0o600 });
  writeFileSync(secret, '12345678901234567890', { mode: 0o600 });
  const good = { PUBLISHER_REPOSITORY: repository, PUBLISHER_APP_ID: '41',
    PUBLISHER_INSTALLATION_ID: '42', PUBLISHER_KEY_FILE: pem,
    PUBLISHER_WEBHOOK_SECRET_FILE: secret, PUBLISHER_TRUSTED_REPO: root };
  assert.equal(configuration(good).enabled, false);
  assert.throws(() => configuration({ ...good, PUBLISHER_ENABLED: 'yes' }), /invalid PUBLISHER_ENABLED/);
  assert.throws(() => configuration({ ...good, PUBLISHER_REPOSITORY: 'other/repo' }), /repository must/);
  assert.throws(() => configuration({ ...good, PUBLISHER_HOST: '0.0.0.0' }), /bind host must/);
  assert.throws(() => configuration({ ...good, PUBLISHER_ENABLED: 'true' }),
    /root-owned immutable verifier|ENOENT/);
});

// Admission is independent of PR-authored check labels.
test('exact-head decision accepts only all reviewed required gates', () => {
  assert.equal(validateDecision(valid(), repository, head, [PR()]), 'success');
  assert.throws(() => validateDecision(valid(), repository, 'd'.repeat(40), [PR()]), /identity/);
  const changed = valid(); changed.prs[0].base_sha = base2;
  assert.throws(() => validateDecision(changed, repository, head, [PR()]), /identity/);
  const missing = valid(); missing.prs[0].required_gate_ids = ['v010-workstation'];
  missing.prs[0].accepted_gate_ids = ['v010-workstation'];
  assert.throws(() => validateDecision(missing, repository, head, [PR()]), /mandatory/);
  const spoof = valid(); spoof.prs[0].accepted_gate_ids.pop();
  assert.throws(() => validateDecision(spoof, repository, head, [PR()]), /unaccepted/);
  const forged = valid(); forged.prs[0].accepted_gate_ids.push('unreviewed-new-gate');
  assert.throws(() => validateDecision(forged, repository, head, [PR()]), /invalid/);
});
test('one success cannot authorize two PRs sharing the same commit', () => {
  assert.throws(() => validateDecision(valid(), repository, head, [PR(7), PR(8)]), /cardinality/);
  const both = valid([PR(7), PR(8)]);
  assert.equal(validateDecision(both, repository, head, [PR(7), PR(8)]), 'success');
  both.prs[1].base_sha = base2;
  assert.throws(() => validateDecision(both, repository, head, [PR(7), PR(8)]), /identity/);
});
test('pending or failing policy never yields success', () => {
  for (const state of ['pending', 'failure']) {
    const receipt = valid(); receipt.state = state;
    assert.equal(validateDecision(receipt, repository, head, [PR()]), state);
  }
});
test('publishes in-progress first and completes only independently verified success', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => valid(), enabled: true });
  await publisher.sweep();
  assert.deepEqual(client.calls.map(c => c[0]), ['start', 'token', 'start', 'success']);
  assert.equal(client.calls[2][1], mergeSha(PR()));
  assert.equal(client.calls[3][1], 3);
  assert.equal(client.calls[0][1], head);
});
test('a PR opened after verification cannot inherit an approved contributor head', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const journal = new MemoryApprovalJournal();
  const publisher = new Publisher({ journal, client, enabled: true, decide: async () => valid() });
  await publisher.sweep();
  const later = PR(8);
  assert.notEqual(mergeSha(PR()), mergeSha(later), 'PR merge refs must be unique');
  const created = client.calls.filter(c => c[0] === 'start').map(c => c[1]);
  assert.deepEqual(created, [head, mergeSha(PR())]);
  assert.deepEqual(journal.list(), [mergeSha(PR())]);
  const successId = client.calls.find(c => c[0] === 'success')[1];
  assert.equal(successId, 3, 'only the PR-specific merge check is successful');
  assert.ok(!created.includes(mergeSha(later)),
    'a newly opened PR has no App approval even when it points to the same head');
});

test('GitHub synthetic merge checks reject stale parents and foreign PR refs', async () => {
  const pull = PR();
  const merge = mergeSha(pull);
  const responses = [];
  const call = async (url, opts) => {
    if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
      json: async () => ({ token: 'app-read', expires_at: new Date(Date.now()+3600_000).toISOString() }) };
    const result = url.endsWith('/pulls/7')
      ? { number: 7, state: 'open', head: { sha: head }, base: { sha: base, ref: 'main' } }
      : url.endsWith('/git/ref/pull/7/merge')
        ? { ref: 'refs/pull/7/merge', object: { type: 'commit', sha: merge } }
        : { sha: merge, parents: [{ sha: base }, { sha: head }] };
    responses.push(url);
    return { ok: true, status: 200, json: async () => result };
  };
  const client = new GitHubClient({ repository, appId: 41, installationId: 42, privateKey }, call);
  assert.equal(await client.mergeTarget(pull), merge);
  assert.deepEqual(responses.map(url => url.split('/').slice(-3).join('/')),
    ['linura/pulls/7', 'pull/7/merge', 'git/commits/' + merge]);
  const changed = new GitHubClient({ repository, appId: 41, installationId: 42, privateKey },
    async (url, opts) => {
      const result = await call(url, opts);
      if (url.endsWith('/git/commits/' + merge)) return { ok: true, status: 200,
        json: async () => ({ sha: merge, parents: [{ sha: base2 }, { sha: head }] }) };
      return result;
    });
  await assert.rejects(changed.mergeTarget(pull), /parents do not match/);
});

test('two PRs with an identical test-merge SHA are denied rather than sharing a check', async () => {
  const prs = [PR(), PR(8)];
  const client = fakeClient([prs, prs]);
  client.mergeTarget = async () => 'd'.repeat(40);
  const pub = new Publisher({ journal: new MemoryApprovalJournal(), client, enabled: true,
    decide: async () => valid(prs) });
  await assert.rejects(pub.sweep(), /test-merge identity is not unique/);
  assert.equal(client.calls.some(c => c[0] === 'success'), false);
});

test('a missing verifier never creates a successful check', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => { throw new Error('decision-head unavailable'); }, enabled: true });
  await assert.rejects(publisher.sweep(), /decision-head unavailable/);
  assert.equal(client.calls[0][0], 'start');
  assert.equal(client.calls.at(-1)[0], 'failure');
});
test('a base change between verification and publication denies success', async () => {
  const client = fakeClient([[PR()], [PR(7, base2)]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => valid(), enabled: true });
  await assert.rejects(publisher.sweep(), /PR inventory changed/);
  assert.equal(client.calls.at(-1)[0], 'failure');
});
test('a new PR sharing an already-successful head blocks its new receipt', async () => {
  const client = fakeClient([[PR()], [PR(), PR(8)]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => valid(), enabled: true });
  await assert.rejects(publisher.sweep(), /PR inventory changed/);
  assert.equal(client.calls.at(-1)[0], 'failure');
});
test('pending verifier leaves check in-progress rather than reporting success', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const receipt = valid(); receipt.state = 'pending';
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => receipt, enabled: true });
  await publisher.sweep();
  assert.equal(client.calls.at(-1)[0], 'token');
});
test('disabled publisher never calls the GitHub API', async () => {
  const client = fakeClient([[PR()]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, decide: async () => valid(), enabled: false });
  publisher.schedule(); await publisher.active;
  assert.deepEqual(client.calls, []);
});
test('malformed GitHub pagination or token responses fail closed', async () => {
  const config = { repository, installationId: 3, appId: 5, privateKey };
  const invalid = new GitHubClient(config, async () => ({ ok: true, status: 201, json: async () => ({ token: 'ok' }) }));
  await assert.rejects(() => invalid.token('read'), /token response invalid/);
  const response = new GitHubClient(config, async () => ({ ok: false, status: 403 }));
  await assert.rejects(() => response.token('write'), /HTTP 403/);
});
test('an App-owned prior check is invalidated and reused instead of flooding checks', async () => {
  const calls = [];
  const existing = { id: 913, name: 'linura/applicable-qualification', head_sha: head,
    app: { id: 41 }, status: 'completed', conclusion: 'success' };
  const client = new GitHubClient({ repository, installationId: 42, appId: 41, privateKey },
    async (url, opts) => {
      calls.push({ url, method: opts.method, body: opts.body && JSON.parse(opts.body) });
      if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
        json: async () => ({ token: 'only-app-token', expires_at:
          new Date(Date.now() + 3600_000).toISOString() }) };
      if (url.includes('/commits/')) return { ok: true, status: 200,
        json: async () => ({ total_count: 1, check_runs: [existing] }) };
      if (url.endsWith('/check-runs/913')) return { ok: true, status: 200,
        json: async () => ({ ...existing, status: 'in_progress', conclusion: null }) };
      throw new Error(`unexpected GitHub API call: ${url}`);
    });
  assert.equal(await client.createCheck(head, 'retry'), 913);
  assert.equal(await client.createCheck(head, 'retry'), 913);
  assert.equal(calls.filter(c => c.method === 'POST' && c.url.endsWith('/check-runs')).length, 0);
  assert.equal(calls.filter(c => c.method === 'PATCH').length, 2);
  assert.ok(calls.filter(c => c.method === 'PATCH').every(c => c.body.status === 'in_progress'));
});

test('an HTTP 200 that leaves a previous green check completed is not invalidation', async () => {
  const old = { id: 913, name: 'linura/applicable-qualification', head_sha: head,
    app: { id: 41 }, status: 'completed', conclusion: 'success' };
  const client = new GitHubClient({ repository, installationId: 42, appId: 41, privateKey },
    async url => {
      if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
        json: async () => ({ token: 'app-token', expires_at:
          new Date(Date.now() + 3600_000).toISOString() }) };
      if (url.includes('/commits/')) return { ok: true, status: 200,
        json: async () => ({ total_count: 1, check_runs: [old] }) };
      return { ok: true, status: 200, json: async () => old };
    });
  await assert.rejects(() => client.createCheck(head, 'invalidate'),
    /prior App check invalidation not confirmed/);
});

test('foreign-App and ambiguous check identities do not authorize a trusted run', async () => {
  const old = { id: 913, name: 'linura/applicable-qualification', head_sha: head,
    app: { id: 41 }, status: 'completed' };
  const invalid = [
    { total_count: 101, check_runs: [old] },
    { total_count: 2, check_runs: [old] },
    { total_count: 2, check_runs: [old, { ...old, id: 914 }] },
    { total_count: 1, check_runs: [{ ...old, app: { id: 42 } }] },
    { total_count: 1, check_runs: [{ ...old, head_sha: 'f'.repeat(40) }] },
    { total_count: 1, check_runs: [{ ...old, name: 'other/context' }] },
    { total_count: 1, check_runs: [{ ...old, id: null }] },
  ];
  for (const reply of invalid) {
    const client = new GitHubClient({ repository, installationId: 42, appId: 41, privateKey },
      async (url) => {
        if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
          json: async () => ({ token: 'only-app-token', expires_at:
            new Date(Date.now() + 3600_000).toISOString() }) };
        return { ok: true, status: 200, json: async () => reply };
      });
    await assert.rejects(() => client.createCheck(head, 'retry'), /unbounded|ambiguous/);
  }
});

test('App check conclusions must be bound to the exact created identity and confirmed state', async () => {
  const created = { id: 941, name: 'linura/applicable-qualification',
    head_sha: head, app: { id: 41 }, status: 'in_progress', conclusion: null };
  const success = { ...created, status: 'completed', conclusion: 'success' };
  for (const [label, response] of [
    ['correct confirmation', success],
    ['foreign App', { ...success, app: { id: 42 } }],
    ['wrong SHA', { ...success, head_sha: 'f'.repeat(40) }],
    ['still running', { ...success, status: 'in_progress', conclusion: null }],
    ['wrong conclusion', { ...success, conclusion: 'neutral' }],
    ['wrong ID', { ...success, id: 942 }],
    ['missing result', null],
  ]) {
    const client = new GitHubClient({ repository, installationId: 42,
      appId: 41, privateKey }, async (url, opts) => {
      if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
        json: async () => ({ token: 'app-token', expires_at:
          new Date(Date.now() + 3600_000).toISOString() }) };
      if (url.includes('/commits/')) return { ok: true, status: 200,
        json: async () => ({ total_count: 0, check_runs: [] }) };
      if (url.endsWith('/check-runs')) return { ok: true, status: 201,
        json: async () => created };
      if (url.endsWith('/check-runs/941')) return { ok: true, status: 200,
        json: async () => response };
      throw Error('unexpected mocked GitHub request');
    });
    const id = await client.createCheck(head, 'exact head');
    assert.equal(id, 941);
    if (label === 'correct confirmation') {
      assert.equal((await client.concludeCheck(id, 'success', 'reviewed')).conclusion, 'success');
    } else {
      await assert.rejects(
        client.concludeCheck(id, 'success', 'reviewed'),
        /App-owned check conclusion not confirmed/,
        label,
      );
    }
    await assert.rejects(
      client.concludeCheck(942, 'success', 'unbound'),
      /missing verified App\/head binding/,
    );
  }
});

test('duplicate or wrong-head GitHub PR inventories are never trusted', () => {
  assert.throws(() => validateDecision(valid([PR(), PR()]), repository, head, [PR(), PR()]), /ambiguous/);
  assert.throws(() => validateDecision(valid(), repository, head, [PR(7, base, 'd'.repeat(40))]), /malformed/);
});

test('installation tokens use distinct read and write permissions', async () => {
  const calls = [];
  const client = new GitHubClient({ repository, installationId: 3, appId: 5, privateKey }, async (_url, opts) => {
    calls.push(JSON.parse(opts.body));
    return { ok: true, status: 201, json: async () => ({ token: `token-${calls.length}`,
      expires_at: new Date(Date.now() + 3600_000).toISOString() }) };
  });
  await client.token('read'); await client.token('write'); await client.token('read');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].permissions, { actions: 'read', checks: 'read', contents: 'read', pull_requests: 'read' });
  assert.deepEqual(calls[1].permissions, { checks: 'write' });
  assert.deepEqual(calls[0].repositories, ['linura']);
});

// Webhooks are triggers, not decisions.
test('webhook requires HMAC and correct repository, never trusts forged decisions', async () => {
  const secret = Buffer.from('012345678901234567890123456789');
  const triggered = [];
  const server = createServer({ repository, webhookSecret: secret, enabled: true, appId: 41 }, {
    schedule: () => triggered.push(1), lastError: null,
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = `http://127.0.0.1:${server.address().port}`;
  let number = 1;
  const delivery = () => `00000000-0000-4000-8000-${String(number++).padStart(12, '0')}`;
  const post = async (value, signed = true, duplicate) => {
    const raw = Buffer.from(JSON.stringify(value));
    const signature = 'sha256=' + createHmac('sha256', secret).update(raw).digest('hex');
    return await fetch(address + '/github/webhook', { method: 'POST', body: raw,
      headers: { 'x-hub-signature-256': signed ? signature : 'bad',
        'x-github-delivery': duplicate || delivery(), 'x-github-event': 'workflow_run' } });
  };
  try {
    assert.equal((await post({ repository: { full_name: repository } }, false)).status, 401);
    assert.equal((await post({ repository: { full_name: 'attacker/repo' } })).status, 403);
    const hostile = { repository: { full_name: repository }, decision: { state: 'success' } };
    assert.equal((await post(hostile)).status, 202);
    assert.equal(triggered.length, 1);
    assert.equal((await post(hostile, true, '00000000-0000-4000-8000-000000000003')).status, 202);
    assert.equal(triggered.length, 1);
    const self = { repository: { full_name: repository }, check_run: { app: { id: 41 } } };
    const raw = Buffer.from(JSON.stringify(self));
    const sig = 'sha256=' + createHmac('sha256', secret).update(raw).digest('hex');
    assert.equal((await fetch(address + '/github/webhook', { method: 'POST', body: raw, headers: {
      'x-hub-signature-256': sig, 'x-github-delivery': delivery(),
      'x-github-event': 'check_run',
    } })).status, 202);
    assert.equal(triggered.length, 1);
    const rerequest = { ...self, action: 'rerequested' };
    const rerequestRaw = Buffer.from(JSON.stringify(rerequest));
    const rerequestSig = 'sha256=' +
      createHmac('sha256', secret).update(rerequestRaw).digest('hex');
    assert.equal((await fetch(address + '/github/webhook', {
      method: 'POST', body: rerequestRaw, headers: {
        'x-hub-signature-256': rerequestSig, 'x-github-delivery': delivery(),
        'x-github-event': 'check_run',
      },
    })).status, 202);
    assert.equal(triggered.length, 2);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('a new App-owned check is created only when no prior matching run exists', async () => {
  const calls = [];
  const client = new GitHubClient({ repository, installationId: 42, appId: 41, privateKey },
    async (url, opts) => {
      calls.push({ url, method: opts.method, body: opts.body && JSON.parse(opts.body) });
      if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
        json: async () => ({ token: 'only-app-token', expires_at:
          new Date(Date.now() + 3600_000).toISOString() }) };
      if (url.includes('/commits/')) return { ok: true, status: 200,
        json: async () => ({ total_count: 0, check_runs: [] }) };
      if (url.endsWith('/check-runs')) return { ok: true, status: 201,
        json: async () => ({ id: 941, name: 'linura/applicable-qualification',
          head_sha: head, app: { id: 41 }, status: 'in_progress' }) };
      throw new Error('unexpected call');
    });
  assert.equal(await client.createCheck(head, 'first verification'), 941);
  assert.equal(calls.filter(c => c.method === 'POST' && c.url.endsWith('/check-runs')).length, 1);
  assert.ok(calls.some(c => c.url.includes('app_id=41&filter=latest')));
});

test('GitHub check response cannot inject a foreign publisher identity', async () => {
  const client = new GitHubClient({ repository, installationId: 42, appId: 41, privateKey },
    async (url) => {
      if (url.endsWith('/access_tokens')) return { ok: true, status: 201,
        json: async () => ({ token: 'only-app-token', expires_at:
          new Date(Date.now() + 3600_000).toISOString() }) };
      if (url.includes('/commits/')) return { ok: true, status: 200,
        json: async () => ({ total_count: 0, check_runs: [] }) };
      return { ok: true, status: 201, json: async () => ({ id: 99,
        head_sha: head, name: 'linura/applicable-qualification', app: { id: 42 } }) };
    });
  await assert.rejects(() => client.createCheck(head, 'first verification'), /identity mismatch/);
});

test('readiness requires successful recent sweeps, never just an enabled flag', async () => {
  const secret = Buffer.from('012345678901234567890123456789');
  const pub = { schedule() {}, lastError: null, lastCompleted: null };
  const server = createServer({ repository, webhookSecret: secret, enabled: true, appId: 41 }, pub);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const address = `http://127.0.0.1:${server.address().port}/health/ready`;
    assert.equal((await fetch(address)).status, 503);
    pub.lastCompleted = new Date().toISOString();
    assert.equal((await fetch(address)).status, 200);
    pub.lastError = 'GitHub quota depleted';
    assert.equal((await fetch(address)).status, 503);
    pub.lastError = null;
    pub.lastCompleted = new Date(Date.now() + 25 * 60_000).toISOString();
    assert.equal((await fetch(address)).status, 503);
    pub.lastCompleted = new Date(Date.now() - 25 * 60_000).toISOString();
    assert.equal((await fetch(address)).status, 503);
  } finally {
    server.close(); await once(server, 'close');
  }
});

// Contract: all legitimate verification and identity/publication phases must
// fit even when API requests approach their individual timeout ceilings.
test('nested verifier, GitHub and journal publication budgets fit full bounded sweep', () => {
  const maxSharedPrs = 8;
  const waves = Math.ceil(MAX_HEADS / MAX_PARALLEL_HEADS);
  const apiRoundsPerHead = 1 + 1 + 2 * 3 +
    (1 + 2 * Math.ceil(maxSharedPrs / MAX_PARALLEL_HEADS)) +
    Math.ceil(maxSharedPrs / MAX_PARALLEL_HEADS);
  assert.ok(HEAD_TIMEOUT_MS >= DECISION_TIMEOUT_MS +
    apiRoundsPerHead * API_TIMEOUT_MS + 45_000,
  'verifier must not consume all time needed for PR-specific checks');
  assert.ok(SWEEP_TIMEOUT_MS >= HEAD_TIMEOUT_MS +
    (1 + 2 * waves * 3) * API_TIMEOUT_MS + 90_000,
  'one bounded step must fit prior-success and contributor-head invalidation');
  assert.ok(SWEEP_TIMEOUT_MS < 20 * 60_000,
  'reconciliation must not depend on one multi-wave 33-minute deadline');
});

test('a slow successful verifier still leaves time for live merge checks and publication', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
  for (const key of ['pulls', 'createCheck', 'mergeTarget', 'concludeCheck']) {
    const original = client[key].bind(client);
    client[key] = async (...args) => { await delay(15); return original(...args); };
  }
  const journal = new MemoryApprovalJournal();
  const pub = new Publisher({ client, journal, enabled: true, headTimeoutMs: 800,
    decide: async () => { await delay(500); return valid(); } });
  await pub.sweep();
  assert.equal(client.calls.filter(c => c[0] === 'success').length, 1);
  assert.deepEqual(journal.list(), [mergeSha(PR())]);
});

// Adversarial scheduling and health proofs for the independent authority.
test('each bounded step checkpoints progress without re-revoking earlier batches', async () => {
  const prs = Array.from({ length: 12 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const journal = new MemoryApprovalJournal();
  const client = fakeClient([prs]);
  const pub = new Publisher({ journal, client, enabled: true,
    decide: async (_, sha) => ({ ...valid([prs.find(pr => pr.head.sha === sha)]), head_sha: sha }) });
  assert.deepEqual(await pub.sweepStep(), { complete: false, remaining: 8 });
  assert.equal(journal.list().length, 4);
  assert.equal(client.calls.filter(c => c[0] === 'start').length, 16);
  assert.deepEqual(new Set(client.calls.slice(0, 12).map(c => c[1])),
    new Set(prs.map(pr => pr.head.sha)), 'all contributor heads must first become non-passing');
  assert.deepEqual(await pub.sweepStep(), { complete: false, remaining: 4 });
  assert.equal(journal.list().length, 8);
  assert.deepEqual(await pub.sweepStep(), { complete: true, remaining: 0 });
  assert.equal(journal.list().length, 12);
  assert.equal(client.calls.filter(c => c[0] === 'start').length, 24,
    'continued batches must not revoke already processed merge checks');
  assert.equal(pub.epoch, null);
});

test('restart after partial publication revokes durable approvals before rebuilding', async () => {
  const prs = Array.from({ length: 8 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const journal = new MemoryApprovalJournal();
  const decide = async (_, sha) => ({ ...valid([prs.find(pr => pr.head.sha === sha)]), head_sha: sha });
  const former = new Publisher({ client: fakeClient([prs]), journal, decide, enabled: true });
  await former.sweepStep();
  const old = journal.list();
  assert.equal(old.length, 4);
  const client = fakeClient([prs]);
  const recovered = new Publisher({ client, journal, decide, enabled: true });
  await recovered.sweepStep();
  assert.deepEqual(client.calls.slice(0, 4).map(c => c[1]), old,
    'recovery MUST first revoke every possibly green PR merge check');
  assert.equal(journal.list().length, 4);
});

test('new evidence supersedes pending batches and forces journal-first revocation', async () => {
  const prs = Array.from({ length: 8 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const journal = new MemoryApprovalJournal();
  const client = fakeClient([prs]);
  const pub = new Publisher({ client, journal, enabled: true,
    decide: async (_, sha) => ({ ...valid([prs.find(pr => pr.head.sha === sha)]), head_sha: sha }) });
  await pub.sweepStep();
  assert.equal(journal.list().length, 4);
  pub.reconciliationGeneration++;
  await assert.rejects(pub.sweepStep(), /superseded/);
  assert.equal(pub.epoch, null);
  await pub.sweepStep();
  assert.deepEqual(client.calls.filter(c => c[0] === 'start').slice(12, 16).map(c => c[1]),
    prs.slice(0, 4).map(mergeSha),
    'new epochs must first revoke all prior possibly successful merge checks');
});

test('periodic ticks cannot starve a multi-batch reconciliation', async () => {
  const pub = new Publisher({ client: fakeClient([PR()]), journal: new MemoryApprovalJournal(),
    enabled: true, decide: async () => valid() });
  pub.reconciling = true;
  pub.epoch = { generation: 5, candidates: [], cursor: 0 };
  pub.reconciliationGeneration = 5;
  pub.schedule({ periodic: true });
  assert.equal(pub.reconciliationGeneration, 5);
  assert.equal(pub.epoch.generation, 5);
  assert.equal(pub.pendingSweep, false);
  assert.equal(pub.periodicRescanDue, true);
});

test('a skipped periodic poll runs after the active epoch instead of starving it', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  let release;
  const block = new Promise(resolve => { release = resolve; });
  let verdicts = 0;
  const pub = new Publisher({ client, journal: new MemoryApprovalJournal(), enabled: true,
    decide: async () => { if (++verdicts === 1) await block; return valid(); } });
  pub.schedule();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(pub.reconciling, true);
  pub.schedule({ periodic: true });
  assert.equal(pub.periodicRescanDue, true);
  assert.equal(pub.reconciliationGeneration, 1);
  const first = pub.active;
  release();
  await first;
  await pub.active;
  assert.equal(verdicts, 2, 'deferred maintenance scan must eventually run');
  assert.equal(pub.periodicRescanDue, false);
  assert.equal(pub.reconciliationGeneration, 2);
  assert.equal(pub.lastError, null);
});

test('readiness is degraded until every incremental batch completes', async () => {
  const pub = { schedule() {}, lastError: null, reconciling: false, pendingSweep: false,
    epoch: { cursor: 4 }, lastCompleted: new Date().toISOString() };
  const server = createServer({ repository, webhookSecret: Buffer.alloc(32), enabled: true,
    appId: 41 }, pub);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const url = `http://127.0.0.1:${server.address().port}/health/ready`;
    assert.equal((await fetch(url)).status, 503);
    pub.epoch = null; pub.reconciling = true;
    assert.equal((await fetch(url)).status, 503);
    pub.reconciling = false; pub.pendingSweep = true;
    assert.equal((await fetch(url)).status, 503);
    pub.pendingSweep = false;
    assert.equal((await fetch(url)).status, 200);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('a failed verifier denies a check and makes readiness degraded, not green', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, enabled: true,
    logger: { error() {} }, decide: async () => { throw new Error('verifier offline'); } });
  publisher.schedule(); await publisher.active;
  assert.match(publisher.lastError, /verifier offline/);
  assert.equal(publisher.lastCompleted, null);
  assert.equal(client.calls.at(-1)[0], 'failure');
  const server = createServer({ repository, webhookSecret: Buffer.alloc(32), enabled: true,
    appId: 41 }, publisher);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const address = `http://127.0.0.1:${server.address().port}/health/ready`;
    assert.equal((await fetch(address)).status, 503);
  } finally { server.close(); await once(server, 'close'); }
  publisher.decide = async () => valid();
  publisher.schedule(); await publisher.active;
  assert.equal(publisher.lastError, null);
  assert.ok(publisher.lastCompleted);
});

test('bounded publisher invalidates every head before authorizing any of them', async () => {
  const prSet = Array.from({ length: 12 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const observed = []; let active = 0, peak = 0;
  const client = { config: { repository },
    pulls: async () => prSet,
    createCheck: async (sha) => { observed.push(['invalidate', sha]); return observed.length; },
    mergeTarget: async pr => mergeSha(pr),
    token: async () => 'token',
    concludeCheck: async (id, state) => observed.push([state, id]),
  };
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, enabled: true, decide: async (_, sha) => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 3));
    active--;
    const matched = prSet.find(p => p.head.sha === sha);
    return { ...valid([matched]), head_sha: sha };
  } });
  await publisher.sweep();
  assert.equal(observed.filter(x => x[0] === 'invalidate').length, 24);
  assert.equal(observed.filter(x => x[0] === 'success').length, 12);
  const firstSuccess = observed.findIndex(x => x[0] === 'success');
  assert.ok(firstSuccess >= 12, 'all contributor-head checks must be invalidated before any approval');
  const initiallyInvalidated = observed.slice(0, 12).map(x => x[1]);
  assert.deepEqual(new Set(initiallyInvalidated), new Set(prSet.map(pr => pr.head.sha)));
  assert.ok(peak <= 4 && peak >= 2, `bounded concurrency expected, got ${peak}`);
  assert.ok(observed.every(x => x[0] !== 'failure'));
});

test('one failed head never starves other heads but degrades service health', async () => {
  const sha2 = 'c'.repeat(40);
  const pulls = [PR(), PR(8, base, sha2)];
  const events = [];
  const client = { config: { repository }, pulls: async () => pulls,
    token: async () => 'read',
    createCheck: async (sha) => { events.push(['start', sha]); return events.length; },
    mergeTarget: async pr => mergeSha(pr),
    concludeCheck: async (id, state) => events.push([state, id]) };
  const publisher = new Publisher({ journal: new MemoryApprovalJournal(), client, enabled: true,
    decide: async (_, sha) => { if (sha === head) throw new Error('one verifier lost');
      const pr = pulls.find(p => p.head.sha === sha);
      return { ...valid([pr]), head_sha: sha }; } });
  await assert.rejects(publisher.sweep(), /one verifier lost/);
  assert.ok(events.some(e => e[0] === 'failure' && e[1] === 1));
  assert.ok(events.some(e => e[0] === 'success'));
  assert.ok(!events.some(e => e[0] === 'success' && e[1] === 1));
});

test('hung verifier exceeds exact-head deadline and can never publish a late success', async () => {
  const client = fakeClient([[PR()], [PR()]]);
  let signalSeen;
  const pub = new Publisher({ journal: new MemoryApprovalJournal(), client, enabled: true, headTimeoutMs: 12,
    decide: async (_token, _head, signal) => {
      signalSeen = signal;
      await new Promise(resolve => setTimeout(resolve, 45));
      return valid();
    } });
  await assert.rejects(pub.sweep(), /deadline exceeded/);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(signalSeen.aborted, true);
  assert.ok(client.calls.some(c => c[0] === 'failure'));
  assert.ok(!client.calls.some(c => c[0] === 'success'));
});

test('17 PR-specific merge targets across 16 heads are denied before new approvals', async () => {
  const prs = Array.from({ length: 16 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  prs.push(PR(17, base, prs[0].head.sha));
  assert.equal(new Set(prs.map(p => p.head.sha)).size, 16);
  const oldMergeApproval = mergeSha(prs[0]);
  const journal = new MemoryApprovalJournal([oldMergeApproval]);
  const client = fakeClient([prs]);
  client.mergeTarget = async () => { throw new Error('over-capacity PR should not verify'); };
  const publisher = new Publisher({ journal, client, enabled: true,
    decide: async () => { throw new Error('over-capacity PR should not run verifier'); } });
  await assert.rejects(publisher.sweep(), /too many PR-specific merge targets.*revoked 1 journaled approvals/);
  assert.deepEqual(journal.list(), [], 'previously approved merge must be invalidated first');
  assert.deepEqual(client.calls.filter(c => c[0] === 'start').map(c => c[1]), [oldMergeApproval]);
  assert.equal(client.calls.some(c => c[0] === 'success'), false);
});

test('16 PR-specific merge targets sharing 15 heads fit bounded journal capacity', async () => {
  const prs = [PR(1), PR(2)];
  prs.push(...Array.from({ length: 14 }, (_, i) => PR(i + 3, base,
    (i + 3).toString(16).padStart(40, '0'))));
  const journal = new MemoryApprovalJournal();
  const client = fakeClient([prs]);
  const publisher = new Publisher({ journal, client, enabled: true,
    decide: async (_token, sha) => ({
      ...valid(prs.filter(pr => pr.head.sha === sha)), head_sha: sha,
    }) });
  await publisher.sweep();
  assert.equal(new Set(prs.map(pr => pr.head.sha)).size, 15);
  assert.equal(journal.list().length, 16);
  assert.deepEqual(new Set(journal.list()), new Set(prs.map(mergeSha)));
  assert.equal(client.calls.filter(c => c[0] === 'success').length, 16);
});

test('a 3200-head flood revokes ONLY recorded App approvals before returning', async () => {
  const prs = Array.from({ length: 3200 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const previous = [prs[9].head.sha, prs[1400].head.sha, prs[3199].head.sha];
  const journal = new MemoryApprovalJournal(previous);
  const invalidated = [];
  let verified = 0;
  const client = { config: { repository }, pulls: async () => prs,
    createCheck: async sha => { invalidated.push(sha); return invalidated.length; },
    token: async () => { throw new Error('over-capacity inventory must not verify'); },
    concludeCheck: async () => { throw new Error('over-capacity inventory must not approve'); } };
  const pub = new Publisher({ journal, client, enabled: true,
    decide: async () => { verified++; return valid(); } });
  await assert.rejects(pub.sweep(), /too many heads.*revoked 3 journaled approvals/);
  assert.deepEqual(new Set(invalidated), new Set(previous));
  assert.deepEqual(journal.list(), []);
  assert.equal(verified, 0);
  assert.equal(invalidated.length, 3, 'unapproved spam heads require no GitHub writes');
});

test('failed old-success revocation stays journaled and never authorizes others', async () => {
  const prs = Array.from({ length: 18 }, (_, i) => PR(i + 1, base,
    (i + 1).toString(16).padStart(40, '0')));
  const old = [prs[0].head.sha, prs[3].head.sha];
  const journal = new MemoryApprovalJournal(old);
  const attempts = [];
  const client = { config: { repository }, pulls: async () => prs,
    createCheck: async sha => {
      attempts.push(sha);
      if (sha === old[0]) throw new Error('GitHub unavailable');
      return attempts.length;
    },
    token: async () => { throw new Error('unexpected verification'); } };
  const pub = new Publisher({ journal, client, enabled: true,
    decide: async () => { throw new Error('unexpected verdict'); } });
  await assert.rejects(pub.sweep(), /cannot invalidate 1 prior App approval/);
  assert.deepEqual(new Set(attempts), new Set(old));
  assert.deepEqual(journal.list(), [old[0]], 'failed revocation must survive recovery');
});

test('durable approval journal survives restart and rejects missing or corrupt state', () => {
  const root = mkdtempSync(join(tmpdir(), 'linura-approval-ledger-'));
  chmodSync(root, 0o700);
  assert.throws(() => new FileApprovalJournal(root), /missing durable approval journal/);
  const created = new FileApprovalJournal(root, { initialize: true });
  assert.deepEqual(created.list(), []);
  created.mark(head);
  const recovered = new FileApprovalJournal(root);
  assert.deepEqual(recovered.list(), [head], 'persist BEFORE a possibly successful remote request');
  recovered.clear(head);
  assert.deepEqual(new FileApprovalJournal(root).list(), []);
  writeFileSync(join(root, 'approved-heads.json'), '{"schema_version":1,"heads":["forged"]}', { mode: 0o600 });
  assert.throws(() => new FileApprovalJournal(root), /invalid approval journal inventory/);
  unlinkSync(join(root, 'approved-heads.json'));
  assert.throws(() => new FileApprovalJournal(root), /missing durable approval journal/);
});

test('a journal failure cannot be promoted to a successful App check', async () => {
  const journal = { list: () => [], clear() {},
    mark: () => { throw new Error('disk full before approval'); } };
  const client = fakeClient([[PR()], [PR()]]);
  const pub = new Publisher({ journal, client, enabled: true, decide: async () => valid() });
  await assert.rejects(pub.sweep(), /disk full before approval/);
  assert.equal(client.calls.some(v => v[0] === 'success'), false);
  assert.equal(client.calls.some(v => v[0] === 'failure'), true);
});

test('a confirmed status failure after write-ahead approval remains journaled', async () => {
  const journal = new MemoryApprovalJournal();
  const client = { config: { repository }, pulls: async () => [PR()],
    createCheck: async () => 1, mergeTarget: async pr => mergeSha(pr),
    token: async () => 'read',
    concludeCheck: async (_id, conclusion) => {
      if (conclusion === 'success') throw new Error('remote result unknown');
    } };
  const pub = new Publisher({ journal, client, enabled: true, decide: async () => valid() });
  await assert.rejects(pub.sweep(), /PR-specific success publication incomplete/);
  assert.deepEqual(journal.list(), [mergeSha(PR())], 'ambiguous remote success must remain revocable');
});

test('verifier subprocess errors sanitize live token, stdout, stderr and causes in CI', async () => {
  // Directly exercise the real child process under the CI runner UID. The
  // privileged production verifier-tree attestation remains unchanged.
  const root = mkdtempSync(join(tmpdir(), 'linura-verifier-leak-'));
  const script = join(root, 'malicious-verifier.py');
  writeFileSync(script,
    'import os, sys\n' +
    'sys.stderr.write("sensitive stderr: " + os.environ["GITHUB_TOKEN"] + "\\n")\n' +
    'sys.stdout.write("sensitive stdout: " + os.environ["GITHUB_TOKEN"] + "\\n")\n' +
    'raise SystemExit(73)\n',
    { mode: 0o600 });
  const secret = 'installation-token-INTERNAL-NEVER-LOG';
  let checked = false;
  await assert.rejects(
    () => runSanitizedVerifier('python3', [script], {
      cwd: root, timeout: 10_000, maxBuffer: 1024 * 1024,
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', GITHUB_TOKEN: secret },
    }),
    error => {
      checked = true;
      assert.equal(error.message, 'trusted verifier process failed');
      assert.equal(error.constructor.name, 'QualificationError');
      assert.ok(!String(error).includes(secret));
      assert.ok(!String(error).includes('sensitive stderr'));
      assert.equal(error.cause, undefined);
      assert.equal(error.stderr, undefined);
      assert.equal(error.stdout, undefined);
      return true;
    });
  assert.equal(checked, true, 'must execute the subprocess and reach the sanitizer');
});

test('a GitHub outage cannot be mistaken for invalidation of earlier success', async () => {
  const journal = new MemoryApprovalJournal([head]);
  const client = { config: { repository }, pulls: async () => [PR()],
    createCheck: async () => { throw new Error('GitHub API unreachable'); },
    token: async () => { throw new Error('must not verify before invalidation'); } };
  const pub = new Publisher({ journal, client, enabled: true, decide: async () => valid() });
  await assert.rejects(pub.sweep(), /cannot invalidate 1 prior App approval/);
  assert.deepEqual(journal.list(), [head]);
});

test('credentials cannot be read from replaceable directories or FIFOs', () => {
  const root = mkdtempSync(join(tmpdir(), 'linura-secret-'));
  const parent = join(root, 'parent');
  mkdirSync(parent);
  const secret = join(parent, 'secret');
  writeFileSync(secret, Buffer.alloc(32, 7), { mode: 0o600 });
  chmodSync(parent, 0o777);
  assert.throws(() => secureSecretFile(secret), /credential parent/);
  chmodSync(parent, 0o700);
  assert.equal(secureSecretFile(secret).length, 32);
  const fifo = join(parent, 'pipe');
  // An attacker-controlled non-regular file must be rejected without blocking.
  execFileSync('mkfifo', [fifo]);
  assert.throws(() => secureSecretFile(fifo), /non-symlink regular file/);
});
