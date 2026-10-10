/**
 * Externally hosted GitHub App check publisher for Linura qualification.
 * Node 22+, standard library only. This service is NEVER run with the private
 * key in GitHub Actions, on PR-controlled code, or from a PR checkout.
 */
import { createHmac, createPrivateKey, createSign, timingSafeEqual } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFileSync, writeFileSync, lstatSync, realpathSync, readdirSync, openSync, fstatSync, closeSync, renameSync, unlinkSync, fsyncSync, existsSync, constants } from 'node:fs';
import { resolve, isAbsolute, dirname, join, sep } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
export const CHECK_NAME = 'linura/applicable-qualification';
// Every sweep remains finite, including the complete publication path.
// Keep the 120-second independently reviewed verifier limit AND reserve enough
// time for fresh PR inventory, two three-request merge identity validations,
// App-owned check invalidation, journal persistence and conclusion. Merely
// giving the verifier 120 of a 150-second head window cannot work reliably.
export const MAX_HEADS = 16;
export const MAX_PARALLEL_HEADS = 4;
const MAX_SHARED_PRS_PER_HEAD = 8;
export const API_TIMEOUT_MS = 15_000;
export const DECISION_TIMEOUT_MS = 120_000;
const HEAD_API_ROUNDS = 1 /* read token */ + 1 /* one-page live PR inventory */ +
  2 * 3 /* two PR-specific merge identity passes */ +
  (1 + 2 * Math.ceil(MAX_SHARED_PRS_PER_HEAD / MAX_PARALLEL_HEADS)) /* merge-check token + create/update waves */ +
  Math.ceil(MAX_SHARED_PRS_PER_HEAD / MAX_PARALLEL_HEADS) /* success conclusion waves */;
export const HEAD_TIMEOUT_MS = DECISION_TIMEOUT_MS + HEAD_API_ROUNDS * API_TIMEOUT_MS + 45_000;
// One reconciliation step may revoke all 16 journaled approvals, invalidate
// all 16 contributor heads and verify at most FOUR heads. Each step has an
// independent deadline, rather than one multi-wave 33-minute deadline.
const INVALIDATION_WAVES = Math.ceil(MAX_HEADS / MAX_PARALLEL_HEADS);
export const SWEEP_TIMEOUT_MS = HEAD_TIMEOUT_MS +
  (1 + 2 * INVALIDATION_WAVES * 3) * API_TIMEOUT_MS + 90_000;
const SHA = /^[0-9a-f]{40}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BASE_GATES = ['canonical-ci', 'security-rustsec', 'codeql'];

export class QualificationError extends Error {
  constructor(message) { super(message); this.name = 'QualificationError'; }
}

export function secureSecretFile(file) {
  if (!isAbsolute(file)) throw new QualificationError('credential path must be absolute');
  // Check the entire directory chain; no untrusted user can replace the file
  // between open and verification. A root-owned sticky /tmp is acceptable for
  // local tests, but ordinary group/world-writable parents are not.
  for (let parent = dirname(file);; parent = dirname(parent)) {
    const st = lstatSync(parent);
    if (!st.isDirectory() || st.isSymbolicLink() ||
        (st.uid !== 0 && st.uid !== process.getuid()) ||
        ((st.mode & 0o022) && !((st.mode & 0o1000) && st.uid === 0))) {
      throw new QualificationError('credential parent must be trusted and not replaceable');
    }
    if (dirname(parent) === parent) break;
  }
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_CLOEXEC;
  let fd;
  try { fd = openSync(file, flags); }
  catch { throw new QualificationError('credential must be a non-symlink regular file with mode 0600 or stricter'); }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 ||
        (stat.uid !== 0 && stat.uid !== process.getuid()) ||
        stat.size < 20 || stat.size > 32768) {
      throw new QualificationError('credential must be a non-symlink regular file with mode 0600 or stricter');
    }
    const content = readFileSync(fd);
    if (content.length !== stat.size) throw new QualificationError('credential changed during read');
    return content;
  } finally { closeSync(fd); }
}

/**
 * Verify the complete protected source tree, not merely the verifier file.
 *
 * Python loads imported tools, contracts and configuration beneath its cwd.
 * Checking just `tools/applicable_qualification.py` is insufficient: a
 * writable intermediate directory can replace the script, and a writable
 * imported module can change the decision without touching the script.
 *
 * The deployment owner is always root (uid 0). The explicit ownerUid argument
 * exists to exercise the same checks against isolated, unprivileged fixtures
 * in Node's tests; production callers do not provide an alternate uid.
 * Since every parent and descendant is locked against other host users,
 * none of those users can race path replacement after this verification.
 */
export function verifyTrustedSourceTree(root, ownerUid = 0) {
  const invalid = () => new QualificationError(
    'enabled authority requires root-owned immutable verifier checkout');
  if (!isAbsolute(root) || resolve(root) !== root ||
      !Number.isSafeInteger(ownerUid) || ownerUid < 0) throw invalid();
  const components = root.split(sep).filter(Boolean);
  let path = sep;
  const checkDirectory = (name, inTree) => {
    const stat = lstatSync(name);
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
        (inTree ? stat.uid !== ownerUid : (stat.uid !== 0 && stat.uid !== ownerUid)) ||
        ((stat.mode & 0o022) &&
          !(stat.uid === 0 && (stat.mode & 0o1000) && !inTree))) {
      throw invalid();
    }
    return stat;
  };
  checkDirectory(path, false);
  for (let i = 0; i < components.length; i++) {
    path = join(path, components[i]);
    checkDirectory(path, i === components.length - 1);
  }
  // Inspect *every* repository entry. A safe top-level verifier is not an
  // authority if a dependency, data file, or descendant directory is writable
  // by an untrusted host user, or if a symbolic link leaves the deployment.
  const stack = [root];
  let visited = 0;
  while (stack.length) {
    const directory = stack.pop();
    for (const entry of readdirSync(directory)) {
      if (++visited > 20000) throw invalid();
      const filename = join(directory, entry);
      const stat = lstatSync(filename);
      if (stat.isSymbolicLink() || stat.uid !== ownerUid ||
          (stat.mode & 0o022) || (!stat.isDirectory() && !stat.isFile())) {
        throw invalid();
      }
      if (stat.isDirectory()) stack.push(filename);
    }
  }
  const script = join(root, 'tools', 'applicable_qualification.py');
  if (!lstatSync(script).isFile()) throw invalid();
  return script;
}

export function verifyWebhook(secret, content, signature) {
  if (typeof signature !== 'string' || !/^sha256=[0-9a-f]{64}$/.test(signature)) return false;
  const calculated = createHmac('sha256', secret).update(content).digest();
  const received = Buffer.from(signature.slice(7), 'hex');
  return received.length === calculated.length && timingSafeEqual(received, calculated);
}

export function createAppJwt(appId, privateKey, now = Date.now()) {
  const seconds = Math.floor(now / 1000);
  const encode = (object) => Buffer.from(JSON.stringify(object)).toString('base64url');
  const header = encode({ alg: 'RS256', typ: 'JWT' });
  const claims = encode({ iat: seconds - 60, exp: seconds + 480, iss: String(appId) });
  const input = `${header}.${claims}`;
  const signature = createSign('RSA-SHA256').update(input).end().sign(privateKey).toString('base64url');
  return `${input}.${signature}`;
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new QualificationError(`invalid ${label}`);
  }
  return value;
}

function stringSet(values, label) {
  if (!Array.isArray(values) || values.length === 0 || values.length > 128 ||
      values.some(v => typeof v !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(v)) ||
      new Set(values).size !== values.length) throw new QualificationError(`invalid ${label}`);
  return new Set(values);
}

/** Strictly bind read-only trusted-policy output to CURRENT GitHub metadata. */
export function validateDecision(receipt, repository, head, currentPulls) {
  assertObject(receipt, 'decision receipt');
  if (receipt.schema_version !== 1 || receipt.repository !== repository ||
      receipt.head_sha !== head || !['success', 'pending', 'failure'].includes(receipt.state) ||
      !Array.isArray(receipt.prs) || receipt.prs.length !== currentPulls.length ||
      currentPulls.length === 0 || currentPulls.length > MAX_SHARED_PRS_PER_HEAD) {
    throw new QualificationError('decision identity or PR cardinality mismatch');
  }
  const byNumber = new Map(currentPulls.map(pr => [pr.number, pr]));
  if (byNumber.size !== currentPulls.length || currentPulls.some(pr =>
      !Number.isSafeInteger(pr.number) || pr.number < 1 || pr.head?.sha !== head ||
      pr.base?.ref !== 'main' || !SHA.test(pr.base?.sha || ''))) {
    throw new QualificationError('current PR inventory is ambiguous or malformed');
  }
  const seen = new Set();
  let qualified = true;
  for (const item of receipt.prs) {
    assertObject(item, 'PR decision');
    const active = byNumber.get(item.number);
    if (!active || seen.has(item.number) || item.head_sha !== head ||
        item.base_sha !== active.base.sha || item.base_ref !== 'main') {
      throw new QualificationError('decision PR/base/head identity mismatch');
    }
    seen.add(item.number);
    const required = stringSet(item.required_gate_ids, 'required gate inventory');
    const accepted = Array.isArray(item.accepted_gate_ids) ? new Set(item.accepted_gate_ids) : null;
    if (!accepted || item.accepted_gate_ids.length !== accepted.size ||
        [...accepted].some(gate => !required.has(gate))) {
      throw new QualificationError('accepted gate set is invalid');
    }
    for (const gate of BASE_GATES) if (!required.has(gate)) {
      throw new QualificationError('missing mandatory native qualification gate');
    }
    if ([...required].some(gate => !accepted.has(gate))) qualified = false;
  }
  if (receipt.state === 'success' && !qualified) {
    throw new QualificationError('claimed success with unaccepted gates');
  }
  // A conservative pending/failure must never be promoted to success.
  return receipt.state;
}

function takeBoolean(name, value) {
  if (value !== 'true' && value !== 'false') throw new QualificationError(`invalid ${name}`);
  return value === 'true';
}

/** Secrets are supplied as root-owned systemd credentials, never CI secrets. */
export function configuration(env = process.env) {
  const repository = env.PUBLISHER_REPOSITORY;
  if (!REPO.test(repository || '') || repository !== 'linura-org/linura') {
    throw new QualificationError('repository must be linura-org/linura');
  }
  const appId = Number(env.PUBLISHER_APP_ID);
  const installationId = Number(env.PUBLISHER_INSTALLATION_ID);
  if (![appId, installationId].every(x => Number.isSafeInteger(x) && x > 0)) {
    throw new QualificationError('App and installation IDs are required');
  }
  const enabled = takeBoolean('PUBLISHER_ENABLED', env.PUBLISHER_ENABLED || 'false');
  const root = env.PUBLISHER_TRUSTED_REPO;
  if (!root || !isAbsolute(root)) throw new QualificationError('trusted checkout must be absolute');
  const privateKey = createPrivateKey(secureSecretFile(env.PUBLISHER_KEY_FILE));
  if (privateKey.asymmetricKeyType !== 'rsa') throw new QualificationError('App private key must be RSA');
  const webhookSecret = secureSecretFile(env.PUBLISHER_WEBHOOK_SECRET_FILE);
  const port = Number(env.PUBLISHER_PORT || '8787');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new QualificationError('invalid publisher port');
  const host = env.PUBLISHER_HOST || '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1') throw new QualificationError('bind host must be loopback');
  const protectedRoot = realpathSync(root);
  if (enabled) verifyTrustedSourceTree(protectedRoot);
  return { repository, appId, installationId, enabled, root: protectedRoot,
    privateKey, webhookSecret, port, host };
}

export class GitHubClient {
  constructor(config, fetcher = fetch) {
    this.config = config;
    this.fetcher = fetcher;
    this.cache = new Map();
    // Bind each check ID to the SHA returned by a verified App-owned create/update.
    this.pendingTargets = new Map();
  }

  rememberCheck(id, head) {
    this.pendingTargets.delete(id);
    this.pendingTargets.set(id, head);
    // Bounded for long-lived hosts; each sweep has at most 32 active checks.
    if (this.pendingTargets.size > 256) {
      this.pendingTargets.delete(this.pendingTargets.keys().next().value);
    }
  }

  async api(path, { method = 'GET', token, body, signal } = {}) {
    if (!path.startsWith('/') || path.includes('://')) throw new QualificationError('invalid API path');
    const res = await this.fetcher(`https://api.github.com${path}`, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(API_TIMEOUT_MS)]) :
        AbortSignal.timeout(API_TIMEOUT_MS),
    });
    if (!res.ok) throw new QualificationError(`GitHub API ${method} ${path.split('?')[0]} HTTP ${res.status}`);
    return res.status === 204 ? null : await res.json();
  }

  async token(permission, signal) {
    if (!['read', 'write'].includes(permission)) throw new QualificationError('bad permission class');
    const cached = this.cache.get(permission);
    if (cached && cached.expiresAt > Date.now() + 90_000) return cached.token;
    const permissions = permission === 'read'
      ? { actions: 'read', checks: 'read', contents: 'read', pull_requests: 'read' }
      : { checks: 'write' };
    const result = await this.api(`/app/installations/${this.config.installationId}/access_tokens`, {
      method: 'POST',
      token: createAppJwt(this.config.appId, this.config.privateKey),
      body: { repositories: [this.config.repository.split('/')[1]], permissions }, signal,
    });
    if (typeof result?.token !== 'string' || !result.expires_at ||
        !Number.isFinite(Date.parse(result.expires_at))) {
      throw new QualificationError('GitHub installation token response invalid');
    }
    const expiresAt = Date.parse(result.expires_at);
    this.cache.set(permission, { token: result.token, expiresAt });
    return result.token;
  }

  async pages(path, token, max = 3200, signal) {
    const results = [];
    for (let page = 1; page <= Math.ceil(max / 100) + 1; page += 1) {
      const delimiter = path.includes('?') ? '&' : '?';
      const segment = await this.api(`${path}${delimiter}per_page=100&page=${page}`, { token, signal });
      if (!Array.isArray(segment) || results.length + segment.length > max) {
        throw new QualificationError('pagination incomplete or unsafe');
      }
      results.push(...segment);
      if (segment.length < 100) return results;
    }
    throw new QualificationError('pagination exceeds safety bound');
  }

  async pulls(signal) {
    const token = await this.token('read', signal);
    const { repository } = this.config;
    const result = await this.pages(`/repos/${repository}/pulls?state=open&base=main`, token, 3200, signal);
    for (const pr of result) {
      if (!Number.isSafeInteger(pr.number) || !SHA.test(pr.head?.sha || '') ||
          !SHA.test(pr.base?.sha || '') || pr.base?.ref !== 'main') {
        throw new QualificationError('untrusted PR inventory shape');
      }
    }
    return result;
  }

  // A required Check Run on the contributor head is shareable by any future
  // PR pointing to that commit. Only publish success on GitHub's PR-specific
  // test merge commit. GitHub evaluates checks on that synthetic merge SHA
  // when the merge ref has a check (see required-status-check semantics).
  async mergeTarget(pr, signal) {
    if (!Number.isSafeInteger(pr?.number) || pr.number < 1 ||
        !SHA.test(pr?.head?.sha || '') || !SHA.test(pr?.base?.sha || '') ||
        pr.base?.ref !== 'main') {
      throw new QualificationError('invalid PR identity for merge check');
    }
    const token = await this.token('read', signal);
    const path = `/repos/${this.config.repository}`;
    const remote = await this.api(`${path}/pulls/${pr.number}`, { token, signal });
    if (remote?.number !== pr.number || remote.state !== 'open' ||
        remote.head?.sha !== pr.head.sha || remote.base?.sha !== pr.base.sha ||
        remote.base?.ref !== 'main') {
      throw new QualificationError('PR identity changed before merge check');
    }
    const refName = `refs/pull/${pr.number}/merge`;
    const ref = await this.api(`${path}/git/ref/pull/${pr.number}/merge`, { token, signal });
    const mergeSha = ref?.object?.sha;
    if (ref?.ref !== refName || ref?.object?.type !== 'commit' ||
        !SHA.test(mergeSha || '') || mergeSha === pr.head.sha ||
        mergeSha === pr.base.sha) {
      throw new QualificationError('PR-specific test merge ref unavailable');
    }
    const merge = await this.api(`${path}/git/commits/${mergeSha}`, { token, signal });
    if (merge?.sha !== mergeSha || !Array.isArray(merge.parents) ||
        merge.parents.length !== 2 || merge.parents[0]?.sha !== pr.base.sha ||
        merge.parents[1]?.sha !== pr.head.sha) {
      throw new QualificationError('test merge commit parents do not match PR');
    }
    return mergeSha;
  }

  async createCheck(head, title, signal) {
    if (!SHA.test(head)) throw new QualificationError('unsafe qualification check SHA');
    const token = await this.token('write', signal);
    // Reuse the App-owned check across retries and scheduled sweeps. Creating
    // another run every ten minutes would eventually exceed GitHub's 1000
    // same-name check-run limit, displacing earlier auditable evidence.
    const existing = await this.api(`/repos/${this.config.repository}/commits/${head}/check-runs` +
      `?check_name=${encodeURIComponent(CHECK_NAME)}&app_id=${this.config.appId}&filter=latest&per_page=100`,
    { token, signal });
    if (!Array.isArray(existing?.check_runs) || !Number.isSafeInteger(existing.total_count) ||
        existing.total_count < 0 || existing.total_count > 100) {
      throw new QualificationError('trusted check-run inventory unavailable or unbounded');
    }
    const matches = existing.check_runs.filter(item =>
      item?.app?.id === this.config.appId && item.name === CHECK_NAME &&
      item.head_sha === head && Number.isSafeInteger(item.id) && item.id > 0);
    // A filtered inventory with a foreign/malformed entry is not empty.
    // Treating it as absent would create a new run while leaving an older
    // App-owned success unchanged. No ambiguous inventory may be authorized.
    if (existing.check_runs.length !== existing.total_count ||
        matches.length !== existing.total_count || matches.length > 1) {
      throw new QualificationError('trusted check-run identity ambiguous');
    }
    const body = {
      status: 'in_progress', started_at: new Date().toISOString(),
      output: { title: 'Qualification awaiting independent proof', summary: title.slice(0, 650) },
    };
    if (matches.length === 1) {
      const id = matches[0].id;
      const updated = await this.api(`/repos/${this.config.repository}/check-runs/${id}`, {
        token, method: 'PATCH', body, signal,
      });
      // Never clear a durable prior-success journal entry merely because a
      // PATCH returned HTTP 200. Require the expected exact-head App-owned
      // check to have actually reached a non-passing state.
      if (updated?.id !== id || updated.status !== 'in_progress' ||
          updated.name !== CHECK_NAME || updated.head_sha !== head ||
          updated.app?.id !== this.config.appId) {
        throw new QualificationError('prior App check invalidation not confirmed');
      }
      this.rememberCheck(id, head);
      return id;
    }
    const response = await this.api(`/repos/${this.config.repository}/check-runs`, {
      token, method: 'POST', body: { name: CHECK_NAME, head_sha: head, ...body }, signal,
    });
    if (!Number.isSafeInteger(response?.id) || response.id < 1 ||
        response.app?.id !== this.config.appId || response.head_sha !== head ||
        response.name !== CHECK_NAME || response.status !== 'in_progress') {
      throw new QualificationError('check creation identity mismatch');
    }
    this.rememberCheck(response.id, head);
    return response.id;
  }

  async concludeCheck(id, conclusion, summary, signal) {
    if (!['success', 'failure'].includes(conclusion)) throw new QualificationError('invalid check conclusion');
    const head = this.pendingTargets.get(id);
    if (!Number.isSafeInteger(id) || !SHA.test(head || '')) {
      throw new QualificationError('check conclusion missing verified App/head binding');
    }
    const token = await this.token('write', signal);
    const response = await this.api(`/repos/${this.config.repository}/check-runs/${id}`, {
      method: 'PATCH', token, signal,
      body: {
        status: 'completed', conclusion, completed_at: new Date().toISOString(),
        output: { title: conclusion === 'success' ? 'Exact-head qualification accepted' : 'Qualification denied',
          summary: summary.slice(0, 650) },
      },
    });
    if (response?.id !== id || response.head_sha !== head ||
        response.app?.id !== this.config.appId || response.name !== CHECK_NAME ||
        response.status !== 'completed' || response.conclusion !== conclusion) {
      throw new QualificationError('App-owned check conclusion not confirmed');
    }
    return response;
  }
}

/** Sanitized subprocess boundary, directly exercised with real child execution in CI.
 * This helper grants no authority to select an executable for production: the
 * trustedDecision caller pins Python and reattests protected source first. */
export async function runSanitizedVerifier(program, args, options) {
  try {
    const { stdout } = await execFileAsync(program, args, options);
    return stdout;
  } catch {
    // Do not propagate child Error, stdout, stderr or cause: the read-scoped
    // installation token is present in the subprocess environment.
    throw new QualificationError('trusted verifier process failed');
  }
}

/** This command is NOT implemented on current main; it is a #206 integration contract. */
export async function trustedDecision(config, readToken, head, signal) {
  // Re-attest the entire root-owned source tree immediately before handing a
  // read token to Python, not only during initial service startup.
  const script = verifyTrustedSourceTree(config.root);
  const args = [script, 'decision-head', '--repository', config.repository,
    '--head-sha', head, '--token-env', 'GITHUB_TOKEN'];
  const stdout = await runSanitizedVerifier('python3', args, {
    cwd: config.root, timeout: DECISION_TIMEOUT_MS, signal, maxBuffer: 1024 * 1024,
    windowsHide: true,
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8',
      PYTHONPATH: config.root, GITHUB_TOKEN: readToken },
  });
  let value;
  try { value = JSON.parse(stdout); }
  catch { throw new QualificationError('trusted verifier did not return JSON'); }
  return value;
}

/** Bound noncooperative test doubles and network operations as well as real subprocesses. */
async function beforeDeadline(action, signal) {
  if (signal.aborted) throw new QualificationError('qualification deadline exceeded');
  let handler;
  try {
    return await Promise.race([
      Promise.resolve().then(action),
      new Promise((_, reject) => {
        handler = () => reject(new QualificationError('qualification deadline exceeded'));
        signal.addEventListener('abort', handler, { once: true });
        if (signal.aborted) handler();
      }),
    ]);
  } finally {
    if (handler) signal.removeEventListener('abort', handler);
  }
}

/** All entries are attempted; individual errors never starve unrelated heads. */
async function boundedMap(entries, concurrency, action) {
  let next = 0;
  const results = new Array(entries.length);
  await Promise.all(Array.from({ length: Math.min(entries.length, concurrency) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= entries.length) return;
      try { results[index] = { value: await action(entries[index]) }; }
      catch (error) { results[index] = { error }; }
    }
  }));
  return results;
}

/**
 * Only HEADS that could have received a successful App check require urgent
 * revocation. The journal is write-ahead: persist before publishing success,
 * and remove a head only after GitHub has acknowledged invalidation.
 * Untrusted new PRs cannot increase this revocation workload.
 */
export class MemoryApprovalJournal {
  constructor(initial = []) {
    if (!Array.isArray(initial) || initial.length > MAX_HEADS ||
        initial.some(head => !SHA.test(head)) ||
        new Set(initial).size !== initial.length) {
      throw new QualificationError('invalid approval journal inventory');
    }
    this.approved = new Set(initial);
  }
  list() { return [...this.approved]; }
  mark(head) {
    if (!SHA.test(head)) throw new QualificationError('invalid approval journal head');
    if (!this.approved.has(head) && this.approved.size >= MAX_HEADS) {
      throw new QualificationError('approval journal capacity reached');
    }
    this.approved.add(head);
  }
  clear(head) { this.approved.delete(head); }
}

/** Atomic Linux state-directory journal; no App success without a durable record. */
export class FileApprovalJournal extends MemoryApprovalJournal {
  constructor(directory, { initialize = false } = {}) {
    if (!isAbsolute(directory || '')) throw new QualificationError('approval journal directory required');
    const root = realpathSync(directory);
    const st = lstatSync(root);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() ||
        (st.mode & 0o077)) throw new QualificationError('unsafe approval journal directory');
    const file = join(root, 'approved-heads.json');
    if (!existsSync(file)) {
      if (!initialize) throw new QualificationError('missing durable approval journal; operator bootstrap required');
      const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT |
        constants.O_EXCL | constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600);
      try {
        writeFileSync(fd, JSON.stringify({ schema_version: 1, heads: [] }) + '\n');
        fsyncSync(fd);
      } finally { closeSync(fd); }
      const dirfd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY);
      try { fsyncSync(dirfd); } finally { closeSync(dirfd); }
    }
    const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let data;
    try {
      const info = fstatSync(fd);
      if (!info.isFile() || info.uid !== process.getuid() ||
          (info.mode & 0o077) || info.size < 20 || info.size > 2048) {
        throw new QualificationError('unsafe approval journal file');
      }
      data = readFileSync(fd, 'utf8');
      if (Buffer.byteLength(data) !== info.size) {
        throw new QualificationError('approval journal modified while reading');
      }
    } finally { closeSync(fd); }
    let doc;
    try { doc = JSON.parse(data); }
    catch { throw new QualificationError('corrupt approval journal'); }
    if (doc?.schema_version !== 1 || !Array.isArray(doc.heads) ||
        Object.keys(doc).sort().join(',') !== 'heads,schema_version') {
      throw new QualificationError('invalid approval journal schema');
    }
    super(doc.heads);
    this.root = root;
    this.file = file;
    this.revision = 0;
  }

  #persist(heads) {
    const data = JSON.stringify({ schema_version: 1, heads: [...heads] }) + '\n';
    const temp = join(this.root, `.approved-heads.${process.pid}.${++this.revision}.tmp`);
    const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT |
      constants.O_EXCL | constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600);
    try {
      writeFileSync(fd, data);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    try {
      renameSync(temp, this.file);
      const dirfd = openSync(this.root, constants.O_RDONLY | constants.O_DIRECTORY);
      try { fsyncSync(dirfd); } finally { closeSync(dirfd); }
    } finally {
      if (existsSync(temp)) unlinkSync(temp);
    }
  }
  mark(head) {
    if (!SHA.test(head)) throw new QualificationError('invalid approval journal head');
    const next = new Set(this.approved);
    next.add(head);
    if (next.size > MAX_HEADS) throw new QualificationError('approval journal capacity reached');
    this.#persist(next); // write-ahead BEFORE any successful GitHub API call
    this.approved = next;
  }
  clear(head) {
    if (!this.approved.has(head)) return;
    const next = new Set(this.approved);
    next.delete(head);
    this.#persist(next); // only AFTER GitHub confirmed status invalidation
    this.approved = next;
  }
}

/** Serialized head reconciliation; never accept contributor-authored verdicts. */
export class Publisher {
  constructor({ client, decide, enabled = false, logger = console,
    journal, headTimeoutMs = HEAD_TIMEOUT_MS }) {
    if (!journal || !['list', 'mark', 'clear'].every(k => typeof journal[k] === 'function')) {
      throw new QualificationError('publisher requires an approval journal');
    }
    if (!Number.isSafeInteger(headTimeoutMs) || headTimeoutMs <= 0 ||
        headTimeoutMs > HEAD_TIMEOUT_MS) throw new QualificationError('invalid head deadline');
    this.client = client;
    this.journal = journal;
    this.decide = decide;
    this.enabled = enabled;
    this.logger = logger;
    this.headTimeoutMs = headTimeoutMs;
    this.active = Promise.resolve();
    this.pendingSweep = false;
    this.lastError = null;
    this.lastCompleted = null;
    this.lastAttempt = null;
    // Only unfinished work position is volatile. Potentially successful
    // GitHub side effects are recorded in the durable write-ahead journal.
    // Restarts rebuild the queue from GitHub after revoking that journal.
    this.epoch = null;
    this.reconciliationGeneration = 0;
    this.reconciling = false;
    this.periodicRescanDue = false;
  }

  schedule({ periodic = false } = {}) {
    if (!this.enabled) return;
    // A maintenance tick must never starve an active multi-step epoch.
    // Webhook-triggered evidence changes invalidate the current generation;
    // the next queued scan revokes journaled successes before authorizing.
    if (periodic && (this.reconciling || this.pendingSweep)) {
      this.periodicRescanDue = true;
      return;
    }
    if (periodic) this.periodicRescanDue = false;
    else this.epoch?.abort.abort();
    this.reconciliationGeneration++;
    if (this.pendingSweep) return;
    this.pendingSweep = true;
    this.active = this.active.catch(() => undefined).then(async () => {
      this.pendingSweep = false;
      this.reconciling = true;
      this.lastAttempt = new Date().toISOString();
      try { await this.sweep(); this.lastError = null; this.lastCompleted = new Date().toISOString(); }
      catch (error) { this.lastError = error.message; this.logger.error('publisher sweep failed:', error.message); }
      finally {
        this.reconciling = false;
        // Polling never aborts legitimate multi-batch work, but a skipped
        // tick is coalesced into a fresh full scan after the epoch completes.
        if (this.periodicRescanDue) this.schedule({ periodic: true });
      }
    });
  }

  // One logical reconciliation comprises independently bounded, resumable
  // steps. A crash safely discards the cursor, never the approval journal.
  async sweep() {
    for (;;) {
      const progress = await this.sweepStep();
      if (progress.complete) return;
    }
  }

  async sweepStep() {
    const sweepSignal = AbortSignal.timeout(SWEEP_TIMEOUT_MS);
    const generation = this.reconciliationGeneration;
    let epoch = this.epoch;
    if (epoch && epoch.generation !== generation) {
      this.epoch = null;
      throw new QualificationError('reconciliation superseded by newer evidence');
    }
    if (!epoch) {
      const prior = this.journal.list();
      if (prior.length > MAX_HEADS) throw new QualificationError('approval journal capacity exceeded');

      // Phase 0: revoke *only previously approvable heads* from the durable
      // journal. A contributor opening 3,200 unapproved PRs cannot starve
      // revocation of the small, known set of prior successful App checks.
      // This also revokes checks for PRs that were closed or retargeted.
      const revocations = await boundedMap(prior, MAX_PARALLEL_HEADS, async head => {
        const id = await beforeDeadline(() => this.client.createCheck(
          head, 'Invalidating previously authorized qualification', sweepSignal), sweepSignal);
        this.journal.clear(head);
        return id;
      });
      const revocationErrors = revocations.filter(result => result.error);
      if (revocationErrors.length) throw new QualificationError(
        `cannot invalidate ${revocationErrors.length} prior App approval(s): ` +
        revocationErrors[0].error.message);

      const inventory = await beforeDeadline(() => this.client.pulls(sweepSignal), sweepSignal);
      const grouped = new Map();
      for (const pr of inventory) {
        const head = pr.head.sha;
        if (!grouped.has(head)) grouped.set(head, []);
        grouped.get(head).push(pr);
      }
      // All *previously successful* checks have already been revoked above.
      // Never attempt unbounded createCheck() calls for unapproved new heads.
      // Nothing may be approved until the inventory falls back within policy.
      if (grouped.size > MAX_HEADS) throw new QualificationError(
        `too many heads for bounded publisher sweep: ${grouped.size}; ` +
        `revoked ${prior.length} journaled approvals; no new approvals permitted`);
      // One contributor head may be referenced by up to eight open PRs.
      // Success is published on each PR's distinct synthetic test-merge SHA,
      // so journal/revocation capacity MUST bound PR merge targets, not merely
      // the number of distinct contributor heads.
      if (inventory.length > MAX_HEADS) throw new QualificationError(
        `too many PR-specific merge targets for bounded approval journal: ${inventory.length}; ` +
        `revoked ${prior.length} journaled approvals; no new approvals permitted`);

      const entries = [...grouped.entries()].map(([head, prs]) => ({ head, prs }));
      const started = await boundedMap(entries, MAX_PARALLEL_HEADS,
        ({ head }) => beforeDeadline(() => this.client.createCheck(
          head, 'Independent verification required', sweepSignal), sweepSignal));
      const errors = [];
      const candidates = [];
      for (let i = 0; i < entries.length; i++) {
        if (started[i].error) {
          errors.push(`${entries[i].head}: cannot invalidate check: ${started[i].error.message}`);
        } else {
          candidates.push({ ...entries[i], id: started[i].value });
        }
      }
      if (errors.length) throw new QualificationError(
        `${errors.length} check invalidation(s) failed; no approvals permitted`);
      if (generation !== this.reconciliationGeneration || sweepSignal.aborted) {
        throw new QualificationError('reconciliation superseded or deadline exceeded');
      }
      epoch = { generation, candidates, cursor: 0, abort: new AbortController() };
      this.epoch = epoch;
    }

    // One bounded batch. The contributor heads were ALL invalidated before
    // the first success; every batch re-fetches live PR evidence per head.
    const candidates = epoch.candidates.slice(epoch.cursor, epoch.cursor + MAX_PARALLEL_HEADS);
    const errors = [];
    const outcomes = await boundedMap(candidates, MAX_PARALLEL_HEADS, async ({ head, prs, id }) => {
      const signal = AbortSignal.any([
        sweepSignal, epoch.abort.signal, AbortSignal.timeout(this.headTimeoutMs),
      ]);
      try {
        if (prs.length > MAX_SHARED_PRS_PER_HEAD) throw new QualificationError('shared head exceeds eight PRs');
        const token = await beforeDeadline(() => this.client.token('read', signal), signal);
        const receipt = await beforeDeadline(() => this.decide(token, head, signal), signal);
        const beforeCommit = await beforeDeadline(() => this.client.pulls(signal), signal);
        const current = beforeCommit.filter(pr => pr.head.sha === head);
        if (current.length !== prs.length || current.some(pr => {
          const old = prs.find(v => v.number === pr.number);
          return !old || old.base.sha !== pr.base.sha;
        })) throw new QualificationError('PR inventory changed during verification');
        const state = validateDecision(receipt, this.client.config.repository, head, current);
        if (state === 'success') {
          if (signal.aborted) throw new QualificationError('qualification deadline exceeded');
          // NEVER mark a contributor-head check green: a newly opened PR
          // could inherit it without having appeared in this verifier receipt.
          // Test-merge commits are PR-scoped; they are independently matched
          // to the base/head parents, then each gets an App-owned check.
          const targets = await Promise.all(current.map(pr =>
            beforeDeadline(() => this.client.mergeTarget(pr, signal), signal)));
          if (new Set(targets).size !== current.length ||
              targets.some(sha => !SHA.test(sha) || sha === head)) {
            throw new QualificationError('PR test-merge identity is not unique');
          }
          const startedMerge = await boundedMap(targets, MAX_PARALLEL_HEADS, sha =>
            beforeDeadline(() => this.client.createCheck(
              sha, 'PR-specific exact-merge qualification', signal), signal));
          if (startedMerge.some(result => result.error)) {
            throw new QualificationError('cannot invalidate all PR-specific merge checks');
          }
          // Journal every potentially green merge SHA before writing ANY
          // success. Partial journal failures deny the entire group.
          for (const sha of targets) this.journal.mark(sha);
          const refreshed = await Promise.all(current.map(pr =>
            beforeDeadline(() => this.client.mergeTarget(pr, signal), signal)));
          if (targets.some((sha, index) => sha !== refreshed[index])) {
            throw new QualificationError('PR test-merge identity changed before publication');
          }
          if (epoch.generation !== this.reconciliationGeneration) {
            throw new QualificationError('reconciliation superseded before publication');
          }
          const mergeChecks = targets.map((sha, index) =>
            ({ sha, checkId: startedMerge[index].value }));
          const committed = await boundedMap(mergeChecks, MAX_PARALLEL_HEADS, ({ checkId }) =>
            beforeDeadline(() => this.client.concludeCheck(
              checkId, 'success',
              'Reviewed PR-specific exact-merge qualification passed.', signal), signal));
          if (committed.some(result => result.error)) {
            throw new QualificationError('PR-specific success publication incomplete');
          }
        } else if (state === 'failure') {
          await beforeDeadline(() => this.client.concludeCheck(id, 'failure',
            'Reviewed qualification policy rejected one or more gates.', signal), signal);
        }
      } catch (error) {
        try {
          await this.client.concludeCheck(id, 'failure',
            'Qualification verifier unavailable or inconsistent; deny by default and recheck on next trusted sweep.');
        } catch {
          // A success attempt that may have reached GitHub remains journaled.
          // Never discard the write-ahead entry after an ambiguous API error.
        }
        throw error;
      }
    });
    for (let i = 0; i < outcomes.length; i++) {
      if (outcomes[i].error) errors.push(`${candidates[i].head}: ${outcomes[i].error.message}`);
    }
    if (sweepSignal.aborted) errors.push('reconciliation step deadline exceeded');
    if (epoch.generation !== this.reconciliationGeneration) {
      errors.push('reconciliation superseded by newer evidence');
    }
    if (errors.length) {
      this.epoch = null; // Restart by revoking any journaled successes.
      throw new QualificationError(
        `${errors.length} qualification head(s) degraded: ${errors.slice(0, 3).join('; ')}`);
    }
    epoch.cursor += candidates.length;
    if (epoch.cursor === epoch.candidates.length) {
      this.epoch = null;
      return { complete: true, remaining: 0 };
    }
    return { complete: false, remaining: epoch.candidates.length - epoch.cursor };
  }
}
