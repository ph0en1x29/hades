'use strict';
/**
 * Hades Dashboard — Node.js backend (zero npm deps)
 * Port: 8666  |  Replaces: app.py / FastAPI + uvicorn
 */

const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const { execFile, spawn } = require('child_process');
const crypto  = require('crypto');
const os      = require('os');
const { URL } = require('url');

// ─────────────────────────────────────────────────────────────
// Paths
// ─────────────────────────────────────────────────────────────
const DASHBOARD_DIR  = __dirname;
const REPO_ROOT      = path.dirname(DASHBOARD_DIR);
const STATIC_DIR     = path.join(DASHBOARD_DIR, 'static');
const UPLOADS_DIR    = path.join(REPO_ROOT, 'data', 'datasets', 'uploads');
const RESULTS_DIR    = path.join(REPO_ROOT, 'results');
const GPU_RESULTS_DIR = path.join(RESULTS_DIR, 'gpu');
const BENCHMARK_FILE = path.join(REPO_ROOT, 'data', 'benchmark', 'hades_benchmark_v1.jsonl');
const SCRIPTS_DIR    = path.join(REPO_ROOT, 'scripts');
const JOBS_FILE      = path.join(DASHBOARD_DIR, 'jobs.json');
const CONFIG_FILE    = path.join(DASHBOARD_DIR, 'model_config.json');

const HF_HOME   = process.env.HF_HOME
  ? path.join(process.env.HF_HOME, 'hub')
  : path.join(os.homedir(), '.cache', 'huggingface', 'hub');
const VLLM_CONTAINER = 'hades-vllm';
const VLLM_PORT      = 8000;
const PORT           = 8666;

// Ensure upload dir exists
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─────────────────────────────────────────────────────────────
// Default model config
// ─────────────────────────────────────────────────────────────
const DEFAULT_CONFIG = [
  {
    key: 'kimi', name: 'Kimi K2.5',
    hf_id: 'moonshotai/Kimi-K2.5-GPTQ-Int4',
    size_label: '~250 GB', gpus_needed: 4, tensor_parallel: 4,
    notes: 'Strongest model — run first. Confirm exact HF ID before downloading.'
  },
  {
    key: 'r1', name: 'DeepSeek R1',
    hf_id: 'deepseek-ai/DeepSeek-R1-GPTQ-Int4',
    size_label: '~168 GB', gpus_needed: 4, tensor_parallel: 4,
    notes: 'Verify GPTQ variant ID on HuggingFace before downloading.'
  },
  {
    key: 'qwen', name: 'Qwen 3.5',
    hf_id: 'Qwen/Qwen3.5-MoE-A3B-GPTQ-Int4',
    size_label: '~100 GB', gpus_needed: 2, tensor_parallel: 2,
    notes: 'MoE model — only 3B active params. Verify model ID on HF.'
  },
  {
    key: 'glm', name: 'GLM-5',
    hf_id: 'THUDM/GLM-5-GPTQ-Int4',
    size_label: '~186 GB', gpus_needed: 4, tensor_parallel: 4,
    notes: 'Check THUDM org on HF for latest GLM-5 GPTQ release.'
  }
];

// ─────────────────────────────────────────────────────────────
// In-memory state
// ─────────────────────────────────────────────────────────────
/** key → { pct, log_line, error, done, process } */
const downloadState = {};
/** job_id → Set<net.Socket> (raw TCP, WebSocket-upgraded) */
const wsClients = new Map();

// ═════════════════════════════════════════════════════════════
// Jobs JSON store  (replaces SQLite)
// ═════════════════════════════════════════════════════════════

function loadStore() {
  try {
    return JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8'));
  } catch {
    return { jobs: [], uploads: [] };
  }
}

function saveStore(data) {
  fs.writeFileSync(JOBS_FILE, JSON.stringify(data, null, 2));
}

function createJob(models, experiments) {
  const id   = crypto.randomBytes(4).toString('hex');
  const now  = new Date().toISOString();
  const job  = {
    id,
    models:             models.join(','),
    experiments:        experiments.join(','),
    status:             'pending',
    progress:           0,
    total:              models.length * experiments.length,
    current_model:      null,
    current_experiment: null,
    started_at:         null,
    finished_at:        null,
    error:              null,
    created_at:         now
  };
  const store = loadStore();
  store.jobs.unshift(job);
  saveStore(store);
  return id;
}

function updateJob(id, updates) {
  const store = loadStore();
  const job   = store.jobs.find(j => j.id === id);
  if (job) Object.assign(job, updates);
  saveStore(store);
}

function getJob(id) {
  return loadStore().jobs.find(j => j.id === id) || null;
}

function listJobs(limit = 50) {
  return loadStore().jobs.slice(0, limit);
}

function addUpload(meta) {
  const id    = crypto.randomBytes(4).toString('hex');
  const store = loadStore();
  if (!store.uploads) store.uploads = [];
  store.uploads.unshift({ id, ...meta, created_at: new Date().toISOString() });
  saveStore(store);
  return id;
}

function listUploads(limit = 100) {
  return (loadStore().uploads || []).slice(0, limit);
}

// ═════════════════════════════════════════════════════════════
// Model config
// ═════════════════════════════════════════════════════════════

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE))
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {}
  return DEFAULT_CONFIG;
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function getModel(key) {
  return loadConfig().find(m => m.key === key) || null;
}

// ═════════════════════════════════════════════════════════════
// HF cache helpers
// ═════════════════════════════════════════════════════════════

function hfCacheDirFor(hfId) {
  return path.join(HF_HOME, 'models--' + hfId.replace('/', '--'));
}

function dirSizeGb(dir) {
  let total = 0;
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory())     walk(p);
      else if (e.isFile()) {
        try { total += fs.statSync(p).size; } catch {}
      }
    }
  }
  walk(dir);
  return Math.round(total / (1024 ** 3) * 10) / 10;
}

function downloadStatus(key) {
  const model = getModel(key);
  if (!model) return { status: 'unknown' };

  const hfId     = model.hf_id;
  const cacheDir = hfCacheDirFor(hfId);
  const marker   = path.join(cacheDir, 'refs', 'main');

  if (fs.existsSync(marker))
    return { status: 'ready', size_gb: dirSizeGb(cacheDir), cache_dir: cacheDir };

  const st = downloadState[key];
  if (st && st.process && !st.done) {
    return {
      status:   'downloading',
      pct:      st.pct      || 0,
      size_gb:  dirSizeGb(cacheDir),
      log_line: st.log_line || ''
    };
  }

  if (fs.existsSync(cacheDir)) {
    const sizeGb = dirSizeGb(cacheDir);
    if (sizeGb > 0.1) {
      if (st && st.error)
        return { status: 'error', error: st.error, size_gb: sizeGb };
      return { status: 'partial', size_gb: sizeGb };
    }
  }

  return { status: 'not_downloaded' };
}

function startDownload(key) {
  const model = getModel(key);
  if (!model) return { error: `Unknown model key: ${key}` };

  const st = downloadState[key];
  if (st && st.process && !st.done) return { error: 'Download already running' };

  downloadState[key] = { pct: 0, log_line: 'Starting...', done: false };

  const proc = spawn(
    'huggingface-cli',
    ['download', model.hf_id, '--local-dir-use-symlinks', 'True'],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );
  downloadState[key].process = proc;

  const handleData = (raw) => {
    for (const line of raw.toString().split('\n')) {
      const t = line.trim();
      if (!t) continue;
      const m   = t.match(/\b(\d{1,3})%/);
      const pct = m ? Math.min(parseInt(m[1]), 100) : (downloadState[key].pct || 0);
      downloadState[key].pct      = pct;
      downloadState[key].log_line = t.slice(0, 120);
    }
  };

  proc.stdout.on('data', handleData);
  proc.stderr.on('data', handleData);

  proc.on('close', code => {
    downloadState[key].done = true;
    if (code === 0) {
      downloadState[key].pct      = 100;
      downloadState[key].log_line = 'Complete';
    } else {
      downloadState[key].error = `huggingface-cli exited ${code}`;
    }
  });

  proc.on('error', err => {
    downloadState[key].done  = true;
    downloadState[key].error = err.code === 'ENOENT'
      ? 'huggingface-cli not found — run: pip install huggingface_hub'
      : err.message;
  });

  return { status: 'started', hf_id: model.hf_id };
}

// ═════════════════════════════════════════════════════════════
// GPU  (nvidia-smi)
// ═════════════════════════════════════════════════════════════

function getGpuStatus() {
  return new Promise(resolve => {
    execFile(
      'nvidia-smi',
      ['--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu',
       '--format=csv,noheader,nounits'],
      { timeout: 10000 },
      (err, stdout, stderr) => {
        if (err) {
          const msg = err.code === 'ENOENT'
            ? 'nvidia-smi not found — no GPU or driver not installed'
            : (stderr.trim() || 'nvidia-smi failed');
          return resolve({ available: false, count: 0, total_memory_gb: 0, used_memory_gb: 0, error: msg, gpus: [] });
        }

        const gpus = [];
        for (const line of stdout.trim().split('\n')) {
          const p = line.split(',').map(s => s.trim());
          if (p.length < 6) continue;
          gpus.push({
            index:           parseInt(p[0]),
            name:            p[1],
            memory_total_mb: parseInt(p[2]),
            memory_used_mb:  parseInt(p[3]),
            utilization_pct: parseInt(p[4]),
            temperature_c:   parseInt(p[5])
          });
        }

        const totMem  = gpus.reduce((s, g) => s + g.memory_total_mb, 0);
        const usedMem = gpus.reduce((s, g) => s + g.memory_used_mb, 0);
        resolve({
          available:       true,
          count:           gpus.length,
          total_memory_gb: Math.round(totMem  / 1024 * 10) / 10,
          used_memory_gb:  Math.round(usedMem / 1024 * 10) / 10,
          error:           null,
          gpus
        });
      }
    );
  });
}

// ═════════════════════════════════════════════════════════════
// vLLM Docker management
// ═════════════════════════════════════════════════════════════

function dockerAvailable() {
  return new Promise(resolve => {
    execFile('docker', ['info'], { timeout: 5000 }, err => resolve(!err));
  });
}

function checkVllmHealth() {
  return new Promise(resolve => {
    const req = http.get(
      { hostname: 'localhost', port: VLLM_PORT, path: '/health', timeout: 2000 },
      res => resolve(res.statusCode === 200)
    );
    req.on('error',   () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

function servingStatus() {
  return new Promise(async resolve => {
    if (!(await dockerAvailable()))
      return resolve({ status: 'no_docker', error: 'Docker not available' });

    execFile(
      'docker',
      ['inspect', '--format', '{{.State.Status}}|{{index .Config.Cmd 1}}', VLLM_CONTAINER],
      { timeout: 5000 },
      async (err, stdout) => {
        if (err) return resolve({ status: 'stopped' });

        const parts      = stdout.trim().split('|');
        const state      = parts[0] || 'unknown';
        const modelHint  = parts[1] || '';
        const healthOk   = await checkVllmHealth();

        resolve({
          status:      state,
          health:      healthOk ? 'healthy' : (state === 'running' ? 'starting' : 'stopped'),
          model_hint:  modelHint,
          container:   VLLM_CONTAINER,
          port:        VLLM_PORT
        });
      }
    );
  });
}

function startServing(hfId, tensorParallel, gpuCount) {
  return new Promise(async resolve => {
    if (!(await dockerAvailable()))
      return resolve({ error: 'Docker not available' });

    execFile('docker', ['rm', '-f', VLLM_CONTAINER], { timeout: 10000 }, () => {
      const gpuSpec = gpuCount >= 4 ? 'device=0,1,2,3' : 'device=0,1';
      const hfHome  = path.join(os.homedir(), '.cache', 'huggingface');
      const args    = [
        'run',
        '--gpus', gpuSpec,
        '-d',
        '--name', VLLM_CONTAINER,
        '-v', `${hfHome}:/root/.cache/huggingface`,
        '-p', `${VLLM_PORT}:${VLLM_PORT}`,
        'vllm/vllm-openai:latest',
        '--model', hfId,
        '--tensor-parallel-size', String(tensorParallel),
        '--quantization', 'gptq',
        '--dtype', 'float16',
        '--max-model-len', '4096'
      ];

      execFile('docker', args, { timeout: 30000 }, (err, _stdout, stderr) => {
        if (err) return resolve({ error: stderr.trim() || 'docker run failed' });
        resolve({ status: 'starting', container: VLLM_CONTAINER, model: hfId });
      });
    });
  });
}

function stopServing() {
  return new Promise(async resolve => {
    if (!(await dockerAvailable()))
      return resolve({ error: 'Docker not available' });

    execFile('docker', ['rm', '-f', VLLM_CONTAINER], { timeout: 15000 }, (err, _out, stderr) => {
      if (err && !stderr.includes('No such container'))
        return resolve({ error: stderr.trim() });
      resolve({ status: 'stopped' });
    });
  });
}

function diskInfo() {
  return new Promise(resolve => {
    fs.statfs(os.homedir(), (err, stats) => {
      if (err) {
        // Fallback to `df`
        execFile('df', ['-B1', os.homedir()], { timeout: 5000 }, (e2, stdout) => {
          if (e2) return resolve({ error: e2.message });
          const p = stdout.trim().split('\n')[1].split(/\s+/);
          resolve({
            total_gb:      Math.round(parseInt(p[1]) / (1024 ** 3) * 10) / 10,
            used_gb:       Math.round(parseInt(p[2]) / (1024 ** 3) * 10) / 10,
            free_gb:       Math.round(parseInt(p[3]) / (1024 ** 3) * 10) / 10,
            hf_cache_gb:   fs.existsSync(HF_HOME) ? dirSizeGb(HF_HOME) : 0,
            hf_cache_path: HF_HOME
          });
        });
        return;
      }
      const blockSize = stats.bsize;
      resolve({
        total_gb:      Math.round(stats.blocks  * blockSize / (1024 ** 3) * 10) / 10,
        used_gb:       Math.round((stats.blocks - stats.bfree) * blockSize / (1024 ** 3) * 10) / 10,
        free_gb:       Math.round(stats.bfree   * blockSize / (1024 ** 3) * 10) / 10,
        hf_cache_gb:   fs.existsSync(HF_HOME) ? dirSizeGb(HF_HOME) : 0,
        hf_cache_path: HF_HOME
      });
    });
  });
}

// ═════════════════════════════════════════════════════════════
// Benchmark stats
// ═════════════════════════════════════════════════════════════

function getBenchmarkStats() {
  const base = { alerts: 12147, techniques: 27, tactics: 9 };
  if (!fs.existsSync(BENCHMARK_FILE))
    return { ...base, source: 'default' };

  try {
    const lines  = fs.readFileSync(BENCHMARK_FILE, 'utf8')
      .split('\n').filter(l => l.trim());
    const alerts = lines
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);

    const techniques = new Set();
    const tactics    = new Set();
    for (const a of alerts) {
      for (const t of (a.benchmark?.mitre_techniques || [])) techniques.add(t);
      for (const t of (a.benchmark?.mitre_tactics    || [])) tactics.add(t);
    }
    return {
      alerts:     alerts.length,
      techniques: techniques.size || base.techniques,
      tactics:    tactics.size    || base.tactics,
      source:     'live'
    };
  } catch {
    return { ...base, source: 'default' };
  }
}

// ═════════════════════════════════════════════════════════════
// Results reader
// ═════════════════════════════════════════════════════════════

function readResults() {
  const out = {};

  if (!fs.existsSync(GPU_RESULTS_DIR)) {
    // Flat fallback (dev/mock results)
    if (fs.existsSync(RESULTS_DIR)) {
      for (const f of fs.readdirSync(RESULTS_DIR).filter(n => n.endsWith('.json')).slice(0, 50)) {
        try {
          const data  = JSON.parse(fs.readFileSync(path.join(RESULTS_DIR, f), 'utf8'));
          const model = String(data.model || f.replace('.json', ''));
          const exp   = String(data.experiment_id || '?');
          if (!out[model]) out[model] = {};
          out[model][exp] = data;
        } catch {}
      }
    }
    return out;
  }

  for (const modelName of fs.readdirSync(GPU_RESULTS_DIR)) {
    const modelDir = path.join(GPU_RESULTS_DIR, modelName);
    try { if (!fs.statSync(modelDir).isDirectory()) continue; } catch { continue; }

    for (const expName of fs.readdirSync(modelDir)) {
      const expDir = path.join(modelDir, expName);
      try { if (!fs.statSync(expDir).isDirectory()) continue; } catch { continue; }

      const runs = fs.readdirSync(expDir).filter(n => /^run_.*\.json$/.test(n)).sort();
      if (!runs.length) continue;

      try {
        const data = JSON.parse(fs.readFileSync(path.join(expDir, runs[runs.length - 1]), 'utf8'));
        if (!out[modelName]) out[modelName] = {};
        out[modelName][expName] = data;
      } catch {}
    }
  }

  return out;
}

// ═════════════════════════════════════════════════════════════
// File format detection / alert counting
// ═════════════════════════════════════════════════════════════

function detectFormat(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith('.xml')) {
    try {
      const t = fs.readFileSync(filePath, 'utf8').slice(0, 500);
      if (t.includes('Sysmon') || t.includes('sysmon'))           return 'Sysmon XML';
      if (t.includes('EventID') || t.includes('Security'))        return 'Windows Security XML';
      return 'XML';
    } catch { return 'XML'; }
  }
  if (name.endsWith('.jsonl') || name.endsWith('.ndjson')) {
    try {
      const obj = JSON.parse(fs.readFileSync(filePath, 'utf8').split('\n')[0]);
      return (obj.source || obj.sourcetype) ? 'Splunk JSONL' : 'JSONL';
    } catch { return 'JSONL'; }
  }
  if (name.endsWith('.json')) {
    try {
      const s = fs.readFileSync(filePath, 'utf8').slice(0, 1000).toLowerCase();
      return (s.includes('alert') || s.includes('event_type')) ? 'Suricata JSON' : 'JSON';
    } catch { return 'JSON'; }
  }
  if (name.endsWith('.csv')) return 'CSV';
  return null;
}

function countAlerts(filePath, fmt) {
  try {
    if (fmt === 'JSONL' || fmt === 'Splunk JSONL')
      return fs.readFileSync(filePath, 'utf8').split('\n').filter(l => l.trim()).length;
    if (fmt === 'JSON' || fmt === 'Suricata JSON') {
      const d = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return Array.isArray(d) ? d.length : 1;
    }
    if (fmt && fmt.includes('XML')) {
      const t = fs.readFileSync(filePath, 'utf8');
      return (t.match(/<Event/g) || t.match(/<Alert/g) || []).length || null;
    }
    return null;
  } catch { return null; }
}

// ═════════════════════════════════════════════════════════════
// Experiment runner
// ═════════════════════════════════════════════════════════════

const MODEL_MAP = { 'Kimi K2.5': 'kimi', 'DeepSeek R1': 'r1', 'Qwen 3.5': 'qwen', 'GLM-5': 'glm' };
const EXP_MAP   = { E1: 'e1', E2: 'e2-sample', E4: 'e4', E5: 'e5', E7: 'e7', E8: 'e8' };

async function runJob(jobId, models, experiments) {
  const total      = models.length * experiments.length;
  let   done       = 0;
  const scriptPath = path.join(SCRIPTS_DIR, 'run_gpu_experiments.sh');

  try {
    for (const modelName of models) {
      const modelKey = MODEL_MAP[modelName] || modelName.toLowerCase().split(' ')[0];

      for (const expName of experiments) {
        const phase = EXP_MAP[expName] || expName.toLowerCase();

        updateJob(jobId, {
          current_model:      modelName,
          current_experiment: expName,
          progress:           done,
          total,
          status:             'running'
        });
        broadcast(jobId, {
          type: 'progress', job_id: jobId,
          current_model: modelName, current_experiment: expName,
          progress: done, total
        });

        if (fs.existsSync(scriptPath)) {
          await new Promise((resolve, reject) => {
            const proc = spawn('bash', [scriptPath, modelKey, phase], {
              cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe']
            });
            const onData = (data) => {
              for (const line of data.toString().split('\n')) {
                const t = line.trim();
                if (t) broadcast(jobId, { type: 'log', job_id: jobId, line: t });
              }
            };
            proc.stdout.on('data', onData);
            proc.stderr.on('data', onData);
            proc.on('close', code => {
              if (code !== 0) reject(new Error(`Script exited ${code} for ${modelName}/${expName}`));
              else resolve();
            });
            proc.on('error', reject);
          });
        } else {
          // Dev mode
          broadcast(jobId, {
            type: 'log', job_id: jobId,
            line: `[DEV] Would run: ${scriptPath} ${modelKey} ${phase}`
          });
          await new Promise(r => setTimeout(r, 1000));
        }

        done++;
        updateJob(jobId, { progress: done });
      }
    }

    updateJob(jobId, { status: 'completed', progress: total, finished_at: new Date().toISOString() });
    broadcast(jobId, { type: 'done', job_id: jobId, status: 'completed' });

  } catch (err) {
    updateJob(jobId, { status: 'error', error: err.message, finished_at: new Date().toISOString() });
    broadcast(jobId, { type: 'error', job_id: jobId, error: err.message });
  }
}

// ═════════════════════════════════════════════════════════════
// WebSocket — manual implementation (no npm)
// ═════════════════════════════════════════════════════════════

function wsAcceptKey(key) {
  return crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

/** Encode a JSON object as a WebSocket text frame. */
function wsEncodeFrame(obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const len     = payload.length;
  let header;

  if (len < 126) {
    header    = Buffer.alloc(2);
    header[0] = 0x81;   // FIN + text opcode
    header[1] = len;
  } else if (len < 65536) {
    header    = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header    = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

/**
 * Decode ONE WebSocket frame from buffer.
 * Returns { frame: { opcode, payload }, consumed } or null if incomplete.
 */
function wsDecodeFrame(buf) {
  if (buf.length < 2) return null;

  const masked  = !!(buf[1] & 0x80);
  let   lenByte = buf[1] & 0x7f;
  let   offset  = 2;
  let   payloadLen;

  if (lenByte < 126) {
    payloadLen = lenByte;
  } else if (lenByte === 126) {
    if (buf.length < 4) return null;
    payloadLen = buf.readUInt16BE(2);
    offset     = 4;
  } else {
    if (buf.length < 10) return null;
    payloadLen = Number(buf.readBigUInt64BE(2));
    offset     = 10;
  }

  const maskLen  = masked ? 4 : 0;
  const total    = offset + maskLen + payloadLen;
  if (buf.length < total) return null;

  let payload;
  if (masked) {
    const mask = buf.slice(offset, offset + 4);
    const raw  = buf.slice(offset + 4, offset + 4 + payloadLen);
    payload    = Buffer.allocUnsafe(payloadLen);
    for (let i = 0; i < payloadLen; i++) payload[i] = raw[i] ^ mask[i % 4];
  } else {
    payload = buf.slice(offset, offset + payloadLen);
  }

  return { frame: { opcode: buf[0] & 0x0f, payload }, consumed: total };
}

function wsRegister(jobId, socket) {
  if (!wsClients.has(jobId)) wsClients.set(jobId, new Set());
  wsClients.get(jobId).add(socket);
}

function wsUnregister(socket) {
  for (const [jid, sockets] of wsClients) {
    sockets.delete(socket);
    if (sockets.size === 0) wsClients.delete(jid);
  }
}

function broadcast(jobId, payload) {
  const frame   = wsEncodeFrame(payload);
  const targets = new Set([
    ...(wsClients.get(jobId)    || []),
    ...(wsClients.get('__all__')|| [])
  ]);
  for (const sock of targets) {
    try { sock.write(frame); } catch { wsUnregister(sock); }
  }
}

function handleWsUpgrade(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  // Complete the WebSocket handshake
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${wsAcceptKey(key)}`,
    '', ''
  ].join('\r\n'));

  let buffer = Buffer.alloc(0);
  let jobId  = null;

  // 5-second timeout to receive the first {job_id} message
  const initTimeout = setTimeout(() => {
    if (!jobId) socket.destroy();
  }, 5000);

  socket.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 2) {
      const result = wsDecodeFrame(buffer);
      if (!result) break;

      buffer = buffer.slice(result.consumed);
      const { opcode, payload } = result.frame;

      if (opcode === 0x8) {           // Close
        socket.destroy();
        wsUnregister(socket);
        return;
      }

      if (opcode === 0x9) {           // Ping → Pong
        const pong = Buffer.alloc(2);
        pong[0] = 0x8a; pong[1] = 0;
        socket.write(pong);

      } else if (opcode === 0x1 || opcode === 0x2) {  // Text / Binary
        try {
          const msg = JSON.parse(payload.toString('utf8'));

          if (!jobId) {
            clearTimeout(initTimeout);
            jobId = msg.job_id || '__all__';
            wsRegister(jobId, socket);

            if (jobId !== '__all__') {
              const job = getJob(jobId);
              if (job) {
                try { socket.write(wsEncodeFrame({ type: 'state', ...job })); } catch {}
              }
            }
          }
        } catch { /* ignore malformed JSON */ }
      }
    }
  });

  socket.on('close', () => { clearTimeout(initTimeout); wsUnregister(socket); });
  socket.on('error', () => { clearTimeout(initTimeout); wsUnregister(socket); });
}

// ═════════════════════════════════════════════════════════════
// Multipart form-data parser (no npm)
// ═════════════════════════════════════════════════════════════

function parseMultipart(body, boundary) {
  const files  = [];
  const sep    = Buffer.from('--' + boundary);
  let   start  = body.indexOf(sep) + sep.length;

  while (start < body.length) {
    // Skip "--" (end marker) or "\r\n"
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break;
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;

    const nextSep = body.indexOf(sep, start);
    if (nextSep === -1) break;

    const part   = body.slice(start, nextSep - 2);   // strip trailing \r\n
    start        = nextSep + sep.length;

    const hdrEnd = part.indexOf(Buffer.from('\r\n\r\n'));
    if (hdrEnd === -1) continue;

    const headers = part.slice(0, hdrEnd).toString('utf8');
    const content = part.slice(hdrEnd + 4);

    const fnMatch = headers.match(/Content-Disposition:[^\r\n]*filename="([^"]+)"/i);
    const ctMatch = headers.match(/Content-Type:\s*([^\r\n]+)/i);

    if (fnMatch) {
      files.push({
        filename:    fnMatch[1],
        contentType: ctMatch ? ctMatch[1].trim() : 'application/octet-stream',
        data:        content
      });
    }
  }

  return files;
}

// ═════════════════════════════════════════════════════════════
// Static file server
// ═════════════════════════════════════════════════════════════

const MIME = {
  '.html':  'text/html; charset=utf-8',
  '.js':    'application/javascript; charset=utf-8',
  '.css':   'text/css; charset=utf-8',
  '.json':  'application/json',
  '.png':   'image/png',
  '.jpg':   'image/jpeg',
  '.svg':   'image/svg+xml',
  '.ico':   'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff':  'font/woff'
};

function serveStatic(res, urlPath) {
  let rel = urlPath;
  if (rel === '/' || !rel) rel = '/index.html';
  if (rel.startsWith('/static/')) rel = rel.slice('/static'.length);
  rel = rel.replace(/^\/+/, '');

  const normalized = path.normalize(rel);
  const filePath   = path.join(STATIC_DIR, normalized);

  // Path traversal guard
  if (!filePath.startsWith(STATIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.access(filePath, fs.constants.R_OK, err => {
    const target = err ? path.join(STATIC_DIR, 'index.html') : filePath;
    fs.readFile(target, (e, data) => {
      if (e) { res.writeHead(404); res.end('Not found'); return; }
      const ct = MIME[path.extname(target)] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': ct });
      res.end(data);
    });
  });
}

// ═════════════════════════════════════════════════════════════
// HTTP helpers
// ═════════════════════════════════════════════════════════════

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data',  c => chunks.push(c));
    req.on('end',   () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function parseJson(buf) {
  return JSON.parse(buf.toString('utf8'));
}

// ═════════════════════════════════════════════════════════════
// Router
// ═════════════════════════════════════════════════════════════

const SPA_ROUTES = new Set(['/', '/experiments', '/results', '/models']);

async function handleRequest(req, res) {
  const { pathname } = new URL(req.url, 'http://localhost');
  const method       = req.method.toUpperCase();

  // CORS
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── Static / SPA ──────────────────────────────────────────
  if (!pathname.startsWith('/api/') && !pathname.startsWith('/ws/')) {
    serveStatic(res, SPA_ROUTES.has(pathname) ? '/index.html' : pathname);
    return;
  }

  try {
    // ── GET /api/benchmark ──────────────────────────────────
    if (method === 'GET' && pathname === '/api/benchmark') {
      return sendJson(res, 200, getBenchmarkStats());
    }

    // ── GET /api/uploads ────────────────────────────────────
    if (method === 'GET' && pathname === '/api/uploads') {
      return sendJson(res, 200, listUploads());
    }

    // ── POST /api/upload ────────────────────────────────────
    if (method === 'POST' && pathname === '/api/upload') {
      const ct       = req.headers['content-type'] || '';
      const bmMatch  = ct.match(/boundary=([^\s;]+)/);
      if (!bmMatch) return sendJson(res, 400, { error: 'No multipart boundary' });

      const body  = await readBody(req);
      const files = parseMultipart(body, bmMatch[1]);
      if (!files.length) return sendJson(res, 400, { error: 'No file in upload' });

      const file = files[0];
      const dest = path.join(UPLOADS_DIR, path.basename(file.filename));
      fs.writeFileSync(dest, file.data);

      const fmt        = detectFormat(dest);
      const alertCount = countAlerts(dest, fmt);
      const id         = addUpload({
        filename:          file.filename,
        format:            fmt,
        alert_count:       alertCount,
        validation_status: 'skipped',
        validation_issues: []
      });

      return sendJson(res, 200, {
        id, filename: file.filename, format: fmt,
        alert_count: alertCount, validation_status: 'skipped', validation_issues: []
      });
    }

    // ── GET /api/gpu ────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/gpu') {
      return sendJson(res, 200, await getGpuStatus());
    }

    // ── GET /api/disk ────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/disk') {
      return sendJson(res, 200, await diskInfo());
    }

    // ── GET /api/models/serving ──────────────────────────────
    if (method === 'GET' && pathname === '/api/models/serving') {
      const st       = await servingStatus();
      const healthOk = await checkVllmHealth();
      return sendJson(res, 200, { ...st, health_ok: healthOk });
    }

    // ── GET /api/models/config ───────────────────────────────
    if (method === 'GET' && pathname === '/api/models/config') {
      return sendJson(res, 200, loadConfig());
    }

    // ── POST /api/models/config  (also accepts PUT) ──────────
    if ((method === 'POST' || method === 'PUT') && pathname === '/api/models/config') {
      const cfg = parseJson(await readBody(req));
      saveConfig(cfg);
      return sendJson(res, 200, { status: 'saved' });
    }

    // ── POST /api/models/stop ────────────────────────────────
    if (method === 'POST' && pathname === '/api/models/stop') {
      return sendJson(res, 200, await stopServing());
    }

    // ── GET /api/models ──────────────────────────────────────
    if (method === 'GET' && pathname === '/api/models') {
      const cfg    = loadConfig();
      const models = cfg.map(m => ({ ...m, download: downloadStatus(m.key) }));
      return sendJson(res, 200, { models, disk: await diskInfo() });
    }

    // ── POST /api/models/:key/download ───────────────────────
    {
      const m = pathname.match(/^\/api\/models\/([^/]+)\/download$/);
      if (m && method === 'POST') {
        const result = startDownload(m[1]);
        return sendJson(res, result.error ? 400 : 200, result);
      }
    }

    // ── GET /api/models/:key/download-status ─────────────────
    {
      const m = pathname.match(/^\/api\/models\/([^/]+)\/download-status$/);
      if (m && method === 'GET') {
        return sendJson(res, 200, downloadStatus(m[1]));
      }
    }

    // ── POST /api/models/:key/serve ──────────────────────────
    {
      const m = pathname.match(/^\/api\/models\/([^/]+)\/serve$/);
      if (m && method === 'POST') {
        const model = getModel(m[1]);
        if (!model) return sendJson(res, 404, { error: `Unknown model: ${m[1]}` });
        const result = await startServing(
          model.hf_id, model.tensor_parallel || 4, model.gpus_needed || 4
        );
        return sendJson(res, result.error ? 500 : 200, result);
      }
    }

    // ── POST /api/models/:key/stop ───────────────────────────
    {
      const m = pathname.match(/^\/api\/models\/([^/]+)\/stop$/);
      if (m && method === 'POST') {
        return sendJson(res, 200, await stopServing());
      }
    }

    // ── POST /api/run ────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/run') {
      const body        = parseJson(await readBody(req));
      const models      = body.models      || [];
      const experiments = body.experiments || [];
      if (!models.length || !experiments.length)
        return sendJson(res, 400, { error: 'models and experiments required' });

      const jobId = createJob(models, experiments);
      updateJob(jobId, { status: 'running', started_at: new Date().toISOString() });
      runJob(jobId, models, experiments);   // fire-and-forget async
      return sendJson(res, 200, { job_id: jobId, status: 'started' });
    }

    // ── GET /api/jobs ────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/jobs') {
      return sendJson(res, 200, listJobs());
    }

    // ── GET /api/results ─────────────────────────────────────
    if (method === 'GET' && pathname === '/api/results') {
      return sendJson(res, 200, readResults());
    }

    // ── GET /api/results/:model ──────────────────────────────
    {
      const m = pathname.match(/^\/api\/results\/(.+)$/);
      if (m && method === 'GET') {
        return sendJson(res, 200, readResults()[m[1]] || {});
      }
    }

    // ── Legacy compat: POST /api/experiments/run ─────────────
    if (method === 'POST' && pathname === '/api/experiments/run') {
      const body        = parseJson(await readBody(req));
      const models      = body.models      || [];
      const experiments = body.experiments || [];
      if (!models.length || !experiments.length)
        return sendJson(res, 400, { error: 'models and experiments required' });

      const jobId = createJob(models, experiments);
      updateJob(jobId, { status: 'running', started_at: new Date().toISOString() });
      runJob(jobId, models, experiments);
      return sendJson(res, 200, { job_id: jobId, status: 'started' });
    }

    // ── Legacy compat: GET /api/experiments/status ───────────
    if (method === 'GET' && pathname === '/api/experiments/status') {
      return sendJson(res, 200, listJobs());
    }

    // ── 404 ──────────────────────────────────────────────────
    sendJson(res, 404, { error: `Not found: ${method} ${pathname}` });

  } catch (err) {
    console.error('[error]', err.message);
    sendJson(res, 500, { error: err.message });
  }
}

// ═════════════════════════════════════════════════════════════
// Server startup
// ═════════════════════════════════════════════════════════════

const server = http.createServer(handleRequest);
server.on('upgrade', handleWsUpgrade);

server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🔥 Hades Dashboard (Node.js)');
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Jobs file: ${JOBS_FILE}`);
  console.log(`   HF cache:  ${HF_HOME}\n`);
});
