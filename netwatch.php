<?php
/**
 * netwatch web UI
 * Place in /var/www/netwatch/index.php (or similar)
 * nginx config: root /var/www/netwatch; index index.php;
 *
 * Requires: www-data in sudoers for netwatch.py (see README)
 */

define('DB_PATH',      '/var/lib/netwatch/known_devices.json');
define('NETWATCH_CMD', 'python3 /usr/local/bin/netwatch.py');

// --- AJAX action handler ---------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    $action = $_POST['action'];
    $output = '';
    $ok     = true;

    if ($action === 'scan') {
        $cmd = NETWATCH_CMD . ' 2>&1';
        exec($cmd, $lines, $rc);
        $output = implode("\n", $lines);
        $ok = ($rc === 0);

    } elseif ($action === 'lookup') {
        $cmd = NETWATCH_CMD . ' --lookup 2>&1';
        exec($cmd, $lines, $rc);
        $output = implode("\n", $lines);
        $ok = ($rc === 0);

    } elseif ($action === 'sendhosts') {
        $cmd = NETWATCH_CMD . ' --sendhosts 2>&1';
        exec($cmd, $lines, $rc);
        $output = implode("\n", $lines);
        $ok = ($rc === 0);

    } elseif ($action === 'save_label') {
        $mac   = preg_replace('/[^a-f0-9:]/', '', strtolower($_POST['mac'] ?? ''));
        $label = substr(trim($_POST['label'] ?? ''), 0, 64);

        if (!preg_match('/^([a-f0-9]{2}:){5}[a-f0-9]{2}$/', $mac)) {
            echo json_encode(['ok' => false, 'output' => 'Invalid MAC']);
            exit;
        }

        $db = json_decode(file_get_contents(DB_PATH), true) ?? [];
        if (isset($db[$mac])) {
            $db[$mac]['label'] = $label;
            file_put_contents(DB_PATH, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            $output = "Label saved for $mac";
        } else {
            $ok     = false;
            $output = "MAC not found in database";
        }

    } else {
        $ok     = false;
        $output = 'Unknown action';
    }

    echo json_encode(['ok' => $ok, 'output' => $output]);
    exit;
}

// --- Load database ---------------------------------------------------------
$db       = [];
$db_mtime = null;
if (file_exists(DB_PATH)) {
    $db_mtime = filemtime(DB_PATH);
    $db = json_decode(file_get_contents(DB_PATH), true) ?? [];
}

// Build flat list for table
$devices = [];
foreach ($db as $mac => $d) {
    $devices[] = [
        'mac'        => $mac,
        'label'      => $d['label']      ?? '',
        'hostname'   => $d['hostname']   ?? '',
        'ipv4'       => $d['ipv4']       ?? '',
        'vendor'     => $d['vendor']     ?? '',
        'ipv6_ll'    => implode(', ', $d['ipv6_link_local'] ?? []),
        'first_seen' => $d['first_seen'] ?? '',
        'last_seen'  => $d['last_seen']  ?? '',
    ];
}

$device_count = count($devices);
$db_time      = $db_mtime ? date('Y-m-d H:i:s', $db_mtime) : '—';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netwatch</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #0d0f12;
    --surface:  #13171c;
    --border:   #1f2730;
    --accent:   #00d4aa;
    --accent2:  #0088ff;
    --warn:     #ff6b35;
    --text:     #c8d0d8;
    --text-dim: #5a6470;
    --text-hi:  #edf0f3;
    --mono:     'IBM Plex Mono', monospace;
    --sans:     'IBM Plex Sans', sans-serif;
    --radius:   4px;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    min-height: 100vh;
    padding: 0 0 60px;
  }

  /* Header */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: var(--mono);
    font-size: 18px;
    font-weight: 500;
    color: var(--accent);
    letter-spacing: -0.5px;
  }
  .logo span { color: var(--text-dim); }

  .meta {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
    text-align: right;
    line-height: 1.6;
  }
  .meta b { color: var(--text); }

  /* Actions bar */
  .actions {
    display: flex;
    gap: 10px;
    padding: 16px 28px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    align-items: center;
  }

  .btn {
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 500;
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn:active { transform: scale(0.97); }
  .btn.primary { border-color: var(--accent); color: var(--accent); }
  .btn.primary:hover { background: var(--accent); color: var(--bg); }
  .btn.loading { opacity: 0.5; pointer-events: none; }

  .btn-icon { font-size: 14px; }

  /* Search */
  .search-wrap {
    margin-left: auto;
    position: relative;
  }
  .search-wrap input {
    font-family: var(--mono);
    font-size: 12px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    padding: 7px 12px 7px 30px;
    width: 220px;
    outline: none;
    transition: border-color 0.15s;
  }
  .search-wrap input:focus { border-color: var(--accent); }
  .search-wrap::before {
    content: '⌕';
    position: absolute;
    left: 9px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-dim);
    font-size: 15px;
    pointer-events: none;
  }

  /* Output log */
  #output {
    margin: 0 28px 0;
    display: none;
    background: #080a0c;
    border: 1px solid var(--border);
    border-top: 2px solid var(--accent);
    border-radius: 0 0 var(--radius) var(--radius);
    padding: 12px 16px;
    font-family: var(--mono);
    font-size: 11px;
    color: #7abf9e;
    white-space: pre;
    max-height: 200px;
    overflow-y: auto;
    line-height: 1.6;
  }
  #output.error { border-top-color: var(--warn); color: #ff8c6a; }
  #output.visible { display: block; }

  /* Table container */
  .table-wrap {
    padding: 20px 28px 0;
    overflow-x: auto;
  }

  .table-header {
    display: flex;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 12px;
  }
  .table-header h2 {
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 500;
    color: var(--text-hi);
  }
  .count-badge {
    font-family: var(--mono);
    font-size: 11px;
    background: var(--border);
    color: var(--text-dim);
    padding: 2px 8px;
    border-radius: 10px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }

  thead th {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 500;
    color: var(--text-dim);
    text-align: left;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
    transition: color 0.15s;
    position: relative;
  }
  thead th:hover { color: var(--accent); }
  thead th.sort-asc::after  { content: ' ↑'; color: var(--accent); }
  thead th.sort-desc::after { content: ' ↓'; color: var(--accent); }
  thead th.no-sort { cursor: default; }
  thead th.no-sort:hover { color: var(--text-dim); }

  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }
  tbody tr:hover { background: rgba(255,255,255,0.025); }
  tbody tr.hidden { display: none; }

  td {
    padding: 10px 12px;
    vertical-align: top;
    line-height: 1.5;
  }

  .td-label input {
    font-family: var(--mono);
    font-size: 11px;
    background: transparent;
    border: none;
    border-bottom: 1px dashed var(--border);
    color: var(--accent2);
    width: 100%;
    min-width: 90px;
    padding: 1px 2px;
    outline: none;
    transition: border-color 0.15s;
  }
  .td-label input:focus { border-bottom-color: var(--accent2); }
  .td-label input::placeholder { color: var(--text-dim); font-style: italic; }
  .save-label {
    display: none;
    font-size: 10px;
    color: var(--accent2);
    cursor: pointer;
    margin-top: 2px;
    font-family: var(--mono);
  }
  .td-label input:focus ~ .save-label,
  .save-label.visible { display: block; }

  .td-host {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-hi);
  }
  .td-mac {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
  }
  .td-ip {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text);
  }
  .td-vendor { color: var(--text-dim); font-size: 11px; }
  .td-ipv6 {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    max-width: 200px;
    word-break: break-all;
  }
  .td-date {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    white-space: nowrap;
  }
  .td-date .date { color: var(--text); }
  .td-date .time { color: var(--text-dim); }

  .local-admin {
    font-size: 9px;
    color: var(--warn);
    font-family: var(--mono);
    opacity: 0.7;
  }

  /* Saving indicator */
  .saved-flash {
    font-size: 10px;
    color: var(--accent);
    font-family: var(--mono);
    margin-top: 2px;
    display: none;
  }

  /* Spinner */
  @keyframes spin { to { transform: rotate(360deg); } }
  .spinner {
    display: inline-block;
    width: 12px; height: 12px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
</style>
</head>
<body>

<header>
  <div class="logo">net<span>//</span>watch</div>
  <div class="meta">
    <b><?= $device_count ?></b> devices &nbsp;·&nbsp; db updated <b><?= htmlspecialchars($db_time) ?></b>
  </div>
</header>

<div class="actions">
  <button class="btn primary" onclick="runAction('scan')" id="btn-scan">
    <span class="btn-icon">⟳</span> Scan now
  </button>
  <button class="btn" onclick="runAction('lookup')" id="btn-lookup">
    <span class="btn-icon">⊡</span> Fritz!Box lookup
  </button>
  <button class="btn" onclick="runAction('sendhosts')" id="btn-sendhosts">
    <span class="btn-icon">✉</span> Send host list
  </button>
  <div class="search-wrap">
    <input type="text" id="search" placeholder="filter…" oninput="filterTable(this.value)">
  </div>
</div>

<div id="output"></div>

<div class="table-wrap">
  <div class="table-header">
    <h2>Known devices</h2>
    <span class="count-badge" id="count-badge"><?= $device_count ?></span>
  </div>

  <table id="devtable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Label</th>
        <th onclick="sortTable(1)">Hostname</th>
        <th onclick="sortTable(2)">IPv4</th>
        <th onclick="sortTable(3)">MAC</th>
        <th onclick="sortTable(4)">Vendor</th>
        <th onclick="sortTable(5)">IPv6 LL</th>
        <th onclick="sortTable(6)" class="sort-desc">First seen</th>
        <th onclick="sortTable(7)">Last seen</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($devices as $d): ?>
      <tr data-mac="<?= htmlspecialchars($d['mac']) ?>"
          data-search="<?= strtolower(htmlspecialchars(
              $d['label'].$d['hostname'].$d['ipv4'].$d['mac'].$d['vendor'].$d['ipv6_ll']
          )) ?>">
        <td class="td-label">
          <input type="text"
                 value="<?= htmlspecialchars($d['label']) ?>"
                 placeholder="add label…"
                 data-mac="<?= htmlspecialchars($d['mac']) ?>"
                 data-orig="<?= htmlspecialchars($d['label']) ?>"
                 oninput="labelChanged(this)"
                 onblur="saveLabel(this)">
          <div class="saved-flash" id="flash-<?= md5($d['mac']) ?>">✓ saved</div>
        </td>
        <td class="td-host"><?= htmlspecialchars($d['hostname'] ?: '—') ?></td>
        <td class="td-ip"><?= htmlspecialchars($d['ipv4'] ?: '—') ?></td>
        <td class="td-mac">
          <?= htmlspecialchars($d['mac']) ?>
          <?php if (str_contains($d['vendor'], 'locally administered')): ?>
          <br><span class="local-admin">random MAC</span>
          <?php endif; ?>
        </td>
        <td class="td-vendor"><?= htmlspecialchars(
            preg_replace('/\(Unknown.*?\)/', '', $d['vendor']) ?: '—'
        ) ?></td>
        <td class="td-ipv6"><?= htmlspecialchars($d['ipv6_ll'] ?: '—') ?></td>
        <td class="td-date" data-ts="<?= htmlspecialchars($d['first_seen']) ?>">
          <?php if ($d['first_seen']): ?>
          <span class="date"><?= substr($d['first_seen'], 0, 10) ?></span><br>
          <span class="time"><?= substr($d['first_seen'], 11, 8) ?></span>
          <?php else: ?>—<?php endif; ?>
        </td>
        <td class="td-date" data-ts="<?= htmlspecialchars($d['last_seen']) ?>">
          <?php if ($d['last_seen']): ?>
          <span class="date"><?= substr($d['last_seen'], 0, 10) ?></span><br>
          <span class="time"><?= substr($d['last_seen'], 11, 8) ?></span>
          <?php else: ?>—<?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<script>
// --- Action buttons -------------------------------------------------------
async function runAction(action) {
  const btn    = document.getElementById('btn-' + action);
  const output = document.getElementById('output');
  const orig   = btn.innerHTML;

  btn.classList.add('loading');
  btn.innerHTML = '<span class="spinner"></span> Running…';
  output.className = 'visible';
  output.textContent = '$ netwatch --' + action + '\n…';

  try {
    const res  = await fetch('', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=' + encodeURIComponent(action),
    });
    const data = await res.json();
    output.textContent = data.output;
    output.className   = data.ok ? 'visible' : 'visible error';

    // Reload table if scan or lookup modified the DB
    if (action === 'scan' || action === 'lookup') {
      setTimeout(() => location.reload(), 1200);
    }
  } catch (e) {
    output.textContent = 'Request failed: ' + e;
    output.className   = 'visible error';
  } finally {
    btn.classList.remove('loading');
    btn.innerHTML = orig;
  }
}

// --- Label editing --------------------------------------------------------
function labelChanged(input) {
  input.dataset.dirty = (input.value !== input.dataset.orig) ? '1' : '';
}

async function saveLabel(input) {
  if (!input.dataset.dirty) return;
  const mac   = input.dataset.mac;
  const label = input.value.trim();
  const flash = document.getElementById('flash-' + md5hex(mac));

  try {
    const res  = await fetch('', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=save_label&mac=' + encodeURIComponent(mac) + '&label=' + encodeURIComponent(label),
    });
    const data = await res.json();
    if (data.ok) {
      input.dataset.orig  = label;
      input.dataset.dirty = '';
      if (flash) {
        flash.style.display = 'block';
        setTimeout(() => flash.style.display = 'none', 1500);
      }
    }
  } catch (e) { /* silent */ }
}

// Simple MD5-like hash for flash ID (just needs to be consistent, not secure)
function md5hex(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  return Math.abs(h).toString(16);
}

// --- Sorting --------------------------------------------------------------
let sortCol = 6, sortDir = -1; // default: first_seen desc

function sortTable(col) {
  const table = document.getElementById('devtable');
  const ths   = table.querySelectorAll('thead th');
  const tbody = table.querySelector('tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));

  if (sortCol === col) {
    sortDir *= -1;
  } else {
    sortCol = col;
    sortDir = 1;
  }

  ths.forEach((th, i) => {
    th.classList.remove('sort-asc', 'sort-desc');
    if (i === col) th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
  });

  rows.sort((a, b) => {
    let av = cellValue(a, col);
    let bv = cellValue(b, col);
    // ISO date strings sort lexicographically — perfect as-is
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });

  rows.forEach(r => tbody.appendChild(r));
}

function cellValue(row, col) {
  const td = row.querySelectorAll('td')[col];
  if (!td) return '';
  // For date columns use data-ts for reliable ISO sort
  if (td.dataset.ts) return td.dataset.ts;
  // For label: use input value
  const input = td.querySelector('input');
  if (input) return input.value.toLowerCase();
  return td.textContent.trim().toLowerCase();
}

// --- Search / filter ------------------------------------------------------
function filterTable(q) {
  q = q.toLowerCase().trim();
  const rows  = document.querySelectorAll('#devtable tbody tr');
  let visible = 0;
  rows.forEach(r => {
    const match = !q || r.dataset.search.includes(q);
    r.classList.toggle('hidden', !match);
    if (match) visible++;
  });
  document.getElementById('count-badge').textContent = q ? visible + ' / <?= $device_count ?>' : '<?= $device_count ?>';
}

// Initial sort (first_seen desc already set by default header class)
sortTable(6);
</script>

</body>
</html>
