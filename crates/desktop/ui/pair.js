// Pairing window logic. Talks to the daemon through Tauri commands only.
const invoke = window.__TAURI__?.core?.invoke;

const $ = (id) => document.getElementById(id);

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

function shortId(id) {
  if (!id) return "—";
  return id.length <= 12 ? id : id.slice(0, 12) + "…";
}

function digits(code) {
  const s = String(code || "").padStart(6, "0");
  return s.slice(0, 3) + " " + s.slice(3);
}

let countdownTimer = null;
let pollTimer = null;
let knownMembers = new Set();

function stopTimers() {
  if (countdownTimer) clearInterval(countdownTimer);
  if (pollTimer) clearInterval(pollTimer);
  countdownTimer = null;
  pollTimer = null;
}

function renderMembers(membership) {
  const list = $("member-list");
  list.innerHTML = "";
  const active = membership?.active_peers || [];
  if (!active.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No paired devices";
    list.appendChild(li);
    return;
  }
  for (const m of active) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "member-name";
    name.textContent = m.device_name || "unknown";
    const meta = document.createElement("span");
    meta.className = "member-meta";
    meta.textContent = (m.relationship || "self") + " · " + shortId(m.peer_id);
    const remove = document.createElement("button");
    remove.className = "ghost small";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      remove.disabled = true;
      try {
        await invoke("remove_member", { peerId: m.peer_id });
        await refresh();
      } catch (err) {
        setStatus($("show-status"), String(err), "error");
        remove.disabled = false;
      }
    });
    li.append(name, meta, remove);
    list.appendChild(li);
  }
}

async function refresh() {
  try {
    const snap = await invoke("daemon_snapshot");
    const status = snap?.status || {};
    const membership = snap?.membership || {};
    $("show-device").textContent = status.device_name || "—";
    $("show-node").textContent = status.peer_id || "—";
    renderMembers(membership);
    const active = membership.active_peers || [];
    const fresh = active.filter((m) => !knownMembers.has(m.peer_id));
    knownMembers = new Set(active.map((m) => m.peer_id));
    if (fresh.length && $("code-box").classList.contains("hidden") === false) {
      const who = fresh[0].device_name || shortId(fresh[0].peer_id);
      setStatus($("show-status"), "Paired with " + who + "!", "ok");
      stopTimers();
    }
    return snap;
  } catch (err) {
    setStatus($("show-status"), String(err), "error");
    return null;
  }
}

function switchTab(which) {
  const show = which === "show";
  $("tab-show").classList.toggle("active", show);
  $("tab-connect").classList.toggle("active", !show);
  $("tab-show").setAttribute("aria-selected", String(show));
  $("tab-connect").setAttribute("aria-selected", String(!show));
  $("panel-show").classList.toggle("hidden", !show);
  $("panel-connect").classList.toggle("hidden", show);
}

$("tab-show").addEventListener("click", () => switchTab("show"));
$("tab-connect").addEventListener("click", () => switchTab("connect"));

$("copy-node").addEventListener("click", async () => {
  try {
    const id = await invoke("copy_node_id_command");
    setStatus($("show-status"), "Copied Node ID " + shortId(id), "ok");
  } catch (err) {
    setStatus($("show-status"), String(err), "error");
  }
});

$("gen-code").addEventListener("click", async () => {
  stopTimers();
  try {
    const res = await invoke("generate_pair_code");
    const code = res?.code || "";
    const ttl = res?.expires_in_secs || 300;
    $("code-box").classList.remove("hidden");
    $("code-digits").textContent = digits(code);
    let left = ttl;
    $("code-countdown").textContent = left + "s";
    setStatus($("show-status"), "Waiting for the other device to connect…", "");
    countdownTimer = setInterval(() => {
      left -= 1;
      $("code-countdown").textContent = Math.max(left, 0) + "s";
      if (left <= 0) {
        stopTimers();
        $("code-box").classList.add("hidden");
        setStatus($("show-status"), "Code expired — generate a new one.", "error");
      }
    }, 1000);
    pollTimer = setInterval(refresh, 2000);
  } catch (err) {
    setStatus($("show-status"), String(err), "error");
  }
});

$("pair-btn").addEventListener("click", async () => {
  const peerId = $("peer-id").value.trim();
  const code = $("peer-code").value.trim();
  const relayUrl = $("relay-url").value.trim();
  const relationship = $("relationship").value;
  if (!peerId) {
    setStatus($("connect-status"), "Peer Node ID is required.", "error");
    return;
  }
  if (!/^\d{6}$/.test(code)) {
    setStatus($("connect-status"), "Pairing code must be 6 digits.", "error");
    return;
  }
  $("pair-btn").disabled = true;
  setStatus($("connect-status"), "Pairing…", "");
  try {
    const res = await invoke("pair_with_peer", {
      peerId,
      code,
      relayUrl: relayUrl || null,
      relationship,
    });
    const name = res?.peer_device_name || shortId(peerId);
    setStatus($("connect-status"), "Paired with " + name + "!", "ok");
    await refresh();
  } catch (err) {
    setStatus($("connect-status"), String(err), "error");
  } finally {
    $("pair-btn").disabled = false;
  }
});

refresh();
