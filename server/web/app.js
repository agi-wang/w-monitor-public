"use strict";
const locale = window.WM_I18N.locale;
const t = (message, values = {}) => (window.WM_I18N.messages[message] ?? message).replace(/\{(\w+)\}/g, (match, key) => values[key] ?? match);
const $ = (id) => document.getElementById(id);
const publicSlug = /^\/status\/(wm1_[A-Za-z0-9_-]{40,320})$/.exec(location.pathname)?.[1];
const responses = new Map();
const historyViews = new Map();
let publicVisibility = { cpu: false, memory: false, disk: false, network: false, history: false };
let historyRequest = 0, historyLoading = false, historyLoadedAt = 0, historyLastSeen;
let session, devices = [], pages = [], bootstrap = "", editingPage = null;
let lastView, currentPage = 0, pollMs = 5000;
let events, poll, refreshing = false, refreshAgain = false, generation = 0, allowEvents = false;
let settingsDevice, settingsPoll, settingsSaving = false, settingsSupported = false;

const browserKeys = new Map();
let autoRestoreAllowed = true;
function bytesHex(bytes) { return [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, "0")).join(""); }
function hexBytes(value) { return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16)); }
function urlBytes(value) { return Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), character => character.charCodeAt(0)); }
async function clientKey(recovery) {
  let pair;
  if (recovery) {
    if (!/^wmr2_[a-f0-9]{64}$/.test(recovery)) throw new Error(t("恢复口令无效"));
    const der = hexBytes("302e020100300506032b657004220420" + recovery.slice(5));
    pair = { privateKey: await crypto.subtle.importKey("pkcs8", der, "Ed25519", true, ["sign"]) };
  } else pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const key = { public_key: bytesHex(urlBytes(jwk.x)), privateKey: await crypto.subtle.importKey("jwk", jwk, "Ed25519", false, ["sign"]), recovery: "wmr2_" + bytesHex(urlBytes(jwk.d)) };
  return key;
}
async function keyStore(mode, callback) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("w-monitor-public-keys", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("owners", { keyPath: "public_key" });
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  try { return await new Promise((resolve, reject) => {
    const transaction = db.transaction("owners", mode), request = callback(transaction.objectStore("owners"));
    let result; request.onsuccess = () => { result = request.result; };
    transaction.oncomplete = () => resolve(result); transaction.onerror = () => reject(transaction.error); transaction.onabort = () => reject(transaction.error);
  }); } finally { db.close(); }
}
async function rememberKey(key) {
  autoRestoreAllowed = true;
  const saved = { public_key: key.public_key, privateKey: key.privateKey };
  browserKeys.set(key.public_key, saved);
  try { await keyStore("readwrite", store => store.put(saved)); localStorage.setItem("wm-active-public-key", key.public_key); }
  catch { notice(t("无法在此浏览器保存密钥，请务必保存恢复口令。")); }
}
async function savedBrowserKey() {
  try {
    const publicKey = localStorage.getItem("wm-active-public-key");
    return publicKey ? browserKeys.get(publicKey) ?? await keyStore("readonly", store => store.get(publicKey)) : undefined;
  } catch { return undefined; }
}
async function keyProof(key, purpose) {
  const data = await api("/api/keys/challenge", { purpose, public_key: key.public_key });
  if (typeof data.challenge !== "string" || !/^wm1_[A-Za-z0-9_-]{40,2048}$/.test(data.challenge)) throw new Error(t("无效密钥验证"));
  const message = new TextEncoder().encode(`wm-space-v1\n${location.origin}\n${purpose}\n${data.challenge}`);
  return { public_key: key.public_key, challenge: data.challenge, signature: bytesHex(await crypto.subtle.sign("Ed25519", key.privateKey, message)) };
}
async function restoreWithKey(key) {
  await api("/api/keys/restore", { key_proof: await keyProof(key, "restore") });
  session = await api("/api/session"); await rememberKey(key);
}
async function restoreSpace(recovery) {
  if (recovery.startsWith("wmr2_")) { await restoreWithKey(await clientKey(recovery)); return; }
  if (!/^wmr_[a-f0-9]{64}$/.test(recovery)) throw new Error(t("恢复口令无效"));
  await api("/api/spaces/restore", { recovery }); session = await api("/api/session");
  if (!session.key_public) {
    const key = await clientKey();
    await api("/api/keys/bind", { key_proof: await keyProof(key, "bind") });
    await rememberKey(key); return key.recovery;
  }
}
async function rotateSpaceKey(path, purpose) {
  const key = await clientKey();
  const data = await api(path, { key_proof: await keyProof(key, purpose) });
  if (data.key_public !== key.public_key) throw new Error(t("无效密钥验证"));
  await rememberKey(key); bootstrap = data.bootstrap_key; await loadSession(); showRecovery(key.recovery, true);
}

function notice(message = "") { $("notice").textContent = message; $("notice").hidden = !message; }
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function button(text, action, className = "button") {
  const element = node("button", text, className);
  element.type = "button";
  element.addEventListener("click", () => run(action));
  return element;
}
async function run(action) {
  try { await action(); } catch (error) { notice(error.message || t("操作失败，请重试")); }
}
async function api(path, value) {
  const previous = value === undefined ? responses.get(path) : undefined;
  const response = await fetch(path, {
    method: value === undefined ? "GET" : "POST", credentials: publicSlug ? "omit" : "same-origin",
    cache: "no-store", redirect: "error",
    headers: { ...(previous ? { "If-None-Match": previous.etag } : {}), ...(!publicSlug && session?.manage_token ? { "X-Operation-Token": session.manage_token } : {}), ...(value === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": session?.csrf ?? "" }) },
    body: value === undefined ? undefined : JSON.stringify(value),
  });
  if (response.status === 304 && previous) return previous.data;
  const data = await response.json();
  if (!response.ok) responses.delete(path);
  if (!response.ok) { const error = new Error(data.error || t("请求失败（{status}）", { status: response.status })); error.status = response.status; throw error; }
  const etag = response.headers.get("ETag");
  if (etag) { responses.set(path, { etag, data }); if (responses.size > 8) responses.delete(responses.keys().next().value); }
  return data;
}
function empty(target, title, description) {
  const box = node("div", undefined, "empty");
  box.append(node("strong", title), node("span", description));
  target.replaceChildren(box);
}
function timeLabel(timestamp) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString(locale, { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : t("尚无上报");
}
function networkRate(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  const units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]; let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value) + " " + units[unit];
}
function drawDevices(target, rows, publicView = false) {
  if (!rows.length) { empty(target, publicView ? t("暂无公开设备") : t("等待第一台设备"), publicView ? t("发布者尚未选择设备，或设备已被移除。") : t("点击“接入设备”，在主机上运行 Lite Agent。首次上报后设备会出现在这里。")); return; }
  const showNetwork = !publicView || publicVisibility.network, showDetails = !publicView || publicVisibility.history;
  const table = node("table", undefined, "device-table");
  const head = node("thead"), headRow = node("tr");
  for (const label of [t("设备 / 最近上报"), t("状态"), ...[["CPU", "cpu"], [t("内存"), "memory"], [t("磁盘"), "disk"]].filter(([, key]) => !publicView || publicVisibility[key]).map(([label]) => label), ...(showNetwork ? [t("默认出口")] : []), ...(showDetails ? [t("设备详情")] : [])]) headRow.append(node("th", label));
  head.append(headRow); table.append(head);
  const body = node("tbody");
  for (const device of rows) {
    const row = node("tr"), name = node("td");
    const openDetails = () => showReport(device, publicView);
    name.append(showDetails ? button(device.name + " ↗", openDetails, "device-name device-link") : node("div", device.name, "device-name"), node("div", timeLabel(device.last_seen), "last-seen"));
    const state = node("td", undefined, "status-cell");
    const badge = node("span", undefined, `status${device.online ? "" : " offline"}`);
    badge.append(node("span", undefined, "dot"), document.createTextNode(device.online === true ? t("在线") : device.online === false ? t("离线") : t("暂无数据"))); state.append(badge);
    row.append(name, state);
    for (const [label, key] of [["CPU", "cpu_percent"], [t("内存"), "memory_percent"], [t("磁盘"), "disk_percent"]]) {
      if (publicView && !publicVisibility[key.replace("_percent", "")]) continue;
      const cell = node("td", undefined, "metric-cell"); cell.dataset.label = label;
      const value = device[key], valid = typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
      const metric = node("span", valid ? `${value.toFixed(1)}%` : "—", `metric${valid && value >= 85 ? " high" : ""}`);
      const bar = node("span", undefined, "bar"), fill = node("i");
      fill.style.width = `${valid ? value : 0}%`; bar.append(fill); metric.append(bar); cell.append(metric);
      const history = historyViews.get(device.viewKey + ":15m");
      if (key === "cpu_percent" && history?.points.length > 1) cell.append(metricPlot(history.points, [key], [label], true, history));
      row.append(cell);
    }
    if (showNetwork) {
    const traffic = node("td", undefined, "metric-cell"); traffic.dataset.label = t("默认出口");
    traffic.textContent = `↓ ${networkRate(device.network_rx_bps)} · ↑ ${networkRate(device.network_tx_bps)}`; row.append(traffic);
    }
    if (showDetails) {
    const cell = node("td", undefined, "actions-cell"), actions = node("div", undefined, "row-actions");
    actions.append(button(t("查看详情") + " →", openDetails, "details-button"));
    if (!publicView) {
      actions.append(button(t("可用性监测"), () => showAvailability(device), ""), button(t("Agent 配置"), () => showAgentSettings(device), ""), button(t("移除接入"), async () => {
        if (!confirm(t("移除此设备的上报凭据和已存数据？这不会卸载或操作主机上的 Agent。"))) return;
        await api("/api/devices/revoke", { id: device.id }); await refresh();
      }, "danger"));
    }
    cell.append(actions); row.append(cell);
    }
    body.append(row);
  }
  table.append(body); target.replaceChildren(table);
}
function drawPaging(target, data) {
  if (data.total <= data.page_size) return;
  const pager = node("div", undefined, "pagination");
  const move = async (number) => { generation += 1; currentPage = number; lastView = undefined; await refresh(); };
  const previous = button(t("上一页"), () => move(Math.max(0, currentPage - 1)));
  const next = button(t("下一页"), () => move(currentPage + 1));
  previous.disabled = currentPage === 0; next.disabled = (currentPage + 1) * data.page_size >= data.total;
  pager.append(previous, node("span", t("第 {page} / {pages} 页 · 共 {total} 台设备", { page: currentPage + 1, pages: Math.ceil(data.total / data.page_size), total: data.total })), next);
  target.append(pager);
}
function drawPages() {
  $("page-count").textContent = pages.length;
  if (!pages.length) { empty($("page-list"), t("创建你的第一个分享页"), t("例如 Page One、Page Two。每一页都可以选择不同设备，并单独停用。")); return; }
  const list = document.createDocumentFragment();
  for (const page of pages) {
    const card = node("article", undefined, "page-card"), info = node("div"), actions = node("div", undefined, "actions");
    info.append(node("h3", page.title), node("p", t("{state} · {count} 台所选设备", { state: page.enabled ? t("公开访问已开启") : t("已停用"), count: page.selection.length })));
    if (page.enabled) {
      const link = node("a", t("打开页面 ↗"), "button"); link.href = `/status/${page.slug}`; link.target = "_blank"; link.rel = "noopener noreferrer"; actions.append(link);
      actions.append(button(t("复制链接"), () => copy(location.origin + `/status/${page.slug}`)));
    }
    actions.append(button(t("编辑"), () => openPage(page)), button(page.enabled ? t("停用") : t("启用"), async () => {
      const available = new Set((await api("/api/device-options")).devices.map((device) => device.id));
      await api("/api/pages/update", { id: page.id, title: page.title, enabled: !page.enabled, ...Object.fromEntries(["cpu", "memory", "disk", "network", "history"].map(key => ["show_" + key, page["show_" + key]])), device_ids: page.selection.filter((id) => available.has(id)) }); await refreshPages();
    }), button(t("更换链接"), async () => {
      if (!confirm(t("更换后，原公开链接会立即失效。"))) return;
      await api("/api/pages/rotate", { id: page.id }); await refreshPages();
    }), button(t("删除"), async () => {
      if (!confirm(t("删除这个分享页并撤销它的公开链接？"))) return;
      await api("/api/pages/delete", { id: page.id }); await refreshPages();
    }, "quiet"));
    card.append(info, actions); list.append(card);
  }
  $("page-list").replaceChildren(list);
}
async function refreshPages() { pages = (await api("/api/pages")).pages; drawPages(); }
async function refreshEmail() {
  const data = await api("/api/email");
  $("bound-email").textContent = data.email || t("尚未绑定邮箱");
  $("email-enabled").checked = data.enabled;
  $("email-enabled").disabled = !data.email;
  $("bind-email").disabled = !data.can_bind;
  $("save-email").disabled = !data.email;
  $("unbind-email").hidden = !data.email;
  $("email-help").textContent = !data.delivery_available ? t("此部署的通知发送服务尚未就绪。") : data.can_bind ? t("可绑定当前登录账号中已验证的邮箱。") : t("请先正常登录并在账号中验证邮箱，再返回绑定。");
}
async function refresh() {
  if (refreshing) { refreshAgain = true; return; }
  refreshing = true; const current = generation;
  try {
    const data = await api((publicSlug ? `/api/public/status/${publicSlug}` : "/api/devices") + `?page=${currentPage}`);
    if (current !== generation) return;
    if (data.page > 0 && data.page * data.page_size >= data.total) { currentPage = Math.max(0, Math.ceil(data.total / data.page_size) - 1); refreshAgain = true; return; }
    allowEvents = data.realtime === true;
    notice(data.data_available === false ? t("实时数据暂时不可用，已隐藏资源读数。空间与设备接入信息仍已保存。") : "");
    if (publicSlug) {
      const visibility = Object.fromEntries(["cpu", "memory", "disk", "network", "history"].map(key => [key, data.visibility?.[key] === true]));
      if (Object.keys(visibility).some(key => visibility[key] !== publicVisibility[key])) {
        historyRequest += 1; historyLoading = false; historyViews.clear();
        if ($("report-dialog").open) $("report-dialog").close();
      }
      publicVisibility = visibility;
      $("public-details-hint").textContent = t(visibility.history ? "点击设备名称或“查看详情”，查看已公开的历史趋势。" : "此页面仅展示发布者选择公开的当前指标。");
    }
    if (data === lastView) { if (reportDevice) void loadHistory(); return; }
    lastView = data;
    const rows = data.devices.map((device, index) => ({ ...device, viewKey: publicSlug ? device.history_key ?? JSON.stringify([currentPage, index, device.name]) : device.id }));
    if (Number.isInteger(data.refresh_ms) && data.refresh_ms >= 500 && data.refresh_ms <= 60000 && pollMs !== data.refresh_ms) {
      pollMs = data.refresh_ms; startRealtime();
    }
    if (publicSlug) { $("public-title").textContent = data.title; drawDevices($("public-list"), rows, true); }
    else { devices = rows; $("device-count").textContent = data.total; drawDevices($("device-list"), devices); }
    if (reportDevice) {
      const selected = rows.find(device => device.viewKey === reportDevice.viewKey);
      if (selected) { reportDevice = selected; updateReportLiveMetrics(selected); void loadHistory(); }
      else $("report-dialog").close();
    }
    drawPaging($(publicSlug ? "public-list" : "device-list"), data);
  } catch (error) {
    if (current !== generation) return;
    notice(error.message); lastView = undefined;
    // Never leave a revoked public snapshot, or a failed private read, visible.
    empty($(publicSlug ? "public-list" : "device-list"), t("暂时无法读取"), t("请刷新页面；链接可能已停用，或当前会话已经失效。"));
    historyViews.clear();
    if (publicSlug && $("report-dialog").open) $("report-dialog").close();
    if (!publicSlug) {
      devices = [];
      if (reportDevice) updateReportLiveMetrics();
      if ([401, 403].includes(error.status)) {
        if ($("report-dialog").open) $("report-dialog").close();
        if ($("device-settings-dialog").open) $("device-settings-dialog").close();
      }
    }
  } finally {
    refreshing = false;
    if (refreshAgain) { refreshAgain = false; void refresh(); }
  }
}
function connection(text, live = false) {
  const element = $(publicSlug ? "public-connection" : "connection");
  element.textContent = text; element.classList.toggle("live", live);
}
function stopRealtime() { events?.close(); events = undefined; clearInterval(poll); poll = undefined; }
function startRealtime() {
  stopRealtime();
  if (document.hidden || (!publicSlug && !session?.space)) return;
  connection(t("定时刷新"));
  poll = setInterval(() => void refresh(), pollMs);
  if (!window.EventSource || !allowEvents) return;
  let errors = 0, firstEvent = true; const started = performance.now();
  const source = new EventSource(publicSlug ? `/events/status/${publicSlug}` : "/events/space"); events = source;
  source.addEventListener("changed", () => {
    if (events !== source) return;
    if (firstEvent && performance.now() - started > 4000) {
      source.close(); events = undefined; connection(t("定时刷新")); void refresh(); return;
    }
    firstEvent = false; errors = 0;
    clearInterval(poll); poll = setInterval(() => void refresh(), 30000);
    connection(t("实时更新"), true); void refresh();
  });
  source.addEventListener("revoked", () => { stopRealtime(); connection(t("访问已失效")); void refresh(); });
  source.onerror = () => {
    if (events !== source) return;
    connection(t("定时刷新"));
    clearInterval(poll); poll = setInterval(() => void refresh(), pollMs);
    if (++errors >= 2) { source.close(); events = undefined; }
  };
}
async function loadSession() {
  if ($("uptime-dialog").open) $("uptime-dialog").close();
  generation += 1; stopRealtime(); responses.clear(); lastView = undefined; currentPage = 0;
  historyViews.clear(); if ($("report-dialog").open) $("report-dialog").close();
  session = await api("/api/session");
  const fragment = new URLSearchParams(location.hash.slice(1)).get("recovery");
  if (fragment) {
    history.replaceState(null, "", location.pathname + location.search);
    try { await restoreSpace(fragment); session = await api("/api/session"); } catch (error) { notice(error.message); }
  } else if (autoRestoreAllowed && !session.space && !session.login.authenticated) {
    const saved = await savedBrowserKey();
    if (saved) {
      try { await restoreWithKey(saved); } catch (error) { autoRestoreAllowed = false; notice(error.message); session = await api("/api/session"); }
    }
  }

  $("login").hidden = !session.login.available || session.login.authenticated;
  $("logout").hidden = !session.space && !session.login.authenticated;
  $("claim").hidden = !session.space || session.space.claimed || !session.login.authenticated;
  $("welcome").hidden = Boolean(session.space); $("dashboard").hidden = !session.space;
  $("loading").hidden = true;
  if (session.space) {
    if (session.key_public) {
      try { const key = browserKeys.get(session.key_public) ?? await keyStore("readonly", store => store.get(session.key_public)); if (key) await rememberKey(key); } catch {}
    }
    history.replaceState(null, "", "/manage/" + session.manage_token);
    $("space-title").textContent = session.space.title;
    $("space-kind").textContent = session.space.claimed ? t("已领用的监控空间") : t("匿名监控空间");
    const owned = session.spaces.some((space) => space.id === session.space.id) ? session.spaces : [session.space, ...session.spaces];
    $("space-select").replaceChildren(...owned.map((space) => { const option = node("option", space.title); option.value = space.id; option.selected = space.id === session.space.id; return option; }));
    $("space-select").disabled = !session.login.authenticated || owned.length < 2;
    await refresh(); await refreshPages(); await refreshEmail(); startRealtime();
  } else { history.replaceState(null, "", "/"); }
}
async function newSpace() {
  const title = prompt(t("为监控空间起一个名字"), t("我的监控空间")); if (!title?.trim()) return;
  const key = await clientKey(); await rememberKey(key);
  const result = await api("/api/spaces/create", { title: title.trim(), key_proof: await keyProof(key, "create") });
  if (result.key_public !== key.public_key) throw new Error(t("无效密钥验证"));
  bootstrap = result.bootstrap_key; await loadSession(); showRecovery(key.recovery);
}
function showRecovery(key, rotated = false) {
  $("recovery-key").value = key;
  $("recovery-explanation").textContent = rotated ? t("旧恢复口令与接入凭据已失效，其他会话已退出；已注册设备继续上报。请保存新口令，只显示这一次。") : t("只显示这一次。保存后，你可以跨浏览器找回这个空间。");
  $("recovery-dialog").showModal();
}
function shellQuote(value) { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }
function agentOptions(prefix) {
  return (!$(`${prefix}-realtime`).checked ? " --no-realtime" : "") + (!$(`${prefix}-compression`).checked ? " --no-compression" : "") + ($(`${prefix}-probes`).checked ? " --enable-service-probes" : "");
}
function installCommand() {
  if (!bootstrap) return "";
  return `curl -fsSL --proto '=https' --max-time 30 'https://github.com/agi-wang/w-monitor-public/releases/latest/download/install.sh' | bash -s -- --endpoint ${shellQuote(session.ingest_url)} --key ${shellQuote(bootstrap)}${agentOptions("install")}`;
}
function updateInstallCommand() {
  $("install-command").value = installCommand();
  $("copy-install").textContent = t(bootstrap ? "复制命令" : "生成并复制命令");
}
function updateQuickCommand() {
  $("quick-command").value = `curl -fsSL --proto '=https' --max-time 30 'https://github.com/agi-wang/w-monitor-public/releases/latest/download/install.sh' | bash -s -- --public ${shellQuote(location.origin)} --language ${shellQuote(locale)}${agentOptions("quick")}`;
}
async function copy(value) {
  try { await navigator.clipboard.writeText(value); notice(t("已复制。")); }
  catch { throw new Error(t("自动复制未完成，请选中文本手动复制。")); }
}
async function openPage(page = null) {
  const options = (await api("/api/device-options")).devices;
  editingPage = page; $("page-dialog-title").textContent = page ? t("编辑分享页") : t("新建分享页");
  $("page-title").value = page?.title ?? ""; $("page-enabled").checked = page ? Boolean(page.enabled) : true;
  for (const key of ["cpu", "memory", "disk", "network", "history"]) $("page-show-" + key).checked = page ? page["show_" + key] === true : ["cpu", "memory", "disk"].includes(key);
  $("page-devices").replaceChildren(...options.map((device) => {
    const label = node("label"), input = node("input"); input.type = "checkbox"; input.value = device.id; input.checked = Boolean(page?.selection.includes(device.id));
    label.append(input, document.createTextNode(device.name)); return label;
  }));
  if (!options.length) $("page-devices").append(node("p", t("尚无设备，可以先保存页面，接入设备后再选择。"), "subtle"));
  $("page-dialog").showModal();
}
const reportTitles = new Map(Object.entries({ system: "系统信息", cpu: "CPU 与负载", memory: "内存与交换", disk: "磁盘与挂载", disk_io: "磁盘 I/O", process: "进程", network: "网络接口", connections: "网络连接", traffic_flows: "流量明细", sensor: "温度与传感器", mount_health: "挂载健康", gpu: "GPU", docker: "容器", security_posture: "安全检查", login_accounts: "登录与账号", diting_audit: "审计摘要", web_hosts: "网站与证书", project_status: "服务与项目", software_inventory: "软件清单", security_advisories: "安全公告", ping: "延迟探测", traceroute: "网络路径", easytier: "EasyTier", cache_scan: "缓存扫描", vps_pressure: "主机负载", transport_runtime: "上报链路", runtime_access: "采集权限" }));
const reportLabels = new Map(Object.entries({ accounting_scope: "流量统计口径", accounting_version: "统计口径版本", default_route_interfaces: "默认出口接口", traffic_groups: "接口分类观测", traffic_class: "接口分类", egress: "默认出口", lan: "其他局域接口", loopback: "回环", container: "容器与网桥", tunnel: "隧道", unknown: "未分类", received_bytes_per_sec: "下行速率", transmitted_bytes_per_sec: "上行速率", received_bytes: "累计接收", transmitted_bytes: "累计发送", interface_count: "接口数量", hostname: "主机名称", os_name: "操作系统", os_version: "系统版本", kernel_version: "内核版本", architecture: "架构", uptime_seconds: "运行时长", uptime_secs: "运行时长", cpu_count: "CPU 核心", total_memory_bytes: "物理内存", usage_percent: "使用率", total_bytes: "总容量", used_bytes: "已用容量", available_bytes: "可用容量", swap_total_bytes: "交换区容量", swap_used_bytes: "已用交换区", swap_usage_percent: "交换区使用率", cores: "核心数", per_core: "每核心指标", core: "核心", brand: "型号", frequency_mhz: "频率", load_avg: "平均负载", one: "1 分钟", five: "5 分钟", fifteen: "15 分钟", disks: "磁盘列表", mount_point: "挂载点", file_system: "文件系统", processes: "进程列表", pid: "PID", name: "名称", cpu_usage: "CPU 使用率", memory_bytes: "内存占用", containers: "容器列表", status: "状态", available: "可用", reason: "原因", count: "数量", interfaces: "接口列表", address: "地址", local_addr: "本地地址", remote_addr: "远端地址", port: "端口", findings: "检查结果", severity: "级别", message: "详情", data: "数据", capabilities: "能力", agent_version: "Agent 版本", report_seq: "上报序号", expected_interval_ms: "上报间隔", timestamp: "采集时间", version: "协议版本", agent_id: "设备标识", os: "系统", arch: "架构", report_interval_ms: "完整上报间隔" }));
let fullReport, reportDevice, reportCollector = "";
async function loadHistory(force = false) {
  if (!reportDevice || historyLoading || (publicSlug && !publicVisibility.history)) return;
  const selected = reportDevice, range = $("report-range").value, key = selected.viewKey + ":" + range;
  const previous = historyViews.get(key), refreshMs = previous?.refresh_ms ?? 3000;
  const changed = (previous?.resolution_seconds ?? 3) < 60 && historyLastSeen !== selected.last_seen;
  if (!force && !changed && Date.now() - historyLoadedAt < refreshMs) return;
  const request = ++historyRequest, ownerGeneration = generation;
  historyLoading = true;
  try {
    const path = publicSlug ? `/api/public/status/${publicSlug}/history?ref=${encodeURIComponent(selected.history_ref)}&range=${range}` : `/api/devices/${selected.id}/history?range=${range}`;
    const data = await api(path);
    if (request !== historyRequest || generation !== ownerGeneration || reportDevice?.viewKey !== selected.viewKey || $("report-range").value !== range) return;
    const expected = ["time", ...["cpu_percent", "memory_percent", "disk_percent", "network_rx_bps", "network_tx_bps"].filter(key => !publicSlug || publicVisibility[key.startsWith("network_") ? "network" : key.replace("_percent", "")])];
    if (JSON.stringify(data.columns) !== JSON.stringify(expected) || !Array.isArray(data.points) || data.points.length > 720 || !Number.isFinite(data.from) || !Number.isFinite(data.to) || data.to <= data.from || !Number.isInteger(data.resolution_seconds) || data.resolution_seconds < 1) throw new Error(t("历史数据格式无效"));
    const points = data.points.map(row => {
      if (!Array.isArray(row) || row.length !== expected.length || !Number.isFinite(row[0]) || row.slice(1).some(value => value !== null && (typeof value !== "number" || !Number.isFinite(value) || value < 0))) throw new Error(t("历史数据格式无效"));
      return Object.fromEntries(expected.map((field, index) => [field, row[index]]));
    });
    historyViews.delete(key); historyViews.set(key, { ...data, points });
    while (historyViews.size > 16) historyViews.delete(historyViews.keys().next().value);
    historyLoadedAt = Date.now(); historyLastSeen = selected.last_seen; drawHistory();
  } catch (error) {
    if (request !== historyRequest || reportDevice?.viewKey !== selected.viewKey) return;
    historyViews.delete(key); historyLoadedAt = Date.now(); historyLastSeen = selected.last_seen; drawHistory();
    $("report-trend-note").textContent = error.message;
    if (publicSlug && [403, 404].includes(error.status)) $("report-dialog").close();
  } finally {
    if (request === historyRequest) historyLoading = false;
  }
}
function drawHistory() {
  const history = historyViews.get(reportDevice?.viewKey + ":" + $("report-range").value), points = history?.points ?? [], charts = $("report-charts"); charts.replaceChildren();
  for (const [title, keys, labels] of [["CPU", ["cpu_percent"], ["CPU"]], [t("内存"), ["memory_percent"], [t("内存")]], [t("磁盘"), ["disk_percent"], [t("磁盘")]], [t("默认出口"), ["network_rx_bps", "network_tx_bps"], [t("下载"), t("上传")]]]) {
    if (publicSlug && !publicVisibility[keys[0].startsWith("network_") ? "network" : keys[0].replace("_percent", "")]) continue;
    const card = node("section", undefined, "metric-chart"), heading = node("div", undefined, "chart-heading"); heading.append(node("h3", title));
    if (keys.length > 1) { const legend = node("span", undefined, "chart-legend"); labels.forEach((label, index) => legend.append(node("span", label, `chart-series-${index}`))); heading.append(legend); }
    card.append(heading, metricPlot(points, keys, labels, false, history)); charts.append(card);
  }
  if (!history) { $("report-trend-note").textContent = t("正在读取服务端历史…"); return; }
  const step = history.resolution_seconds, resolution = step < 60 ? t("{count} 秒均值", { count: step }) : step < 3600 ? t("{count} 分钟均值", { count: step / 60 }) : t("{count} 小时均值", { count: step / 3600 });
  $("report-trend-note").textContent = (points.length ? t("服务端历史 · {resolution} · {count} 个采样点", { resolution, count: points.length }) : t("该时段暂无历史采样")) + " · " + t("Redis 最长保留 {days} 天；刷新页面或换浏览器可继续查看，缺失采样留空。", { days: new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(history.max_retention_seconds / 86400) });
}
function metricPlot(points, keys, labels, small = false, history) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const width = small ? 120 : window.innerWidth <= 760 ? Math.max(200, window.innerWidth - 108) : 460, height = small ? 28 : 172, left = small ? 1 : 64, right = width - 8, top = 10, bottom = height - (small ? 2 : 30);
  const element = (name, attributes, text) => { const item = document.createElementNS(svg.namespaceURI, name); for (const [key, value] of Object.entries(attributes)) item.setAttribute(key, String(value)); if (text !== undefined) item.textContent = text; svg.append(item); return item; };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`); svg.setAttribute("class", small ? "metric-spark" : "metric-plot"); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", labels.join(" / ") + " · " + t("历史趋势")); element("title", {}, labels.join(" / ") + " · " + t("历史趋势"));
  const end = history?.to ?? Date.now() / 1000, start = history?.from ?? end - 900;
  let maximum = keys[0].endsWith("percent") ? 100 : 1;
  if (!keys[0].endsWith("percent")) for (const point of points) for (const key of keys) if (point[key] !== null) maximum = Math.max(maximum, point[key] * 1.15);
  const x = time => left + (time - start) / (end - start) * (right - left), y = value => bottom - Math.min(maximum, value) / maximum * (bottom - top);
  if (!small) {
    for (const fraction of [0, 0.5, 1]) {
      const level = y(maximum * fraction); element("line", { x1: left, x2: right, y1: level, y2: level, class: "chart-grid" });
      element("text", { x: left - 8, y: level + 3, "text-anchor": "end", class: "chart-axis" }, keys[0].endsWith("percent") ? `${maximum * fraction}%` : keys[0] === "latency_ms" ? `${(maximum * fraction).toFixed(0)} ms` : networkRate(maximum * fraction));
    }
    const clock = time => new Date(time * 1000).toLocaleString(locale, { ...(end - start > 86400 ? { month: "2-digit", day: "2-digit" } : {}), hour12: false, hour: "2-digit", minute: "2-digit", ...((history?.resolution_seconds ?? 3) < 60 ? { second: "2-digit" } : {}) });
    element("text", { x: left, y: height - 6, class: "chart-axis" }, clock(start)); element("text", { x: right, y: height - 6, "text-anchor": "end", class: "chart-axis" }, clock(end));
  }
  keys.forEach((key, index) => {
    let path = "", previous;
    for (const point of points) {
      const value = point[key]; if (value === null) { previous = undefined; continue; }
      path += `${previous && point.time - previous.time <= Math.max(15, (history?.resolution_seconds ?? 3) * 1.6) ? "L" : "M"}${x(point.time).toFixed(1)},${y(value).toFixed(1)} `; previous = point;
    }
    element("path", { d: path, fill: "none", class: `chart-line chart-series-${index}`, "stroke-width": small ? 1.5 : 2, "vector-effect": "non-scaling-stroke" });
    const latest = points.at(-1); if (latest?.[key] !== null && latest?.[key] !== undefined) element("circle", { cx: x(latest.time), cy: y(latest[key]), r: small ? 1.5 : 3, class: `chart-point chart-series-${index}` });
  });
  return svg;
}
function reportLabel(key) { return t(reportLabels.get(key) ?? reportTitles.get(key) ?? key.replaceAll("_", " ")); }
function reportScalar(value, key = "") {
  if (key === "accounting_scope") return t(value === "default_route_interfaces" ? "默认出口接口" : "出口未识别");
  if (key === "traffic_class") return t(({egress:"默认出口",lan:"其他局域接口",loopback:"回环",container:"容器与网桥",tunnel:"隧道",unknown:"未分类"})[value] ?? value);
  if (value === null || value === undefined) return t("未提供");
  if (typeof value === "boolean") return t(value ? "是" : "否");
  if (typeof value === "number") {
    if (/bytes(?:_per_sec)?$/.test(key) && value >= 0) {
      const units = ["B", "KiB", "MiB", "GiB", "TiB"]; let number = value, unit = 0;
      while (number >= 1024 && unit < units.length - 1) { number /= 1024; unit += 1; }
      return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(number)} ${units[unit]}${key.endsWith("_per_sec") ? "/s" : ""}`;
    }
    return new Intl.NumberFormat(locale, { maximumFractionDigits: 3 }).format(value) + (key.endsWith("percent") || key === "cpu_usage" ? "%" : key.endsWith("_mhz") ? " MHz" : key.endsWith("_ms") ? " ms" : key.endsWith("_seconds") || key.endsWith("_secs") ? " s" : "");
  }
  return typeof value === "string" && value === "insufficient_permissions" ? t("权限不足") : String(value);
}
function reportMetric(value, key = "") {
  const box = node("span", undefined, "report-value"), text = node("span", reportScalar(value, key));
  box.append(text);
  if (typeof value === "number") {
    text.title = String(value);
    if ((key.endsWith("percent") || key === "cpu_usage") && value >= 0 && value <= 100) {
      const meter = node("span", undefined, "report-meter"), fill = node("i");
      meter.setAttribute("role", "meter"); meter.setAttribute("aria-label", reportLabel(key)); meter.setAttribute("aria-valuemin", "0"); meter.setAttribute("aria-valuemax", "100"); meter.setAttribute("aria-valuenow", String(value));
      fill.style.width = value + "%"; if (value >= 85) meter.classList.add("high"); meter.append(fill); box.append(meter);
    }
  } else if (typeof value === "boolean" || /(?:^|_)(?:status|state|severity|health|available)$/.test(key)) {
    const state = String(value).toLowerCase(); text.className = "report-state";
    if (["ok", "healthy", "active", "running", "online", "up", "passed", "low", "info"].includes(state)) text.classList.add("good");
    else if (["error", "failed", "critical", "high", "unhealthy", "down", "expired"].includes(state)) text.classList.add("bad");
    else if (["warning", "medium", "degraded", "offline", "stopped"].includes(state)) text.classList.add("warn");
  }
  return box;
}
function updateReportLiveMetrics(device) {
  const box = $("report-live"); box.replaceChildren();
  const online = device?.online === true;
  for (const [label, key] of [["CPU", "cpu_percent"], [t("内存"), "memory_percent"], [t("磁盘"), "disk_percent"]]) {
    if (publicSlug && !publicVisibility[key.replace("_percent", "")]) continue;
    const item = node("div"), value = device?.[key]; item.append(node("span", label), node("strong", online && typeof value === "number" ? `${value.toFixed(1)}%` : "—")); box.append(item);
  }
  $("report-network-note").hidden = Boolean(publicSlug && !publicVisibility.network);
  if (!publicSlug || publicVisibility.network) {
  const network = node("div"); network.append(node("span", t("默认出口")), node("strong", online ? `↓ ${networkRate(device.network_rx_bps)} · ↑ ${networkRate(device.network_tx_bps)}` : "—")); box.append(network);
  }
  $("report-live-status").textContent = `${t(online ? "在线" : "暂无实时数据")} · ${t("最近上报")} ${timeLabel(device?.last_seen)}`;
  drawHistory();
}
function reportBranch(value, title) {
  const details = node("details", undefined, "report-branch"), count = Array.isArray(value) ? value.length : Object.keys(value).length;
  details.append(node("summary", `${title} · ${count}`));
  details.addEventListener("toggle", () => { if (details.open && !details.dataset.loaded) { details.dataset.loaded = "true"; details.append(renderReportValue(value)); } });
  return details;
}
function renderReportValue(value) {
  if (Array.isArray(value)) {
    if (!value.length) return node("p", t("暂无条目"), "subtle");
    const box = node("div", undefined, "report-array"), search = node("input"), content = node("div", undefined, "report-table-scroll"), paging = node("div", undefined, "report-array-paging");
    search.type = "search"; search.placeholder = t("筛选当前列表"); search.setAttribute("aria-label", t("筛选当前列表")); box.append(search, content, paging);
    const searchable = value.map(item => JSON.stringify(item).toLocaleLowerCase(locale)); let current = value, page = 0;
    const draw = () => {
      content.replaceChildren(); paging.replaceChildren(); const rows = current.slice(page * 25, (page + 1) * 25);
      if (!rows.length) { content.append(node("p", t("暂无匹配条目"), "subtle")); return; }
      if (rows.every(row => row !== null && typeof row === "object" && !Array.isArray(row))) {
        const columns = [...new Set(rows.flatMap(row => Object.keys(row)))], table = node("table", undefined, "report-data-table"), head = node("thead"), tr = node("tr");
        for (const key of columns) tr.append(node("th", reportLabel(key))); head.append(tr); table.append(head); const body = node("tbody");
        for (const row of rows) {
          const line = node("tr"); for (const key of columns) { const cell = node("td"), item = Object.prototype.hasOwnProperty.call(row, key) ? row[key] : null; cell.append(item !== null && typeof item === "object" ? reportBranch(item, t("展开")) : reportMetric(item, key)); line.append(cell); } body.append(line);
        }
        table.append(body); content.append(table);
      } else {
        const list = node("ol"); list.start = page * 25 + 1;
        for (const item of rows) { const row = node("li"); row.append(item !== null && typeof item === "object" ? reportBranch(item, t("展开")) : reportMetric(item)); list.append(row); } content.append(list);
      }
      const previous = button(t("上一页"), () => { page -= 1; draw(); }, "button"), next = button(t("下一页"), () => { page += 1; draw(); }, "button"); previous.disabled = page === 0; next.disabled = (page + 1) * 25 >= current.length;
      paging.append(node("span", t("第 {start}–{end} 条，共 {count} 条", { start: page * 25 + 1, end: Math.min((page + 1) * 25, current.length), count: current.length })), previous, next);
    };
    search.oninput = () => { const term = search.value.trim().toLocaleLowerCase(locale); current = value.filter((_, index) => searchable[index].includes(term)); page = 0; draw(); }; draw(); return box;
  }
  if (value !== null && typeof value === "object") {
    const box = node("div", undefined, "report-object"), fields = node("dl", undefined, "report-fields"); box.append(fields);
    for (const [key, item] of Object.entries(value)) {
      if (item !== null && typeof item === "object") box.append(reportBranch(item, reportLabel(key)));
      else { const pair = node("div"), content = node("dd"); content.append(reportMetric(item, key)); pair.append(node("dt", reportLabel(key)), content); fields.append(pair); }
    }
    if (!Object.keys(value).length) box.append(node("p", t("暂无条目"), "subtle")); return box;
  }
  return node("p", reportScalar(value), "report-text");
}
function drawCollectorCatalog() {
  const catalog = $("report-catalog"); catalog.replaceChildren();
  for (const [key, title] of [["", t("全部采集")], ...Object.keys(fullReport?.collectors ?? {}).map(key => [key, t(reportTitles.get(key) ?? key.replaceAll("_", " "))])]) {
    const item = button(title, () => { reportCollector = key; $("report-search").value = ""; drawFullReport(); }, "collector-chip"); item.dataset.collector = key; catalog.append(item);
  }
}
function drawFullReport() {
  const target = $("report-sections"); target.replaceChildren();
  const collectors = fullReport?.collectors ?? {}, order = [...reportTitles.keys()], entries = Object.entries(collectors).sort(([a], [b]) => (order.includes(a) ? order.indexOf(a) : order.length) - (order.includes(b) ? order.indexOf(b) : order.length)), term = $("report-search").value.trim().toLocaleLowerCase(locale);
  for (const chip of $("report-catalog").children) chip.setAttribute("aria-pressed", String(chip.dataset.collector === reportCollector && !term));
  $("report-summary").textContent = t("{count} 项采集 · 最近完整快照：{time}", { count: entries.length, time: fullReport?.timestamp ? new Date(fullReport.timestamp).toLocaleString(locale) : t("未提供") });
  const all = [["envelope", Object.fromEntries(Object.entries(fullReport ?? {}).filter(([key]) => key !== "collectors"))], ...entries];
  let shown = 0;
  for (const [key, value] of all) {
    if (reportCollector && key !== reportCollector) continue;
    const title = key === "envelope" ? t("上报信息") : t(reportTitles.get(key) ?? key.replaceAll("_", " "));
    if (term && !`${key} ${title} ${value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).join(" ") : ""}`.toLocaleLowerCase(locale).includes(term)) continue;
    const section = node("details", undefined, "report-section"), heading = node("summary"), label = node("span", title), badge = node("span", key, "report-section-key"); heading.append(label, badge); section.append(heading); target.append(section); shown += 1;
    const fill = () => {
      if (!section.open || section.dataset.loaded) return;
      section.dataset.loaded = "true";
      // Collector envelopes retain their status/error fields while displaying
      // the actual data immediately, rather than hiding it behind another fold.
      if (value && typeof value === "object" && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, "data")) {
        const envelope = Object.fromEntries(Object.entries(value).filter(([field]) => field !== "data"));
        if (Object.keys(envelope).length) section.append(renderReportValue(envelope));
        section.append(renderReportValue(value.data));
      } else section.append(renderReportValue(value));
    };
    section.addEventListener("toggle", fill); if (["system", "cpu", "memory"].includes(key) || term) { section.open = true; fill(); }
  }
  if (!shown) empty(target, t("暂无匹配采集项"), t("可尝试采集名称或字段名。"));
}

async function showReport(device, publicView = false) {
  if (publicView && !publicVisibility.history) return;
  historyRequest += 1; historyLoading = false; historyLoadedAt = 0; historyLastSeen = undefined;
  reportDevice = device; fullReport = undefined; reportCollector = ""; updateReportLiveMetrics(device);
  $("report-title").textContent = device.name;
  $("report-summary").textContent = t("正在读取完整快照…");
  $("report-sections").replaceChildren(); $("report-catalog").replaceChildren(); $("report-search").value = "";
  $("report-download").disabled = true; $("report-raw").open = false;
  $("report-private").hidden = publicView;
  $("report-visibility").textContent = t(publicView ? "公开设备详情" : "设备完整详情");
  if (!$("report-dialog").open) $("report-dialog").showModal();
  void loadHistory(true);
  if (publicView) { $("report-summary").textContent = t("仅展示发布者已公开的运行指标，持续接收更新。"); return; }
  const requestGeneration = generation;
  try {
    const data = await api(`/api/devices/${device.id}`);
    if (generation !== requestGeneration || reportDevice?.viewKey !== device.viewKey) return;
    fullReport = data.report; $("report-download").disabled = false; drawCollectorCatalog(); drawFullReport();
  } catch (error) { if (reportDevice?.viewKey === device.viewKey) $("report-summary").textContent = error.message; }
}
async function readAgentSettings(initial = false) {
  const selected = settingsDevice;
  if (!selected) return;
  const data = await api(`/api/devices/${selected.id}/settings`);
  if (selected !== settingsDevice) return;
  if (initial) {
    $("device-realtime").checked = data.settings.realtime_metrics;
    $("device-compression").checked = data.settings.compress_reports;
  }
  settingsSupported = data.supported;
  $("device-settings-save").disabled = !settingsSupported || settingsSaving;
  $("device-settings-status").textContent = t(!data.supported ? "请先在设备上手动更新 Agent" : data.pending ? "已保存，等待 Agent 接收并确认。" : "配置已应用。下次连接会继续使用这些设置。");
}
async function showAgentSettings(device) {
  settingsDevice = device;
  settingsSupported = false;
  $("device-settings-name").textContent = device.name;
  $("device-settings-status").textContent = t("正在读取配置…");
  $("device-settings-save").disabled = true;
  $("device-settings-dialog").showModal();
  try { await readAgentSettings(true); } catch (error) { $("device-settings-status").textContent = error.message; return; }
  if (settingsDevice !== device) return;
  clearInterval(settingsPoll);
  settingsPoll = setInterval(() => void readAgentSettings().catch(error => { $("device-settings-status").textContent = error.message; }), 3000);
}
for (const element of document.querySelectorAll("[data-close]")) element.addEventListener("click", () => $(element.dataset.close).close());
$("report-dialog").addEventListener("close", () => { historyRequest += 1; historyLoading = false; reportDevice = undefined; fullReport = undefined; $("report-content").textContent = ""; $("report-sections").replaceChildren(); $("report-catalog").replaceChildren(); $("report-charts").replaceChildren(); });
$("report-range").onchange = () => { historyRequest += 1; historyLoading = false; historyLoadedAt = 0; drawHistory(); void loadHistory(true); };
window.addEventListener("resize", () => { if (reportDevice) updateReportLiveMetrics(reportDevice); });
$("report-refresh").onclick = () => { if (reportDevice && !publicSlug) void showReport(reportDevice); };
$("report-search").oninput = () => { reportCollector = ""; if (fullReport) drawFullReport(); };
$("report-raw").addEventListener("toggle", () => { if ($("report-raw").open && fullReport) $("report-content").textContent = JSON.stringify(fullReport, null, 2); });
$("report-download").onclick = () => { if (!fullReport) return; const url = URL.createObjectURL(new Blob([JSON.stringify(fullReport, null, 2)], { type: "application/json" })), link = node("a"); link.href = url; link.download = "w-monitor-" + String(reportDevice.id) + ".json"; link.hidden = true; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
$("restore-dialog").addEventListener("close", () => { $("restore-key").value = ""; });
$("install-dialog").addEventListener("close", () => { $("install-command").value = ""; });
$("device-settings-dialog").addEventListener("close", () => { clearInterval(settingsPoll); settingsDevice = undefined; });
$("device-settings-form").onsubmit = (event) => { event.preventDefault(); void run(async () => {
  if (!settingsDevice || settingsSaving || !settingsSupported) return;
  settingsSaving = true;
  $("device-settings-save").disabled = true;
  try {
    await api(`/api/devices/${settingsDevice.id}/settings`, { settings: { realtime_metrics: $("device-realtime").checked, compress_reports: $("device-compression").checked } });
    await readAgentSettings();
  } catch (error) { $("device-settings-status").textContent = error.message; throw error; }
  finally { settingsSaving = false; if (settingsDevice) $("device-settings-save").disabled = !settingsSupported; }
}); };
$("recovery-dialog").addEventListener("cancel", (event) => event.preventDefault());
$("saved-recovery").onclick = () => { $("recovery-dialog").close(); $("recovery-key").value = ""; };
$("copy-recovery").onclick = () => run(() => copy($("recovery-key").value));
for (const id of ["create-space", "new-space"]) $(id).onclick = () => run(newSpace);
for (const id of ["show-restore", "restore-another"]) $(id).onclick = () => $("restore-dialog").showModal();
$("restore-form").onsubmit = (event) => { event.preventDefault(); void run(async () => { const backup = await restoreSpace($("restore-key").value.trim()); bootstrap = ""; $("restore-dialog").close(); await loadSession(); if (backup) showRecovery(backup); }); };
$("login").onclick = () => run(async () => { const data = await api("/api/login", {}); location.assign(data.url); });
$("logout").onclick = () => run(async () => { await api("/api/logout", {}); autoRestoreAllowed = false; try { localStorage.removeItem("wm-active-public-key"); } catch {} browserKeys.clear(); bootstrap = ""; await loadSession(); });
$("claim").onclick = () => run(async () => { await rotateSpaceKey("/api/spaces/claim", "claim"); });
$("rotate-recovery").onclick = () => run(async () => {
  if (!confirm(t("轮换后，旧恢复口令和接入凭据失效，其他会话退出。已注册设备继续上报。"))) return;
  await rotateSpaceKey("/api/recovery/rotate", "rotate");
});
$("space-select").onchange = () => run(async () => { await api("/api/spaces/select", { id: $("space-select").value }); bootstrap = ""; await loadSession(); });
$("add-device").onclick = () => { updateInstallCommand(); $("install-dialog").showModal(); };
$("generate-bootstrap").onclick = () => run(async () => {
  if (bootstrap && !confirm(t("生成新凭据后，旧接入命令将不能注册新设备。已注册设备不受影响。"))) return;
  bootstrap = (await api("/api/bootstrap/rotate", {})).bootstrap_key; updateInstallCommand();
});
$("quick-deploy").onclick = () => {
  updateQuickCommand();
  $("quick-dialog").showModal();
};
$("copy-quick").onclick = () => run(() => copy($("quick-command").value));
$("copy-install").onclick = () => run(async () => {
  const button = $("copy-install"); button.disabled = true;
  try {
    if (!bootstrap) bootstrap = (await api("/api/bootstrap/rotate", {})).bootstrap_key;
    updateInstallCommand(); await copy($("install-command").value);
  } finally { button.disabled = false; }
});
for (const prefix of ["install", "quick"]) for (const option of ["realtime", "compression", "probes"]) {
  $(`${prefix}-${option}`).onchange = prefix === "install" ? updateInstallCommand : updateQuickCommand;
}
$("new-page").onclick = () => run(() => openPage());
$("bind-email").onclick = () => run(async () => { await api("/api/email/bind", { enabled: true }); await refreshEmail(); notice(t("已绑定验证过的邮箱，并开启通知。")); });
$("save-email").onclick = () => run(async () => { await api("/api/email/settings", { enabled: $("email-enabled").checked }); await refreshEmail(); notice(t("通知设置已保存。")); });
$("unbind-email").onclick = () => run(async () => {
  if (!confirm(t("解除邮箱绑定并停止后续通知？"))) return;
  await api("/api/email/unbind", {}); await refreshEmail();
});
$("page-form").onsubmit = (event) => { event.preventDefault(); void run(async () => {
  const value = { title: $("page-title").value.trim(), enabled: $("page-enabled").checked, ...Object.fromEntries(["cpu", "memory", "disk", "network", "history"].map(key => ["show_" + key, $("page-show-" + key).checked])), device_ids: [...$("page-devices").querySelectorAll("input:checked")].map((input) => input.value) };
  if (editingPage) value.id = editingPage.id;
  await api(editingPage ? "/api/pages/update" : "/api/pages/create", value); $("page-dialog").close(); await refreshPages();
}); };
function selectTab(pagesView) {
  $("devices-tab").setAttribute("aria-selected", String(!pagesView)); $("pages-tab").setAttribute("aria-selected", String(pagesView));
  $("devices-tab").tabIndex = pagesView ? -1 : 0; $("pages-tab").tabIndex = pagesView ? 0 : -1;
  $("devices-panel").hidden = pagesView; $("pages-panel").hidden = !pagesView;
}
$("devices-tab").onclick = () => selectTab(false); $("pages-tab").onclick = () => selectTab(true);
for (const id of ["devices-tab", "pages-tab"]) $(id).onkeydown = (event) => {
  if (["ArrowLeft", "ArrowRight"].includes(event.key)) { event.preventDefault(); const next = id === "devices-tab"; selectTab(next); $(next ? "pages-tab" : "devices-tab").focus(); }
};
document.addEventListener("visibilitychange", () => { if (document.hidden) stopRealtime(); else { if (publicSlug || session?.space) void refresh(); startRealtime(); } });
window.addEventListener("pagehide", stopRealtime);
async function refreshPlatformLoad() {
  if (publicSlug) return;
  try {
    const data = await api("/api/platform-load");
    $("load-status").textContent = t(data.available ? "服务可用" : "等待服务状态");
    $("load-stamp").textContent = data.collected_at ? t("状态更新于 {time}", { time: timeLabel(data.collected_at) }) : "";
  } catch { $("load-status").textContent = t("服务状态暂不可用"); $("load-stamp").textContent = ""; }
}
$("platform-status").hidden = Boolean(publicSlug);
if (!publicSlug) void refreshPlatformLoad();
const platformPoll = setInterval(() => { if (!publicSlug && !document.hidden) void refreshPlatformLoad(); }, 60000);
window.addEventListener("pagehide", () => clearInterval(platformPoll));
void run(async () => {
  if (publicSlug) { $("loading").hidden = true; $("public-page").hidden = false; await refresh(); startRealtime(); }
  else await loadSession();
});

void run(async () => {
  if (publicSlug) return;
  const catalog = await api("/api/regions");
  for (const region of catalog.regions) {
    const option = node("option", region.name); option.value = region.origin;
    option.selected = region.origin === location.origin;
    $("region-select").append(option);
  }
  $("region-picker").hidden = catalog.regions.length < 2;
  $("region-select").onchange = () => {
    const selected = catalog.regions.find(region => region.origin === $("region-select").value);
    if (selected && selected.origin !== location.origin) location.assign(selected.origin + "/");
  };
});

let uptimeDevice, uptimePoll, uptimeBusy = false;
const availabilityLabel = state => t(state === "up" ? "可用" : state === "down" ? "不可用" : "未知");
async function readAvailability() {
  if (!uptimeDevice || uptimeBusy) return;
  uptimeBusy = true;
  const selectedDevice = uptimeDevice, selected = $("uptime-monitor").value, range = $("uptime-range").value, requestGeneration = generation;
  try {
    const data = await api(`/api/devices/${selectedDevice.id}/uptime?monitor=${encodeURIComponent(selected)}&range=${range}`);
    if (uptimeDevice !== selectedDevice || generation !== requestGeneration || $("uptime-monitor").value !== selected || $("uptime-range").value !== range) return;
    const options = [Object.assign(node("option", t("设备在线率")), {value:"device"}), ...data.monitors.map(m => Object.assign(node("option", m.name), {value:m.id}))];
    $("uptime-monitor").replaceChildren(...options); $("uptime-monitor").value = selected;
    $("uptime-status").textContent = t("当前状态") + ": " + availabilityLabel(data.state) + (data.state_since ? " · " + new Date(data.state_since * 1000).toLocaleString(locale) : "");
    const history = data.history, rate = history.availability_percent === null ? "—" : history.availability_percent.toFixed(3) + "%";
    $("uptime-summary").textContent = t("已知采样可用率") + ": " + rate + " · " + t("覆盖率") + ": " + history.coverage_percent.toFixed(1) + "% · " + t("每分钟记录；缺失区间保留未知，超过 24 小时按小时聚合。") + (data.worker_available ? "" : " · " + t("历史记录任务尚未运行或已延迟。"));
    const points = history.points.map(row => Object.fromEntries(history.columns.map((key, index) => [key, row[index]])));
    $("uptime-charts").replaceChildren(...[["up_percent", "可用率"], ["latency_ms", "响应时间"]].map(([key,label]) => {
      const card = node("section", undefined, "chart-card"); card.append(node("h3", t(label)), metricPlot(points, [key], [t(label)], false, history)); return card;
    }));
    $("uptime-events").replaceChildren(...data.events.map(event => node("p", new Date(event.at * 1000).toLocaleString(locale) + " · " + availabilityLabel(event.previous) + " → " + availabilityLabel(event.state))));
    $("uptime-monitors").replaceChildren(...data.monitors.map(m => {
      const card = node("div", undefined, "settings-row"); card.append(node("span", `${m.name} · ${m.kind.toUpperCase()} · ${m.target} · ${availabilityLabel(m.state)}${typeof m.latency_ms === "number" ? " · " + m.latency_ms + " ms" : ""}`));
      card.append(button(t("删除"), async () => { if (!confirm(t("删除此服务探测及其历史记录？"))) return; await api("/api/services/delete", {device_id:selectedDevice.id,id:m.id}); if ($("uptime-monitor").value === m.id) $("uptime-monitor").value = "device"; await readAvailability(); }, "quiet")); return card;
    }));
    $("uptime-create").disabled = !data.service_probes_enabled;
    $("uptime-consent").textContent = data.service_probes_enabled ? t("此设备已允许服务探测；新配置在下次上报时接收。") : t("请在设备本机手动更新 Agent，并使用原配置加 --enable-service-probes 启动，允许作为服务探针。");
  } catch(error) {
    if (uptimeDevice === selectedDevice) {
      $("uptime-status").textContent = error.message;
      if (error.status === 404 && selected !== "device") $("uptime-monitor").value = "device";
      else if (error.status === 404) $("uptime-dialog").close();
    }
  } finally { uptimeBusy = false; }
}
async function showAvailability(device) {
  uptimeDevice = device; $("uptime-title").textContent = device.name;
  $("uptime-monitor").replaceChildren(Object.assign(node("option", t("设备在线率")), {value:"device"}));
  $("uptime-status").textContent = t("正在读取服务端历史…"); $("uptime-dialog").showModal();
  await readAvailability(); if (uptimeDevice !== device || !$("uptime-dialog").open) return; clearInterval(uptimePoll); uptimePoll = setInterval(() => void readAvailability(), 5000);
}
$("uptime-dialog").addEventListener("close", () => { clearInterval(uptimePoll); uptimeDevice = undefined; $("uptime-monitors").replaceChildren(); $("uptime-charts").replaceChildren(); $("uptime-events").replaceChildren(); $("uptime-form").reset(); $("uptime-title").textContent = ""; $("uptime-summary").textContent = ""; });
$("uptime-monitor").onchange = () => void readAvailability();
$("uptime-range").onchange = () => void readAvailability();
$("uptime-form").onsubmit = event => { event.preventDefault(); void run(async () => {
  if (!uptimeDevice) return;
  await api("/api/services/create", {device_id:uptimeDevice.id,settings:{name:$("uptime-name").value.trim(),kind:$("uptime-kind").value,target:$("uptime-target").value.trim(),interval_seconds:Number($("uptime-interval").value),timeout_seconds:Number($("uptime-timeout").value)}});
  $("uptime-name").value = ""; $("uptime-target").value = ""; await readAvailability();
}); };
