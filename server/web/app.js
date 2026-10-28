"use strict";
const locale = window.WM_I18N.locale;
const t = (message, values = {}) => (window.WM_I18N.messages[message] ?? message).replace(/\{(\w+)\}/g, (match, key) => values[key] ?? match);
const $ = (id) => document.getElementById(id);
const publicSlug = /^\/status\/(wm1_[A-Za-z0-9_-]{40,320})$/.exec(location.pathname)?.[1];
const responses = new Map();
let session, devices = [], pages = [], bootstrap = "", editingPage = null;
let lastView, currentPage = 0;
let events, poll, refreshing = false, refreshAgain = false, generation = 0, allowEvents = false;

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
  if (!response.ok) throw new Error(data.error || t("请求失败（{status}）", { status: response.status }));
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
function drawDevices(target, rows, publicView = false) {
  if (!rows.length) { empty(target, publicView ? t("暂无公开设备") : t("等待第一台设备"), publicView ? t("发布者尚未选择设备，或设备已被移除。") : t("点击“接入设备”，在主机上运行 Lite Agent。首次上报后设备会出现在这里。")); return; }
  const table = node("table", undefined, "device-table");
  const head = node("thead"), headRow = node("tr");
  for (const label of [t("设备 / 最近上报"), t("状态"), "CPU", t("内存"), t("磁盘"), ...(publicView ? [] : [t("只读数据")])]) headRow.append(node("th", label));
  head.append(headRow); table.append(head);
  const body = node("tbody");
  for (const device of rows) {
    const row = node("tr"), name = node("td");
    name.append(node("div", device.name, "device-name"), node("div", timeLabel(device.last_seen), "last-seen"));
    const state = node("td", undefined, "status-cell");
    const badge = node("span", undefined, `status${device.online ? "" : " offline"}`);
    badge.append(node("span", undefined, "dot"), document.createTextNode(device.online === true ? t("在线") : device.online === false ? t("离线") : t("暂无数据"))); state.append(badge);
    row.append(name, state);
    for (const [label, key] of [["CPU", "cpu_percent"], [t("内存"), "memory_percent"], [t("磁盘"), "disk_percent"]]) {
      const cell = node("td", undefined, "metric-cell"); cell.dataset.label = label;
      const value = device[key], valid = typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
      const metric = node("span", valid ? `${value.toFixed(1)}%` : "—", `metric${valid && value >= 85 ? " high" : ""}`);
      const bar = node("span", undefined, "bar"), fill = node("i");
      fill.style.width = `${valid ? value : 0}%`; bar.append(fill); metric.append(bar); cell.append(metric); row.append(cell);
    }
    if (!publicView) {
      const cell = node("td", undefined, "actions-cell"), actions = node("div", undefined, "row-actions");
      actions.append(button(t("查看采集"), () => showReport(device), ""), button(t("移除接入"), async () => {
        if (!confirm(t("移除此设备的上报凭据和已存数据？这不会卸载或操作主机上的 Agent。"))) return;
        await api("/api/devices/revoke", { id: device.id }); await refresh();
      }, "danger")); cell.append(actions); row.append(cell);
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
      await api("/api/pages/update", { id: page.id, title: page.title, enabled: !page.enabled, device_ids: page.selection.filter((id) => available.has(id)) }); await refreshPages();
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
    if (data === lastView) return;
    lastView = data;
    if (publicSlug) { $("public-title").textContent = data.title; drawDevices($("public-list"), data.devices, true); }
    else { devices = data.devices; $("device-count").textContent = data.total; drawDevices($("device-list"), devices); }
    drawPaging($(publicSlug ? "public-list" : "device-list"), data);
  } catch (error) {
    if (current !== generation) return;
    notice(error.message); lastView = undefined;
    // Never leave a revoked public snapshot, or a failed private read, visible.
    empty($(publicSlug ? "public-list" : "device-list"), t("暂时无法读取"), t("请刷新页面；链接可能已停用，或当前会话已经失效。"));
    if (!publicSlug) devices = [];
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
  poll = setInterval(() => void refresh(), 5000);
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
    clearInterval(poll); poll = setInterval(() => void refresh(), 5000);
    if (++errors >= 2) { source.close(); events = undefined; }
  };
}
async function loadSession() {
  generation += 1; stopRealtime(); responses.clear(); lastView = undefined; currentPage = 0;
  session = await api("/api/session");
  $("login").hidden = !session.login.available || session.login.authenticated;
  $("logout").hidden = !session.space && !session.login.authenticated;
  $("claim").hidden = !session.space || session.space.claimed || !session.login.authenticated;
  $("welcome").hidden = Boolean(session.space); $("dashboard").hidden = !session.space;
  $("loading").hidden = true;
  if (session.space) {
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
  const result = await api("/api/spaces/create", { title: title.trim() });
  bootstrap = result.bootstrap_key; await loadSession(); showRecovery(result.recovery);
}
function showRecovery(key, rotated = false) {
  $("recovery-key").value = key;
  $("recovery-explanation").textContent = rotated ? t("旧恢复口令与接入凭据已失效，其他会话已退出；已注册设备继续上报。请保存新口令，只显示这一次。") : t("只显示这一次。保存后，你可以跨浏览器找回这个空间。");
  $("recovery-dialog").showModal();
}
function shellQuote(value) { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }
function installCommand() {
  if (!bootstrap) return t("点击“生成新的接入凭据”，再复制安装命令。已注册设备不受凭据轮换影响。");
  return `curl -fsSL --proto '=https' --max-time 30 ${shellQuote(location.origin + "/downloads/install.sh")} | bash -s -- --endpoint ${shellQuote(session.ingest_url)} --key ${shellQuote(bootstrap)}`;
}
async function copy(value) {
  try { await navigator.clipboard.writeText(value); notice(t("已复制。")); }
  catch { throw new Error(t("自动复制未完成，请选中文本手动复制。")); }
}
async function openPage(page = null) {
  const options = (await api("/api/device-options")).devices;
  editingPage = page; $("page-dialog-title").textContent = page ? t("编辑分享页") : t("新建分享页");
  $("page-title").value = page?.title ?? ""; $("page-enabled").checked = page ? Boolean(page.enabled) : true;
  $("page-devices").replaceChildren(...options.map((device) => {
    const label = node("label"), input = node("input"); input.type = "checkbox"; input.value = device.id; input.checked = Boolean(page?.selection.includes(device.id));
    label.append(input, document.createTextNode(device.name)); return label;
  }));
  if (!options.length) $("page-devices").append(node("p", t("尚无设备，可以先保存页面，接入设备后再选择。"), "subtle"));
  $("page-dialog").showModal();
}
async function showReport(device) {
  const data = await api(`/api/devices/${device.id}`);
  const raw = JSON.stringify(data.report, null, 2);
  $("report-title").textContent = device.name + t(" · 只读快照");
  $("report-content").textContent = raw.length > 512000 ? raw.slice(0, 512000) + t("\n…预览已截断，可通过当前设备数据接口读取完整快照。") : raw;
  $("report-dialog").showModal();
}
for (const element of document.querySelectorAll("[data-close]")) element.addEventListener("click", () => $(element.dataset.close).close());
$("report-dialog").addEventListener("close", () => { $("report-content").textContent = ""; });
$("restore-dialog").addEventListener("close", () => { $("restore-key").value = ""; });
$("install-dialog").addEventListener("close", () => { $("install-command").value = ""; });
$("recovery-dialog").addEventListener("cancel", (event) => event.preventDefault());
$("saved-recovery").onclick = () => { $("recovery-dialog").close(); $("recovery-key").value = ""; };
$("copy-recovery").onclick = () => run(() => copy($("recovery-key").value));
for (const id of ["create-space", "new-space"]) $(id).onclick = () => run(newSpace);
for (const id of ["show-restore", "restore-another"]) $(id).onclick = () => $("restore-dialog").showModal();
$("restore-form").onsubmit = (event) => { event.preventDefault(); void run(async () => { await api("/api/spaces/restore", { recovery: $("restore-key").value.trim() }); bootstrap = ""; $("restore-dialog").close(); await loadSession(); }); };
$("login").onclick = () => run(async () => { const data = await api("/api/login", {}); location.assign(data.url); });
$("logout").onclick = () => run(async () => { await api("/api/logout", {}); bootstrap = ""; await loadSession(); });
$("claim").onclick = () => run(async () => { const data = await api("/api/spaces/claim", {}); bootstrap = data.bootstrap_key; await loadSession(); showRecovery(data.recovery, true); });
$("rotate-recovery").onclick = () => run(async () => {
  if (!confirm(t("轮换后，旧恢复口令和接入凭据失效，其他会话退出。已注册设备继续上报。"))) return;
  const data = await api("/api/recovery/rotate", {}); bootstrap = data.bootstrap_key; showRecovery(data.recovery, true);
});
$("space-select").onchange = () => run(async () => { await api("/api/spaces/select", { id: $("space-select").value }); bootstrap = ""; await loadSession(); });
$("add-device").onclick = () => { $("install-command").value = installCommand(); $("copy-install").disabled = !bootstrap; $("install-dialog").showModal(); };
$("generate-bootstrap").onclick = () => run(async () => {
  if (bootstrap && !confirm(t("生成新凭据后，旧接入命令将不能注册新设备。已注册设备不受影响。"))) return;
  bootstrap = (await api("/api/bootstrap/rotate", {})).bootstrap_key; $("install-command").value = installCommand(); $("copy-install").disabled = false;
});
$("quick-deploy").onclick = () => {
  $("quick-command").value = `curl -fsSL --proto '=https' --max-time 30 ${shellQuote(location.origin + "/downloads/install.sh")} | bash -s -- --public ${shellQuote(location.origin)} --language ${shellQuote(locale)}`;
  $("quick-dialog").showModal();
};
$("copy-quick").onclick = () => run(() => copy($("quick-command").value));
$("copy-install").onclick = () => run(() => copy($("install-command").value));
$("new-page").onclick = () => run(() => openPage());
$("bind-email").onclick = () => run(async () => { await api("/api/email/bind", { enabled: true }); await refreshEmail(); notice(t("已绑定验证过的邮箱，并开启通知。")); });
$("save-email").onclick = () => run(async () => { await api("/api/email/settings", { enabled: $("email-enabled").checked }); await refreshEmail(); notice(t("通知设置已保存。")); });
$("unbind-email").onclick = () => run(async () => {
  if (!confirm(t("解除邮箱绑定并停止后续通知？"))) return;
  await api("/api/email/unbind", {}); await refreshEmail();
});
$("page-form").onsubmit = (event) => { event.preventDefault(); void run(async () => {
  const value = { title: $("page-title").value.trim(), enabled: $("page-enabled").checked, device_ids: [...$("page-devices").querySelectorAll("input:checked")].map((input) => input.value) };
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
  try {
    const data = await api("/api/platform-load");
    if (!data.available) throw new Error();
    const format = (value, suffix = "") => typeof value === "number" && Number.isFinite(value) ? new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value) + suffix : "—";
    $("load-devices").textContent = `${data.online_devices} / ${data.devices}`;
    $("load-rps").textContent = format(data.requests_per_second);
    $("load-latency").textContent = format(data.mean_response_ms, " ms");
    $("load-errors").textContent = format(data.server_error_percent, "%");
    $("load-redis").textContent = format(data.redis_used_bytes / 1048576, " MiB");
    $("load-host").textContent = format(data.host_load?.[0]);
    $("load-stamp").textContent = t("更新于 {time} · 展示上一完整分钟；系统负载来自共享宿主机，并非本账号 CPU 占用。", { time: timeLabel(data.collected_at) });
  } catch {
    for (const id of ["load-devices", "load-rps", "load-latency", "load-errors", "load-redis", "load-host"]) $(id).textContent = "—";
    $("load-stamp").textContent = t("等待统计。系统负载来自共享宿主机，不代表本账号 CPU 占用。");
  }
}
void refreshPlatformLoad();
const platformPoll = setInterval(() => { if (!document.hidden) void refreshPlatformLoad(); }, 60000);
window.addEventListener("pagehide", () => clearInterval(platformPoll));
void run(async () => {
  if (publicSlug) { $("loading").hidden = true; $("public-page").hidden = false; await refresh(); startRealtime(); }
  else await loadSession();
});
