// Código compartido por las tres pantallas: llamadas a la API, modelo elegido, textos en español,
// formato de números, cabecera, avisos y panel lateral del flujo.
// Todo lo que viene de la API o de un archivo se escribe con textContent, nunca con innerHTML.

const STORAGE_KEYS = { model: 'ntd-model', theme: 'ntd-theme' };
const ICONS_URL = 'assets/icons.svg';
// Variables que el panel muestra antes de "Ver todas".
const TOP_CONTRIBUTIONS = 10;
const TOAST_MS = 3000;

// ---------- API (contrato, secciones 4 a 9) ----------

export class ApiError extends Error {
  constructor(code, message, details = null, status = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

// network_error es solo del frontend: el navegador no recibió ninguna respuesta del servidor.
const NETWORK_ERROR_MESSAGE = 'No se pudo conectar con el servidor. Revisa que la aplicación esté en ejecución y vuelve a intentarlo.';
// Mensaje de internal_error del contrato (sección 9), para una respuesta que no es JSON.
const INTERNAL_ERROR_MESSAGE = 'Ocurrió un error inesperado en el servidor. Intenta de nuevo; si se repite, avisa al equipo.';

export const networkError = () => new ApiError('network_error', NETWORK_ERROR_MESSAGE);

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(path, { headers: { Accept: 'application/json' }, ...options });
  } catch {
    throw networkError();
  }
  let body;
  try {
    body = await response.json();
  } catch {
    throw new ApiError('internal_error', INTERNAL_ERROR_MESSAGE, null, response.status);
  }
  if (body && body.error) {
    const { code, message, details } = body.error;
    throw new ApiError(code, message, details ?? null, response.status);
  }
  if (!response.ok) throw new ApiError('internal_error', INTERNAL_ERROR_MESSAGE, null, response.status);
  return body;
}

export const fetchModels = () => request('api/models');
export const fetchMetrics = () => request('api/metrics');
export const fetchAnalysis = (analysisId) => request('api/analysis/' + encodeURIComponent(analysisId));

export function explainFlow(analysisId, flowId) {
  return request('api/explain/' + encodeURIComponent(flowId) + '?analysis_id=' + encodeURIComponent(analysisId));
}

// file: un archivo o null; con useSample = true se analiza la muestra de demostración.
export function predict({ file = null, useSample = false, model = null, useLabels = true }) {
  const form = new FormData();
  if (file) form.append('file', file);
  if (useSample) form.append('use_sample', 'true');
  if (model) form.append('model', model);
  form.append('use_labels', useLabels ? 'true' : 'false');
  return request('api/predict', { method: 'POST', body: form });
}

// Dirección del WebSocket de la simulación, relativa a la página (wss:// si la página va por https).
export function simulationUrl() {
  const url = new URL('ws/simulate', window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.search = '';
  return url.href;
}

// ---------- Almacenamiento del navegador (puede estar bloqueado) ----------

function readStorage(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Sin almacenamiento: la elección vale solo mientras la página esté abierta.
  }
}

// ---------- Modelo elegido (contrato, sección 6) ----------

// El modelo de la lista de GET /api/models con ese nombre, o null si no está.
export function findModel(models, name) {
  return (models && models.models.find((m) => m.name === name)) || null;
}

// El modelo guardado en el navegador si sigue en la lista; si no, el modelo por defecto.
export function getChosenModel(models) {
  return findModel(models, readStorage(STORAGE_KEYS.model)) || findModel(models, models.default_model);
}

export function setChosenModel(name) {
  writeStorage(STORAGE_KEYS.model, name);
}

// La muestra de demostración tiene analysis_id fijos (contrato, sección 2): sample-<modelo> con
// etiquetas y sample-<modelo>-unlabeled sin ellas. Son los únicos ids que el frontend arma o interpreta.
const SAMPLE_PREFIX = 'sample-';
export const isSampleAnalysis = (analysisId) => analysisId.startsWith(SAMPLE_PREFIX);
export const sampleAnalysisId = (modelName, labeled) => SAMPLE_PREFIX + modelName + (labeled ? '' : '-unlabeled');

// Si un modelo es simulado: true o false según GET /api/models, o null si no aparece en la lista
// (por ejemplo, un enlace viejo a un modelo que se quitó del registro). Con null no se supone nada.
export function isMockModel(models, name) {
  const model = findModel(models, name);
  return model ? model.is_mock : null;
}

// ---------- Textos en español ----------

// Etiquetas de las variables (nombre técnico al pasar el cursor). Aprobadas por el equipo.
export const FEATURE_LABELS = {
  dur: 'Duración',
  spkts: 'Paquetes del origen',
  dpkts: 'Paquetes del destino',
  sbytes: 'Bytes del origen',
  dbytes: 'Bytes del destino',
  rate: 'Paquetes por segundo',
  sttl: 'TTL del origen',
  dttl: 'TTL del destino',
  sload: 'Carga del origen (bits/s)',
  dload: 'Carga del destino (bits/s)',
  sloss: 'Pérdidas del origen',
  dloss: 'Pérdidas del destino',
  sinpkt: 'Intervalo entre paquetes del origen (ms)',
  dinpkt: 'Intervalo entre paquetes del destino (ms)',
  sjit: 'Variación del retardo del origen (jitter, ms)',
  djit: 'Variación del retardo del destino (jitter, ms)',
  synack: 'Tiempo SYN → SYN-ACK',
  ackdat: 'Tiempo SYN-ACK → ACK',
  smean: 'Tamaño medio del origen',
  dmean: 'Tamaño medio del destino',
  trans_depth: 'Solicitudes HTTP encadenadas',
  response_body_len: 'Tamaño de la respuesta HTTP',
  ct_srv_src: 'Conexiones del origen al mismo servicio',
  ct_state_ttl: 'Estado según TTL',
  ct_dst_ltm: 'Conexiones recientes al destino',
  ct_src_dport_ltm: 'Conexiones del origen al mismo puerto',
  ct_dst_sport_ltm: 'Conexiones al destino desde el mismo puerto',
  ct_dst_src_ltm: 'Conexiones entre el mismo origen y destino',
  ct_ftp_cmd: 'Comandos FTP',
  ct_flw_http_mthd: 'Flujos con métodos HTTP',
  ct_src_ltm: 'Conexiones recientes del origen',
  ct_srv_dst: 'Conexiones al mismo servicio y destino',
  proto: 'Protocolo',
  service: 'Servicio',
  state: 'Estado de la conexión',
};

// Severidades (contrato, sección 2): texto e ícono, para no depender solo del color.
export const SEVERITIES = {
  critical: { label: 'Crítica', icon: 'octagon-alert' },
  high: { label: 'Alta', icon: 'triangle-alert' },
  medium: { label: 'Media', icon: 'circle-alert' },
  low: { label: 'Baja', icon: 'circle-minus' },
  normal: { label: 'Normal', icon: 'circle-check' },
};
export const ALERT_SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Descripciones de los tipos de ataque, basadas en Koroniotis, Moustafa, Sitnikova y Slay (2017),
// "Towards Developing Network forensic mechanism for Botnet Activities in the IoT based on Machine
// Learning Techniques", arXiv:1711.02825v1, que las atribuye a Moustafa y Slay (2016), Information
// Security Journal: A Global Perspective, 25(1-3), 18-31.
export const ATTACK_TYPE_DESCRIPTIONS = {
  Fuzzers: 'Envía grandes cantidades de datos aleatorios para encontrar debilidades de seguridad, esperando que el sistema falle.',
  Analysis: 'Distintas técnicas de intrusión dirigidas a puertos, direcciones de correo y scripts web.',
  Backdoor: 'Evita los mecanismos de autenticación y permite el acceso remoto no autorizado a un equipo.',
  DoS: 'Técnica de interrupción que busca dejar el sistema atacado sin responder.',
  Exploits: 'Instrucciones que aprovechan errores del código y dejan el sistema o la red en un estado vulnerable.',
  Generic: 'Ataque que intenta provocar una colisión en un cifrado por bloques usando una función hash.',
  Reconnaissance: 'Sondeo para reunir información, que suele lanzarse antes del ataque real.',
  Shellcode: 'Comandos preparados que se inyectan por la red en una aplicación en ejecución para tomar el control del equipo remoto.',
  Worms: 'Programa malicioso que se replica a sí mismo y se propaga a uno o varios equipos.',
};

// ---------- Formato de números (español de Colombia; solo se redondea al mostrar) ----------

const LOCALE = 'es-CO';
const intFormat = new Intl.NumberFormat(LOCALE);
const percentFormat = new Intl.NumberFormat(LOCALE, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 });
const valueFormat = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 6 });

export const formatInt = (n) => intFormat.format(n);
export const formatPercent = (x) => (x === null || x === undefined ? '—' : percentFormat.format(x));

export function formatDecimal(x, digits = 2) {
  return new Intl.NumberFormat(LOCALE, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(x);
}

// Puntajes (F1, PR-AUC, ROC-AUC, F1 macro): decimal con 3 cifras, como en la literatura.
// Las probabilidades y las tasas van en porcentaje con formatPercent.
export const formatScore = (x) => (x === null || x === undefined ? '—' : formatDecimal(x, 3));

export function formatSigned(x) {
  return (x >= 0 ? '+' : '−') + formatDecimal(Math.abs(x));
}

// Valor de una variable de un flujo, tal como vino en el archivo.
export function formatValue(v) {
  if (v === null || v === undefined) return 'vacío';
  return typeof v === 'number' ? valueFormat.format(v) : String(v);
}

// ---------- Construcción de la página ----------

// h('div', {class: 'x', onclick: fn}, hijo, 'texto', ...): crea un elemento sin innerHTML.
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

// Ícono decorativo de assets/icons.svg; el significado lo da el texto que lo acompaña.
export function icon(name, { size } = {}) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', size === 'sm' ? 'icon icon-sm' : 'icon');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', ICONS_URL + '#icon-' + name);
  svg.append(use);
  return svg;
}

// Botón de solo ícono: su texto en español va en aria-label.
export function iconButton(name, label, attrs = {}) {
  return h('button', { type: 'button', class: 'icon-btn', 'aria-label': label, ...attrs }, icon(name));
}

export function featureName(name) {
  return h('span', { class: 'feat', 'data-tech': name, tabindex: '0' }, FEATURE_LABELS[name] || name);
}

export function attackType(cat) {
  const description = ATTACK_TYPE_DESCRIPTIONS[cat];
  return h('span', { title: description || null }, cat);
}

export function severityBadge(severity) {
  const s = SEVERITIES[severity];
  return h('span', { class: 'sev-badge sev-' + severity }, icon(s.icon), s.label);
}

export function probability(flow) {
  return h('span', { class: 'prob sev-' + flow.severity },
    h('span', { class: 'prob-bar', 'aria-hidden': 'true' }, h('span', { style: 'width:' + (flow.attack_probability * 100).toFixed(1) + '%' })),
    h('span', { class: 'prob-num' }, formatPercent(flow.attack_probability)));
}

// Compara lo predicho con lo real de un flujo; solo tiene sentido con etiquetas.
export function flowResult(flow) {
  if (flow.is_alert && flow.true_label === 1) {
    const otherType = flow.predicted_attack_cat !== flow.true_attack_cat;
    return h('span', { class: 'result ok' }, icon('check'), 'Ataque detectado',
      otherType ? h('span', { class: 'extra' }, ' (tipo distinto)') : null);
  }
  if (flow.is_alert) return h('span', { class: 'result bad' }, icon('x'), 'Falsa alarma');
  if (flow.true_label === 1) return h('span', { class: 'result bad' }, icon('x'), 'Ataque no detectado');
  return h('span', { class: 'result ok' }, icon('check'), 'Normal');
}

// Sobre qué flujos se calcula cada tasa (con etiquetas): detección sobre los ataques reales y
// falsas alarmas sobre los normales. Solo cuenta flujos; las tasas salen del summary de la API.
export function rateTips(flows) {
  const attacks = flows.filter((f) => f.true_label === 1);
  const normals = flows.filter((f) => f.true_label === 0);
  const alerts = (list) => list.filter((f) => f.is_alert).length;
  const note = ' Por eso Detección y Falsas alarmas no suman 100 %.';
  return {
    detection: formatInt(alerts(attacks)) + ' de ' + formatInt(attacks.length)
      + ' ataques reales dieron alerta. Se calcula solo sobre los ataques reales.' + note,
    falseAlarm: formatInt(alerts(normals)) + ' de ' + formatInt(normals.length)
      + ' flujos normales dieron alerta. Se calcula solo sobre los flujos normales.' + note,
  };
}

// Indicador: etiqueta, valor y nota. Con tip, el recuadro de ayuda aparece al pasar el mouse, con
// el foco del teclado o al tocarlo; los lectores de pantalla lo leen como descripción.
// tipSide: 'start' o 'end', el borde del indicador al que se alinea la ayuda.
let tipCount = 0;
export function kpiCard({ label, value, sub = null, sev = null, labeled = false, tip = null, tipSide = 'start' }) {
  const missing = value === null;
  const tipId = tip ? 'kpi-tip-' + (tipCount += 1) : null;
  return h('div', {
    class: 'kpi' + (sev ? ' sev sev-' + sev : '') + (labeled ? ' kpi-labeled' : '') + (tip ? ' has-tip tip-' + tipSide : ''),
    tabindex: tip ? '0' : null, 'aria-describedby': tipId,
  },
  h('span', { class: 'kpi-label' }, sev ? icon(SEVERITIES[sev].icon) : null, label,
    tip ? icon('info', { size: 'sm' }) : null),
  h('span', { class: 'kpi-value' + (missing ? ' is-na' : '') }, missing ? '—' : value),
  sub ? h('span', { class: 'kpi-sub' }, sub) : null,
  tip ? h('span', { class: 'kpi-tip', id: tipId, role: 'tooltip' }, tip) : null);
}

// ---------- Avisos ----------

export function mockNotice() {
  return h('div', { class: 'notice notice-warn', role: 'note' }, icon('flask-conical'),
    h('p', {}, h('strong', {}, 'Modelo simulado.'),
      ' Sus probabilidades, tipos y explicaciones son inventados: sirven para probar la aplicación, no para evaluar el tráfico.'));
}

// Nombre de un modelo con la etiqueta "Simulado" solo si GET /api/models dice que lo es.
export function modelName(models, model) {
  const mock = isMockModel(models, model.name) === true;
  return h('span', { class: 'model-name' }, model.display_name,
    mock ? h('span', { class: 'tag tag-mock' }, icon('flask-conical', { size: 'sm' }), 'Simulado') : null);
}

export function errorNotice(error, { actionLabel, onAction } = {}) {
  const message = error instanceof ApiError ? error.message : INTERNAL_ERROR_MESSAGE;
  return h('div', { class: 'notice notice-error', role: 'alert' }, icon('circle-x'),
    h('div', { class: 'stack' }, h('p', {}, message),
      actionLabel ? h('div', {}, h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: onAction }, actionLabel)) : null));
}

let toastTimer = null;
export function showToast(text) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = h('div', { id: 'toast', class: 'toast', role: 'status' });
    document.body.append(toast);
  }
  toast.textContent = text;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, TOAST_MS);
}

// Enlace directo a un flujo (contrato, sección 2).
export function flowLink(analysisId, flowId) {
  return 'index.html?analysis=' + encodeURIComponent(analysisId) + '&flow=' + encodeURIComponent(flowId);
}

export async function copyLink(url) {
  const absolute = new URL(url, window.location.href).href;
  try {
    await navigator.clipboard.writeText(absolute);
    showToast('Enlace copiado');
  } catch {
    showToast('No se pudo copiar el enlace');
  }
}

// ---------- Cabecera y modo claro u oscuro ----------

function renderThemeButton(button) {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  button.replaceChildren(icon(dark ? 'sun' : 'moon'));
  button.setAttribute('aria-label', dark ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro');
}

function initThemeToggle() {
  const button = document.getElementById('themeToggle');
  if (!button) return;
  renderThemeButton(button);
  button.addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    writeStorage(STORAGE_KEYS.theme, next);
    renderThemeButton(button);
  });
}

// Llena la píldora "Modelo en uso" con el modelo elegido y devuelve ese modelo.
export function initHeader(models) {
  const model = getChosenModel(models);
  const pill = document.getElementById('modelPill');
  if (pill && model) {
    pill.replaceChildren(h('span', { class: 'pill-k' }, 'Modelo en uso:'),
      h('span', { class: 'pill-v' }, model.display_name),
      model.is_mock ? h('span', { class: 'tag tag-mock' }, icon('flask-conical', { size: 'sm' }), 'Simulado') : null);
    pill.hidden = false;
  }
  return model;
}

// Lo que hace cada página al abrir: el botón de modo, la lista de modelos y la cabecera.
// Devuelve la respuesta de GET /api/models, o null si falló (el error queda en #pageStatus).
export async function initPage() {
  initThemeToggle();
  try {
    const models = await fetchModels();
    initHeader(models);
    return models;
  } catch (error) {
    const status = document.getElementById('pageStatus');
    if (status) status.replaceChildren(errorNotice(error, { actionLabel: 'Reintentar', onAction: () => window.location.reload() }));
    return null;
  }
}

// ---------- Grupos de opciones (filtros, velocidades) ----------

// Grupo role="radiogroup" con opciones role="radio" y data-value: las flechas cambian la opción y
// solo la marcada entra en el orden de tabulación.
export function initRadioGroup(group, onChange) {
  const items = () => [...group.querySelectorAll('[role="radio"]')];
  const select = (item, notify = true) => {
    for (const other of items()) {
      const checked = other === item;
      other.setAttribute('aria-checked', String(checked));
      other.tabIndex = checked ? 0 : -1;
    }
    if (notify) onChange(item.dataset.value);
  };
  group.addEventListener('click', (event) => {
    const item = event.target.closest('[role="radio"]');
    if (item && group.contains(item) && !item.disabled) select(item);
  });
  group.addEventListener('keydown', (event) => {
    const list = items().filter((i) => !i.disabled);
    const index = list.indexOf(document.activeElement);
    if (index < 0) return;
    const moves = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    let next = null;
    if (event.key in moves) next = list[(index + moves[event.key] + list.length) % list.length];
    else if (event.key === 'Home') next = list[0];
    else if (event.key === 'End') next = list[list.length - 1];
    if (!next) return;
    event.preventDefault();
    next.focus();
    select(next);
  });
  const initial = items().find((i) => i.getAttribute('aria-checked') === 'true') || items()[0];
  if (initial) select(initial, false);
  return {
    setValue(value) {
      const item = items().find((i) => i.dataset.value === String(value));
      if (item) select(item, false);
    },
  };
}

// ---------- Panel lateral del flujo (consola y simulación) ----------

let panel = null;

function realClass(flow) {
  return (flow.true_label === 1 ? 'Ataque' : 'Normal');
}

function flowSummary(flow, hasLabels, threshold) {
  return [
    h('div', { class: 'drawer-summary sev-' + flow.severity },
      h('div', {}, h('div', { class: 'lbl' }, 'Probabilidad de ataque'), h('div', { class: 'big' }, formatPercent(flow.attack_probability))),
      h('div', { class: 'side' }, severityBadge(flow.severity),
        threshold === null || threshold === undefined ? null : h('span', {}, 'Umbral del modelo: ' + formatDecimal(threshold)))),
    h('dl', { class: 'kv' },
      h('dt', {}, 'ID'), h('dd', { class: 'mono' }, String(flow.id)),
      h('dt', {}, featureName('proto')), h('dd', { class: 'mono' }, formatValue(flow.proto)),
      h('dt', {}, featureName('service')), h('dd', { class: 'mono' }, formatValue(flow.service)),
      h('dt', {}, featureName('state')), h('dd', { class: 'mono' }, formatValue(flow.state)),
      h('dt', {}, 'Tipo probable'), h('dd', {}, flow.predicted_attack_cat ? attackType(flow.predicted_attack_cat) : '—'),
      hasLabels ? [
        h('div', { class: 'kv-sep' }),
        h('dt', {}, 'Clase real'), h('dd', {}, realClass(flow), ' · ', attackType(flow.true_attack_cat)),
        h('dt', {}, 'Resultado'), h('dd', {}, flowResult(flow)),
      ] : []),
  ];
}

function explanation(explained) {
  const title = h('h3', {}, 'Por qué el modelo decidió esto');
  if (!explained.can_explain) {
    return h('section', { class: 'stack' }, title, h('p', { class: 'help' }, 'Este modelo no explica sus decisiones.'));
  }
  const all = explained.contributions;
  const maxAbs = Math.max(...all.map((c) => Math.abs(c.contribution)), Number.EPSILON);
  const item = (c) => {
    const dir = c.contribution >= 0 ? 'pos' : 'neg';
    return h('li', { class: 'expl-item' },
      h('div', { class: 'expl-name' }, featureName(c.feature), h('span', { class: 'val' }, formatValue(c.value))),
      h('div', { class: 'expl-bar', 'aria-hidden': 'true' },
        h('span', { class: dir, style: 'width:' + ((Math.abs(c.contribution) / maxAbs) * 50).toFixed(1) + '%' })),
      h('div', { class: 'expl-c ' + dir }, formatSigned(c.contribution)));
  };
  const list = h('ol', { class: 'expl-list' });
  let showAll = false;
  const toggle = h('button', { type: 'button', class: 'link-btn' });
  const render = () => {
    list.replaceChildren(...(showAll ? all : all.slice(0, TOP_CONTRIBUTIONS)).map(item));
    toggle.textContent = showAll ? 'Ver solo las ' + TOP_CONTRIBUTIONS + ' principales' : 'Ver todas (' + all.length + ')';
    toggle.hidden = all.length <= TOP_CONTRIBUTIONS;
  };
  toggle.addEventListener('click', () => { showAll = !showAll; render(); });
  render();
  return h('section', { class: 'stack' }, title,
    h('p', { class: 'help' }, 'Las variables de mayor efecto en la probabilidad de ataque, de mayor a menor.'),
    h('div', { class: 'expl-legend' },
      h('span', { class: 'to-normal' }, icon('arrow-left', { size: 'sm' }), 'Empuja hacia «normal»'),
      h('span', { class: 'to-attack' }, 'Empuja hacia «ataque»', icon('arrow-right', { size: 'sm' }))),
    list, h('div', {}, toggle));
}

function onPanelKey(event) {
  if (event.key === 'Escape') closeFlowPanel();
}

// Abre el panel de un flujo. Si se pasa flow, se muestra al instante; la explicación se pide a la API.
// actions: botones extra [{label, icon, onClick}] o enlaces [{label, icon, href}].
export function openFlowPanel({ analysisId, flowId, flow = null, hasLabels = null, threshold = null, actions = [], onClose = null }) {
  closeFlowPanel({ restoreFocus: false });
  const opener = document.activeElement;
  const title = h('h2', { id: 'drawerTitle', tabindex: '-1' }, 'Flujo ' + flowId);
  const summary = h('div', { class: 'stack' });
  const details = h('div', { class: 'stack' }, h('div', { class: 'loader', role: 'status' },
    h('div', { class: 'loader-bar' }, h('span')), h('p', { class: 'help' }, 'Calculando la explicación…')));
  const extra = actions.map((a) => (a.href
    ? h('a', { class: 'btn btn-secondary btn-sm', href: a.href }, a.icon ? icon(a.icon) : null, a.label)
    : h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: a.onClick }, a.icon ? icon(a.icon) : null, a.label)));
  const drawer = h('aside', { class: 'drawer', 'aria-labelledby': 'drawerTitle' },
    h('div', { class: 'drawer-head' }, title, iconButton('x', 'Cerrar el panel del flujo', { onclick: () => closeFlowPanel() })),
    h('div', { class: 'drawer-body' }, summary, details,
      h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => copyLink(flowLink(analysisId, flowId)) },
          icon('link'), 'Copiar enlace a este flujo'),
        extra)));
  const backdrop = h('div', { class: 'backdrop', onclick: () => closeFlowPanel() });
  document.body.append(backdrop, drawer);
  document.addEventListener('keydown', onPanelKey);
  const token = {};
  panel = { drawer, backdrop, opener, onClose, token };

  const labelsFor = (f) => (hasLabels === null ? f.true_label !== null : hasLabels);
  if (flow) summary.replaceChildren(...flowSummary(flow, labelsFor(flow), threshold));
  title.focus();

  explainFlow(analysisId, flowId).then((explained) => {
    if (!panel || panel.token !== token) return;
    summary.replaceChildren(...flowSummary(explained.flow, labelsFor(explained.flow), threshold));
    details.replaceChildren(explanation(explained));
  }).catch((error) => {
    if (!panel || panel.token !== token) return;
    details.replaceChildren(errorNotice(error));
  });
}

export function closeFlowPanel({ restoreFocus = true } = {}) {
  if (!panel) return;
  const { drawer, backdrop, opener, onClose } = panel;
  panel = null;
  drawer.remove();
  backdrop.remove();
  document.removeEventListener('keydown', onPanelKey);
  if (restoreFocus && opener && document.contains(opener)) opener.focus();
  if (onClose) onClose();
}
