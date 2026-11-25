// Simulación: reproduce un análisis flujo a flujo por WebSocket (contrato, sección 8) y lo anima.
// Solo muestra y cuenta lo que llega por el WebSocket; las tasas salen de GET /api/analysis al terminar.
import {
  ALERT_SEVERITIES, ApiError, SEVERITIES, attackType, errorNotice, fetchAnalysis, flowLink,
  formatInt, formatPercent, getChosenModel, h, icon, initPage, initRadioGroup, isMockModel,
  isSampleAnalysis, kpiCard, mockNotice, modelName, networkError, openFlowPanel, rateTips,
  sampleAnalysisId, severityBadge, simulationUrl, formatDecimal, formatValue, valueTitle,
} from './common.js';

// Pausa entre flujos a velocidad 1×, en ms (contrato, sección 8: 1 segundo dividido entre speed).
const INTERVAL_MS = 1000;
// El viaje de un punto dura esta parte de la pausa entre flujos, para que no se acumulen.
const TRAVEL_SHARE = 0.8;
// Partes del viaje: hasta el modelo, dentro del modelo (oculto) y hacia el destino.
const LEG_IN = 0.4;
const LEG_MODEL = 0.2;
const LOG_SIZE = 50;
// Cada cuántos flujos se actualiza el mensaje para lectores de pantalla.
const LIVE_EVERY = 10;
const SVG_NS = 'http://www.w3.org/2000/svg';

const $ = (id) => document.getElementById(id);
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const narrow = window.matchMedia('(max-width: 760px)');

const state = {
  models: null,
  analysisId: null,
  analysis: null,
  fromMenu: false,
  labeled: true,
  ws: null,
  phase: 'idle', // idle, connecting, playing, paused, ended, error
  speed: 1,
  total: 0,
  sent: 0, // posición del último mensaje recibido
  shown: 0, // flujos ya aplicados (llegaron a su destino)
  counts: null,
  log: [],
  lastAlert: null,
  endPending: false,
  resumeAfterPanel: false,
};

// ---------- Escenario ----------

// Coordenadas del escenario: horizontal en pantallas anchas y vertical en celular.
const GEOMETRY = {
  wide: {
    viewBox: '0 0 960 280',
    file: { x: 16, y: 110, w: 170, h: 60 },
    model: { x: 400, y: 100, w: 170, h: 80 },
    alerts: { x: 780, y: 24, w: 164, h: 84 },
    normal: { x: 780, y: 172, w: 164, h: 84 },
    laneIn: 'M186 140 H400',
    through: 'M400 140 H570',
    laneAlerts: 'M570 140 C660 140 680 66 780 66',
    laneNormal: 'M570 140 C660 140 680 214 780 214',
  },
  tall: {
    viewBox: '0 0 360 470',
    file: { x: 95, y: 10, w: 170, h: 60 },
    model: { x: 95, y: 160, w: 170, h: 80 },
    alerts: { x: 12, y: 380, w: 160, h: 84 },
    normal: { x: 188, y: 380, w: 160, h: 84 },
    laneIn: 'M180 70 V160',
    through: 'M180 160 V240',
    laneAlerts: 'M180 240 C180 320 92 300 92 380',
    laneNormal: 'M180 240 C180 320 268 300 268 380',
  },
};

const stage = { svg: null, paths: null, texts: null, dotLayer: null, model: null };
const dots = [];
let clock = 0; // tiempo de la animación en ms; solo avanza mientras se reproduce
let lastFrame = null;
let lastArrival = 0;
let frameRequested = false;

function svgEl(tag, attrs = {}, text = null) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  if (text !== null) el.textContent = text;
  return el;
}

function node(box, cls, title, sub, count) {
  const g = svgEl('g', { class: 'stage-node ' + cls });
  g.append(svgEl('rect', { x: box.x, y: box.y, width: box.w, height: box.h, rx: 10 }));
  const cx = box.x + box.w / 2;
  const titleEl = svgEl('text', { x: cx, y: box.y + (count ? 26 : box.h / 2 - 2) }, title);
  g.append(titleEl);
  let valueEl;
  if (count) valueEl = svgEl('text', { x: cx, y: box.y + box.h - 18, class: 'count' }, '0');
  else valueEl = svgEl('text', { x: cx, y: box.y + box.h / 2 + 18, class: 'sub' }, sub);
  g.append(valueEl);
  return { g, valueEl, titleEl };
}

function shortName(text, max = 22) {
  return text.length > max ? text.slice(0, max - 1) + '…' : text;
}

function buildStage() {
  // Al cambiar de forma, los puntos en camino llegan de inmediato.
  finishDots();
  const geo = narrow.matches ? GEOMETRY.tall : GEOMETRY.wide;
  const svg = svgEl('svg', { viewBox: geo.viewBox, focusable: 'false' });
  const lane = (d, extra = '') => svgEl('path', { d, class: 'stage-lane ' + extra });
  const paths = {
    in: lane(geo.laneIn, 'stage-lane-in'),
    through: svgEl('path', { d: geo.through, fill: 'none', stroke: 'none' }),
    alerts: lane(geo.laneAlerts),
    normal: lane(geo.laneNormal),
  };
  const dotLayer = svgEl('g');
  const file = node(geo.file, 'stage-file', 'Archivo', '0 en cola');
  const modelLabel = state.analysis ? shortName(state.analysis.model.display_name) : 'Modelo';
  const model = node(geo.model, 'stage-model', 'Modelo', modelLabel);
  const alerts = node(geo.alerts, 'stage-alerts', 'Alertas', null, true);
  const normal = node(geo.normal, 'stage-normal', 'Tráfico normal', null, true);
  // Los puntos van debajo de los nodos: dentro del modelo quedan ocultos.
  svg.append(paths.in, paths.alerts, paths.normal, paths.through, dotLayer, file.g, model.g, alerts.g, normal.g);
  $('stage').replaceChildren(svg);
  Object.assign(stage, {
    svg, paths, dotLayer, model: model.g,
    texts: { queue: file.valueEl, alerts: alerts.valueEl, normal: normal.valueEl },
  });
  renderStageCounts();
}

function renderStageCounts() {
  if (!stage.texts) return;
  stage.texts.queue.textContent = formatInt(Math.max(0, state.total - state.sent)) + ' en cola';
  stage.texts.alerts.textContent = formatInt(state.counts ? state.counts.alerts : 0);
  stage.texts.normal.textContent = formatInt(state.counts ? state.counts.normal : 0);
}

function renderLegend() {
  const item = (label, cls) => h('span', { class: cls || null }, h('i', {}), label);
  $('legend').replaceChildren(
    item('Sin evaluar'),
    ...['critical', 'high', 'medium', 'low', 'normal'].map((sev) => item(SEVERITIES[sev].label, 'sev-' + sev)));
}

// Se anima solo si la persona no pidió menos movimiento y la pestaña está a la vista.
const shouldAnimate = () => !reducedMotion.matches && document.visibilityState === 'visible';

function pointAt(path, share) {
  const length = path.getTotalLength();
  return path.getPointAtLength(Math.max(0, Math.min(1, share)) * length);
}

function spawnDot(message) {
  const base = (INTERVAL_MS / state.speed) * TRAVEL_SHARE;
  // Un punto nunca llega antes que el anterior, aunque la velocidad haya subido.
  const duration = Math.max(base, lastArrival - clock + 30);
  const circle = svgEl('circle', { r: 7, class: 'sim-dot' });
  stage.dotLayer.append(circle);
  const dot = { message, circle, start: clock, duration };
  lastArrival = clock + duration;
  dots.push(dot);
  placeDot(dot, 0);
  requestFrame();
}

function placeDot(dot, t) {
  const { flow } = dot.message;
  let point;
  if (t < LEG_IN) {
    point = pointAt(stage.paths.in, t / LEG_IN);
    dot.circle.setAttribute('class', 'sim-dot');
  } else if (t < LEG_IN + LEG_MODEL) {
    point = pointAt(stage.paths.through, (t - LEG_IN) / LEG_MODEL);
  } else {
    const lane = flow.is_alert ? stage.paths.alerts : stage.paths.normal;
    point = pointAt(lane, (t - LEG_IN - LEG_MODEL) / (1 - LEG_IN - LEG_MODEL));
    dot.circle.setAttribute('class', 'sim-dot sev-' + flow.severity);
  }
  dot.circle.setAttribute('cx', point.x.toFixed(1));
  dot.circle.setAttribute('cy', point.y.toFixed(1));
}

function requestFrame() {
  if (!frameRequested) {
    frameRequested = true;
    window.requestAnimationFrame(frame);
  }
}

function frame(now) {
  frameRequested = false;
  const dt = lastFrame === null ? 0 : Math.min(100, now - lastFrame);
  lastFrame = now;
  if (state.phase === 'playing') clock += dt;
  let busy = false;
  for (const dot of [...dots]) {
    const t = (clock - dot.start) / dot.duration;
    if (t >= 1) {
      removeDot(dot);
      arrive(dot.message);
    } else {
      placeDot(dot, t);
      busy = busy || (t >= LEG_IN && t < LEG_IN + LEG_MODEL);
    }
  }
  stage.model.classList.toggle('is-busy', busy);
  // En pausa los puntos quedan quietos y no se piden más cuadros; resume() vuelve a pedirlos.
  if (dots.length && state.phase === 'playing') requestFrame();
  else lastFrame = null;
}

function removeDot(dot) {
  dot.circle.remove();
  dots.splice(dots.indexOf(dot), 1);
}

// Los puntos en camino llegan de inmediato, en orden.
function finishDots() {
  for (const dot of [...dots]) {
    removeDot(dot);
    arrive(dot.message);
  }
  if (stage.model) stage.model.classList.remove('is-busy');
}

// ---------- Llegada de un flujo a su destino ----------

function emptyCounts() {
  return { alerts: 0, normal: 0, ...Object.fromEntries(ALERT_SEVERITIES.map((s) => [s, 0])) };
}

function arrive(message) {
  const { flow, position } = message;
  state.shown = Math.max(state.shown, position);
  if (flow.is_alert) {
    state.counts.alerts += 1;
    state.counts[flow.severity] += 1;
    state.lastAlert = message;
  } else {
    state.counts.normal += 1;
  }
  state.log.unshift(message);
  state.log.length = Math.min(state.log.length, LOG_SIZE);
  renderStageCounts();
  renderKpis();
  renderProgress();
  renderLog();
  renderLastAlert();
  if (state.shown % LIVE_EVERY === 0) announce();
  if (state.endPending && dots.length === 0) finish();
}

// ---------- WebSocket ----------

function connect() {
  closeSocket();
  resetProgress();
  state.phase = 'connecting';
  renderControls();
  $('simStatus').replaceChildren();
  let ws;
  try {
    ws = new WebSocket(simulationUrl());
  } catch {
    fail(networkError());
    return;
  }
  state.ws = ws;
  ws.addEventListener('open', () => ws.send(JSON.stringify({ type: 'start', analysis_id: state.analysisId, speed: state.speed })));
  ws.addEventListener('message', (event) => {
    if (state.ws !== ws) return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    handle(message);
  });
  ws.addEventListener('close', () => {
    if (state.ws !== ws) return;
    state.ws = null;
    // Sin "end" ni "error", la conexión se perdió.
    if (!['ended', 'error'].includes(state.phase) && !state.endPending) fail(networkError());
  });
}

function closeSocket() {
  const ws = state.ws;
  state.ws = null;
  if (ws && ws.readyState <= WebSocket.OPEN) ws.close();
}

function send(message) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send(JSON.stringify(message));
}

function handle(message) {
  if (message.type === 'started') {
    state.total = message.total_flows;
    state.phase = 'playing';
    renderControls();
    renderProgress();
    renderStageCounts();
  } else if (message.type === 'flow') {
    state.sent = message.position;
    renderStageCounts();
    if (shouldAnimate()) spawnDot(message);
    else arrive(message);
  } else if (message.type === 'end') {
    state.endPending = true;
    if (dots.length === 0) finish();
  } else if (message.type === 'error') {
    const { code, message: text, details } = message.error;
    fail(new ApiError(code, text, details ?? null));
  }
}

function fail(error) {
  finishDots();
  state.phase = 'error';
  state.endPending = false;
  closeSocket();
  $('simStatus').replaceChildren(errorNotice(error));
  renderControls();
  announce();
}

async function finish() {
  state.endPending = false;
  state.phase = 'ended';
  closeSocket();
  renderControls();
  announce();
  try {
    const analysis = await fetchAnalysis(state.analysisId);
    renderKpis(analysis);
  } catch (error) {
    $('simStatus').replaceChildren(errorNotice(error));
  }
}

// ---------- Controles ----------

const PLAY_LABELS = {
  idle: ['play', 'Iniciar'],
  connecting: ['play', 'Iniciar'],
  playing: ['pause', 'Pausar'],
  paused: ['play', 'Reanudar'],
  ended: ['rotate-ccw', 'Reproducir de nuevo'],
  error: ['rotate-ccw', 'Reproducir de nuevo'],
};

function renderControls() {
  const [iconName, label] = PLAY_LABELS[state.phase];
  const play = $('playBtn');
  play.replaceChildren(icon(iconName), label);
  play.disabled = !state.analysisId || state.phase === 'connecting';
  $('resetBtn').disabled = ['idle', 'connecting'].includes(state.phase);
  const running = ['connecting', 'playing', 'paused'].includes(state.phase);
  for (const radio of $('labelsMode').querySelectorAll('[role="radio"]')) radio.disabled = running;
}

function pause() {
  if (state.phase !== 'playing') return;
  send({ type: 'pause' });
  state.phase = 'paused';
  renderControls();
  announce();
}

function resume() {
  if (state.phase !== 'paused') return;
  send({ type: 'resume' });
  state.phase = 'playing';
  renderControls();
  requestFrame();
}

function onPlay() {
  if (state.phase === 'idle' || state.phase === 'ended' || state.phase === 'error') connect();
  else if (state.phase === 'playing') pause();
  else if (state.phase === 'paused') resume();
}

function renderSpeedHelp() {
  $('speedHelp').textContent = state.speed === 1 ? '1 flujo por segundo' : state.speed + ' flujos por segundo';
}

function resetProgress() {
  for (const dot of [...dots]) removeDot(dot);
  clock = 0;
  lastArrival = 0;
  Object.assign(state, { sent: 0, shown: 0, counts: emptyCounts(), log: [], lastAlert: null, endPending: false });
  if (state.analysis) state.total = state.analysis.summary.total_flows;
  renderStageCounts();
  renderKpis();
  renderProgress();
  renderLog();
  renderLastAlert();
}

// ---------- Indicadores, progreso, registro y última alerta ----------

const kpi = kpiCard;

// finished solo llega al terminar: el análisis completo, con sus tasas y sus flujos.
function renderKpis(finished = null) {
  const counts = state.counts || emptyCounts();
  const labels = state.analysis ? state.analysis.has_labels : true;
  const tips = finished && labels ? rateTips(finished.flows) : null;
  const rate = (key, label, ok, emptyText, tipKey, tipSide) => {
    if (!finished) return kpi({ label, labeled: true, value: null, sub: 'Se calcula al terminar' });
    const value = finished.summary[key];
    return kpi({
      label, labeled: true, value: value === null ? null : formatPercent(value),
      sub: !labels ? 'Requiere etiquetas reales' : value === null ? emptyText : ok,
      tip: tips && value !== null ? tips[tipKey] : null, tipSide,
    });
  };
  $('kpis').replaceChildren(
    kpi({ label: 'Flujos recibidos', value: formatInt(state.shown), sub: 'de ' + formatInt(state.total) }),
    kpi({ label: 'Alertas', value: formatInt(counts.alerts) }),
    ...ALERT_SEVERITIES.map((sev) => kpi({ label: SEVERITIES[sev].label, value: formatInt(counts[sev]), sev })),
    rate('detection_rate', 'Detección', 'de los ataques reales', 'No hay ataques reales en el archivo', 'detection', 'start'),
    rate('false_alarm_rate', 'Falsas alarmas', 'de los flujos normales', 'No hay flujos normales en el archivo', 'falseAlarm', 'end'));
}

function renderProgress() {
  $('progressText').textContent = formatInt(state.shown) + ' / ' + formatInt(state.total);
  const bar = $('progressBar');
  bar.setAttribute('aria-valuemax', String(state.total));
  bar.setAttribute('aria-valuenow', String(state.shown));
  bar.firstElementChild.style.width = (state.total ? (state.shown / state.total) * 100 : 0).toFixed(1) + '%';
}

// Protocolo, servicio y estado de un flujo, como se muestran (formatValue escribe "vacío" si falta).
function flowMeta(flow) {
  return [formatValue(flow.proto, 'proto'), formatValue(flow.service, 'service'), formatValue(flow.state, 'state')].join(' · ');
}

function logItem(message) {
  const { flow, position } = message;
  return h('li', { class: 'tl-item sev-' + flow.severity + (flow.is_alert ? ' is-alert' : ' is-normal') },
    h('button', {
      type: 'button', class: 'tl-btn', 'aria-label': 'Flujo ' + flow.id + ', ' + SEVERITIES[flow.severity].label + ': ver detalle',
      onclick: () => showDetail(message),
    },
    h('span', { class: 'tl-pos' }, '#' + formatInt(position)),
    h('span', { class: 'tl-id' }, 'id ' + flow.id),
    severityBadge(flow.severity),
    h('span', { class: 'tl-main' },
      h('span', { class: 'tl-type' }, flow.predicted_attack_cat ? attackType(flow.predicted_attack_cat) : 'Sin alerta'),
      h('span', { class: 'tl-meta', title: valueTitle(flow.proto, 'proto') }, flowMeta(flow))),
    h('span', { class: 'tl-prob' }, formatPercent(flow.attack_probability))));
}

function renderLog() {
  $('logList').replaceChildren(...state.log.map(logItem));
  $('logEmpty').hidden = state.log.length > 0;
}

function renderLastAlert() {
  const box = $('lastAlert');
  const eyebrow = h('span', { class: 'eyebrow' }, 'Última alerta');
  if (!state.lastAlert) {
    box.replaceChildren(eyebrow, h('p', { class: 'help' }, 'Todavía no hay alertas.'));
    return;
  }
  const { flow } = state.lastAlert;
  box.replaceChildren(eyebrow,
    h('h3', {}, attackType(flow.predicted_attack_cat), h('span', { class: 'mono' }, '#' + flow.id)),
    h('div', { class: 'btn-row' }, severityBadge(flow.severity), h('span', { class: 'mono' }, formatPercent(flow.attack_probability))),
    h('p', { class: 'help mono', title: valueTitle(flow.proto, 'proto') }, flowMeta(flow)),
    h('div', {}, h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => showDetail(state.lastAlert) },
      'Ver detalle de la alerta')));
}

// Un solo mensaje de estado para lectores de pantalla, sin anunciar cada flujo.
function announce() {
  const base = 'Flujo ' + formatInt(state.shown) + ' de ' + formatInt(state.total) + ' · ' + formatInt(state.counts ? state.counts.alerts : 0) + ' alertas';
  const suffix = { paused: ' · en pausa', ended: ' · simulación terminada', error: ' · simulación detenida' }[state.phase] || '';
  $('simLive').textContent = base + suffix;
}

// ---------- Panel del flujo ----------

function showDetail(message) {
  const { flow } = message;
  state.resumeAfterPanel = state.phase === 'playing';
  pause();
  openFlowPanel({
    analysisId: state.analysisId, flowId: flow.id, flow,
    hasLabels: state.analysis ? state.analysis.has_labels : null,
    threshold: state.analysis ? state.analysis.model.threshold : null,
    actions: [{ label: 'Abrir en la cola de alertas', icon: 'list', href: flowLink(state.analysisId, flow.id) }],
    onClose: () => {
      if (state.resumeAfterPanel) resume();
      state.resumeAfterPanel = false;
    },
  });
}

// ---------- Análisis que se reproduce ----------

function renderBar() {
  const a = state.analysis;
  const name = isSampleAnalysis(a.analysis_id) ? 'Muestra de demostración' : 'Archivo subido';
  const sep = () => h('span', { class: 'sep', 'aria-hidden': 'true' });
  $('analysisBar').replaceChildren(
    h('span', {}, 'Análisis: ', h('strong', {}, name)), sep(),
    h('span', {}, formatInt(a.summary.total_flows) + ' flujos'), sep(),
    h('span', {}, a.has_labels ? 'Con etiquetas' : 'Sin etiquetas'), sep(),
    h('span', {}, 'Modelo: ', h('strong', {}, modelName(state.models, a.model)), ' · umbral ' + formatDecimal(a.model.threshold)),
    h('span', { class: 'bar-actions' },
      h('a', { class: 'link-btn', href: 'index.html?analysis=' + encodeURIComponent(a.analysis_id) }, icon('list'), 'Abrir en la consola')));
  const mock = isMockModel(state.models, a.model.name) === true;
  $('mockSlot').replaceChildren(...(mock ? [mockNotice()] : []));
}

async function loadAnalysis(analysisId) {
  closeSocket();
  state.analysisId = analysisId;
  state.analysis = null;
  state.phase = 'idle';
  renderControls();
  try {
    state.analysis = await fetchAnalysis(analysisId);
    renderBar();
    buildStage();
    resetProgress();
    $('simStatus').replaceChildren();
  } catch (error) {
    state.analysisId = null;
    $('simStatus').replaceChildren(errorNotice(error));
  }
  renderControls();
}

// ---------- Inicio ----------

async function start() {
  renderLegend();
  state.counts = emptyCounts();
  buildStage();
  renderKpis();
  renderProgress();
  renderLog();
  renderLastAlert();
  renderSpeedHelp();
  renderControls();

  $('playBtn').addEventListener('click', onPlay);
  $('resetBtn').addEventListener('click', connect);
  initRadioGroup($('speeds'), (value) => {
    state.speed = Number(value);
    renderSpeedHelp();
    if (['playing', 'paused'].includes(state.phase)) send({ type: 'set_speed', speed: state.speed });
  });
  initRadioGroup($('labelsMode'), (value) => {
    state.labeled = value === 'labeled';
    const model = getChosenModel(state.models);
    if (model) loadAnalysis(sampleAnalysisId(model.name, state.labeled));
  });
  $('onlyAlerts').addEventListener('change', (event) => $('logList').classList.toggle('only-alerts', event.target.checked));
  narrow.addEventListener('change', buildStage);
  // Con la pestaña oculta el navegador frena las animaciones: los puntos en camino llegan de
  // inmediato y los mensajes siguientes se aplican al llegar, hasta que la pestaña vuelva.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') finishDots();
  });
  reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) finishDots(); });

  state.models = await initPage();
  const linked = new URLSearchParams(window.location.search).get('analysis');
  if (linked) {
    await loadAnalysis(linked);
  } else if (state.models) {
    state.fromMenu = true;
    $('labelsMode').hidden = false;
    await loadAnalysis(sampleAnalysisId(getChosenModel(state.models).name, true));
  }
}

start();
