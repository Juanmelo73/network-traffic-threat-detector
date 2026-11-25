// Consola: carga de un archivo o de la muestra, indicadores, cola de alertas y panel del flujo.
// No calcula alertas, severidades ni métricas: muestra lo que devuelve la API, y solo filtra,
// ordena, pagina y cuenta.
import {
  ALERT_SEVERITIES, SEVERITIES, attackType, closeFlowPanel, copyLink, errorNotice, featureName,
  fetchAnalysis, flowResult, formatDecimal, formatInt, formatPercent, getChosenModel, h, icon,
  initPage, initRadioGroup, isMockModel, isSampleAnalysis, kpiCard, mockNotice, modelName, openFlowPanel,
  predict, probability, rateTips, severityBadge, formatValue, valueTitle, isLabeledSample, sampleAnalysisId,
} from './common.js';

const PAGE_SIZE = 25;
const FILTERS = [
  { value: 'alerts', label: 'Todas las alertas', test: (f) => f.is_alert },
  ...ALERT_SEVERITIES.map((sev) => ({ value: sev, label: SEVERITIES[sev].label, icon: SEVERITIES[sev].icon, test: (f) => f.severity === sev })),
  { value: 'all', label: 'Todos los flujos', test: () => true },
];

const $ = (id) => document.getElementById(id);
const state = {
  models: null,
  analysis: null,
  fileName: null,
  byFile: [],
  byProbability: [],
  filter: 'alerts',
  sort: 'probability',
  page: 1,
  selectedId: null,
  busy: false,
};
let filterGroup = null;

// ---------- Dirección de la página ----------

function setUrl({ analysis = null, flow = null }) {
  const params = new URLSearchParams();
  if (analysis) params.set('analysis', analysis);
  if (flow !== null && flow !== undefined) params.set('flow', flow);
  const query = params.toString();
  window.history.replaceState(null, '', 'index.html' + (query ? '?' + query : ''));
}

// ---------- Último análisis de la pestaña ----------

// La consola recuerda su último análisis en sessionStorage (memoria de la pestaña, se borra al
// cerrarla), para mostrarlo de nuevo al volver por el menú o el logo, que abren index.html sin
// ?analysis=. Si el navegador bloquea el almacenamiento, la consola abre vacía.
const LAST_ANALYSIS_KEY = 'ntd-console-analysis';

function readLastAnalysis() {
  try {
    return JSON.parse(window.sessionStorage.getItem(LAST_ANALYSIS_KEY)) || null;
  } catch {
    return null;
  }
}

function saveLastAnalysis(analysisId, fileName) {
  try {
    window.sessionStorage.setItem(LAST_ANALYSIS_KEY, JSON.stringify({ analysisId, fileName }));
  } catch {
    // Sin almacenamiento: al volver por el menú la consola abre vacía.
  }
}

function forgetLastAnalysis() {
  try {
    window.sessionStorage.removeItem(LAST_ANALYSIS_KEY);
  } catch {
    // Nada que borrar.
  }
}

// ---------- Carga ----------

function setBusy(busy) {
  state.busy = busy;
  for (const id of ['sampleLabeled', 'sampleUnlabeled']) $(id).disabled = busy;
  $('dropzone').setAttribute('aria-disabled', String(busy));
  if (busy) {
    $('uploadStatus').replaceChildren(h('div', { class: 'loader', role: 'status' },
      h('div', { class: 'loader-bar' }, h('span')), h('p', { class: 'help' }, 'Analizando el archivo…')));
  }
}

async function analyze({ file = null, useSample = false, useLabels = true }) {
  if (state.busy) return;
  setBusy(true);
  const model = state.models ? getChosenModel(state.models) : null;
  try {
    const analysis = await predict({ file, useSample, useLabels, model: model ? model.name : null });
    state.fileName = file ? file.name : null;
    $('uploadStatus').replaceChildren(h('div', { class: 'notice notice-ok', role: 'status' }, icon('circle-check'),
      h('p', {}, h('strong', {}, 'Análisis listo. '),
        formatInt(analysis.summary.total_flows) + ' flujos analizados, ' + formatInt(analysis.summary.alerts) + ' alertas.')));
    showAnalysis(analysis);
    setUrl({ analysis: analysis.analysis_id });
    saveLastAnalysis(analysis.analysis_id, state.fileName);
  } catch (error) {
    $('uploadStatus').replaceChildren(errorNotice(error));
  } finally {
    setBusy(false);
  }
}

// La muestra sigue al modelo elegido: si el análisis pedido es la muestra de otro modelo, se abre la
// del modelo elegido, en el mismo modo (con o sin etiquetas). Los id de los flujos son los mismos en
// todas las muestras, así que &flow= sigue abriendo el mismo flujo. Un archivo subido no cambia:
// no se puede volver a analizar sin el archivo.
function followChosenModel(analysisId) {
  const chosen = state.models ? getChosenModel(state.models) : null;
  if (!chosen || !isSampleAnalysis(analysisId)) return analysisId;
  return sampleAnalysisId(chosen.name, isLabeledSample(analysisId));
}

// Abre un análisis ya hecho: por enlace (?analysis=) o el último de la pestaña.
async function loadFromLink(requestedId, flowParam) {
  const analysisId = followChosenModel(requestedId);
  setBusy(true);
  // El nombre del archivo solo lo conoce esta pestaña: se recupera si es el mismo análisis.
  const last = readLastAnalysis();
  state.fileName = last && last.analysisId === analysisId ? last.fileName : null;
  try {
    const analysis = await fetchAnalysis(analysisId);
    $('uploadStatus').replaceChildren();
    showAnalysis(analysis);
    setUrl({ analysis: analysisId });
    saveLastAnalysis(analysisId, state.fileName);
    if (flowParam !== null) openFromLink(flowParam);
  } catch (error) {
    if (error.code === 'analysis_not_found' && last && last.analysisId === analysisId) forgetLastAnalysis();
    $('uploadStatus').replaceChildren(errorNotice(error));
  } finally {
    setBusy(false);
  }
}

function wireUpload() {
  const dropzone = $('dropzone');
  const input = $('fileInput');
  const pick = () => { if (!state.busy) input.click(); };
  const useLabels = () => $('labelsSwitch').getAttribute('aria-checked') === 'true';

  dropzone.addEventListener('click', pick);
  dropzone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); pick(); }
  });
  input.addEventListener('change', () => {
    const file = input.files[0];
    input.value = '';
    if (file) analyze({ file, useLabels: useLabels() });
  });
  dropzone.addEventListener('dragover', (event) => { event.preventDefault(); dropzone.classList.add('is-over'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('is-over'));
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('is-over');
    const file = event.dataTransfer.files[0];
    if (file) analyze({ file, useLabels: useLabels() });
  });
  $('sampleLabeled').addEventListener('click', () => analyze({ useSample: true, useLabels: true }));
  $('sampleUnlabeled').addEventListener('click', () => analyze({ useSample: true, useLabels: false }));
  $('labelsSwitch').addEventListener('click', (event) => {
    const sw = event.currentTarget;
    sw.setAttribute('aria-checked', String(sw.getAttribute('aria-checked') !== 'true'));
  });
}

// ---------- Análisis ----------

const isSample = (analysis) => isSampleAnalysis(analysis.analysis_id);

function showAnalysis(analysis) {
  closeFlowPanel({ restoreFocus: false });
  state.analysis = analysis;
  state.selectedId = null;
  state.byFile = analysis.flows.map((_, i) => i);
  // Array.prototype.sort es estable: con la misma probabilidad se conserva el orden del archivo.
  state.byProbability = [...state.byFile].sort(
    (a, b) => analysis.flows[b].attack_probability - analysis.flows[a].attack_probability);
  state.filter = 'alerts';
  state.sort = 'probability';
  state.page = 1;
  $('sortSelect').value = 'probability';
  filterGroup.setValue('alerts');

  renderBar();
  const mock = isMockModel(state.models, analysis.model.name) === true;
  $('mockSlot').replaceChildren(...(mock ? [mockNotice()] : []));
  renderModelNotice();
  renderKpis();
  $('sampleNote').hidden = !isSample(analysis);
  renderFilterCounts();
  renderQueue();
  $('results').hidden = false;
}

// Elegir otro modelo no cambia un archivo ya analizado (la muestra sí cambia: followChosenModel).
// Si el análisis abierto se hizo con un modelo distinto del elegido, el título del resumen dice con
// qué modelo se hizo y un aviso explica cómo analizarlo con el elegido.
function renderModelNotice() {
  const a = state.analysis;
  const chosen = state.models ? getChosenModel(state.models) : null;
  const other = chosen !== null && chosen.name !== a.model.name;
  $('h-summary').textContent = 'Resumen del análisis' + (other ? ' con ' + a.model.display_name : '');
  if (!other) {
    $('modelSlot').replaceChildren();
    return;
  }
  $('modelSlot').replaceChildren(h('div', { class: 'notice notice-info', role: 'note' }, icon('info'),
    h('div', { class: 'stack' },
      h('p', {}, 'Este análisis se hizo con ', h('strong', {}, a.model.display_name),
        '. El modelo elegido ahora es ', h('strong', {}, chosen.display_name), ': los análisis nuevos lo usarán.'),
      h('p', {}, 'Para analizarlo con ' + chosen.display_name + ', vuelve a cargar el archivo.'))));
}

function renderBar() {
  const a = state.analysis;
  const name = isSample(a) ? 'Muestra de demostración' : (state.fileName || 'Archivo subido');
  const sep = () => h('span', { class: 'sep', 'aria-hidden': 'true' });
  $('analysisBar').replaceChildren(
    h('span', {}, 'Análisis: ', h('strong', {}, name)), sep(),
    h('span', {}, formatInt(a.summary.total_flows) + ' flujos'), sep(),
    h('span', {}, a.has_labels ? 'Con etiquetas' : 'Sin etiquetas'), sep(),
    h('span', {}, 'Modelo: ', h('strong', {}, modelName(state.models, a.model)), ' · umbral ' + formatDecimal(a.model.threshold)),
    h('span', { class: 'bar-actions' },
      h('button', { type: 'button', class: 'link-btn', onclick: () => copyLink('index.html?analysis=' + encodeURIComponent(a.analysis_id)) },
        icon('link'), 'Copiar enlace al análisis'),
      h('a', { class: 'link-btn', href: 'simulation.html?analysis=' + encodeURIComponent(a.analysis_id) },
        icon('activity'), 'Simular este análisis')));
}

const kpi = kpiCard;

function renderKpis() {
  const { summary, has_labels: labels, flows } = state.analysis;
  const tips = labels ? rateTips(flows) : null;
  // Con etiquetas y valor, la ayuda dice sobre qué flujos se calcula la tasa.
  const rate = (value, label, ok, emptyText, tip, tipSide) => kpi({
    label, labeled: true,
    value: value === null ? null : formatPercent(value),
    sub: !labels ? 'Requiere etiquetas reales' : value === null ? emptyText : ok,
    tip: labels && value !== null ? tip : null, tipSide,
  });
  $('kpis').replaceChildren(
    kpi({ label: 'Flujos analizados', value: formatInt(summary.total_flows) }),
    kpi({ label: 'Alertas', value: formatInt(summary.alerts), sub: 'de ' + formatInt(summary.total_flows) + ' flujos' }),
    ...ALERT_SEVERITIES.map((sev) => kpi({ label: SEVERITIES[sev].label, value: formatInt(summary.alerts_by_severity[sev]), sev })),
    rate(summary.detection_rate, 'Detección', 'de los ataques reales', 'No hay ataques reales en el archivo', tips?.detection, 'start'),
    rate(summary.false_alarm_rate, 'Falsas alarmas', 'de los flujos normales', 'No hay flujos normales en el archivo', tips?.falseAlarm, 'end'));
}

// ---------- Cola de alertas ----------

function buildFilters() {
  const group = $('filters');
  group.replaceChildren(...FILTERS.map((f) => h('button', {
    type: 'button', role: 'radio', class: 'chip' + (ALERT_SEVERITIES.includes(f.value) ? ' sev-' + f.value : ''),
    'aria-checked': String(f.value === 'alerts'), 'data-value': f.value,
  }, f.icon ? icon(f.icon) : null, f.label, ' ', h('span', { class: 'chip-n' }))));
  filterGroup = initRadioGroup(group, (value) => {
    state.filter = value;
    state.page = 1;
    renderQueue();
  });
}

function renderFilterCounts() {
  const { summary } = state.analysis;
  const counts = { alerts: summary.alerts, all: summary.total_flows, ...summary.alerts_by_severity };
  for (const chip of $('filters').querySelectorAll('[role="radio"]')) {
    chip.querySelector('.chip-n').textContent = formatInt(counts[chip.dataset.value]);
  }
}

function filteredIndices() {
  const { flows } = state.analysis;
  const order = state.sort === 'probability' ? state.byProbability : state.byFile;
  const filter = FILTERS.find((f) => f.value === state.filter);
  return order.filter((i) => filter.test(flows[i]));
}

function renderHead() {
  const th = (content, cls) => h('th', { scope: 'col', class: cls || null }, content);
  const labels = state.analysis.has_labels;
  return h('thead', {}, h('tr', {},
    th('ID'), th('Prob. de ataque', 'num'), th('Severidad'), th('Tipo probable'),
    th(featureName('proto')), th(featureName('service')), th(featureName('state')),
    labels ? [th('Clase real', 'col-labeled'), th('Tipo real', 'col-labeled'), th('Resultado', 'col-labeled')] : []));
}

function renderRow(flow) {
  const labels = state.analysis.has_labels;
  const empty = (v, feature) => (v === null ? h('span', { class: 'cell-empty' }, 'vacío') : formatValue(v, feature));
  const row = h('tr', {
    tabindex: '0', 'data-id': String(flow.id), 'aria-label': 'Flujo ' + flow.id + ', ' + SEVERITIES[flow.severity].label,
    class: flow.id === state.selectedId ? 'is-selected' : null,
  },
  h('td', { class: 'id' }, String(flow.id)),
  h('td', { class: 'num' }, probability(flow)),
  h('td', {}, severityBadge(flow.severity)),
  h('td', {}, flow.predicted_attack_cat ? attackType(flow.predicted_attack_cat) : h('span', { class: 'cell-empty' }, '—')),
  h('td', { class: 'cat', title: valueTitle(flow.proto, 'proto') }, empty(flow.proto, 'proto')),
  h('td', { class: 'cat' }, empty(flow.service)),
  h('td', { class: 'cat' }, empty(flow.state)),
  labels ? [
    h('td', { class: 'col-labeled' }, flow.true_label === 1 ? 'Ataque' : 'Normal'),
    h('td', { class: 'col-labeled' }, attackType(flow.true_attack_cat)),
    h('td', { class: 'col-labeled' }, flowResult(flow)),
  ] : []);
  row.addEventListener('click', () => openFlow(flow));
  row.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); openFlow(flow); }
  });
  return row;
}

function emptyState() {
  const sev = SEVERITIES[state.filter];
  if (sev) {
    return h('div', { class: 'empty' }, icon('circle-check'),
      h('p', {}, 'No hay alertas de severidad ' + sev.label.toLowerCase() + ' en este análisis.'),
      h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => selectFilter('alerts') }, 'Ver todas las alertas'));
  }
  return h('div', { class: 'empty' }, icon('circle-check'),
    h('p', {}, 'Este análisis no tiene alertas.'),
    h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => selectFilter('all') }, 'Ver todos los flujos'));
}

function selectFilter(value) {
  filterGroup.setValue(value);
  state.filter = value;
  state.page = 1;
  renderQueue();
}

function renderQueue() {
  const indices = filteredIndices();
  const total = indices.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  state.page = Math.min(Math.max(1, state.page), pages);
  const start = (state.page - 1) * PAGE_SIZE;
  const visible = indices.slice(start, start + PAGE_SIZE).map((i) => state.analysis.flows[i]);
  const noun = state.filter === 'all' ? 'flujos' : 'alertas';

  $('queueTable').replaceChildren(renderHead(), h('tbody', {}, visible.map(renderRow)));
  $('queueWrap').hidden = total === 0;
  $('pagination').hidden = total === 0;
  $('queueEmpty').hidden = total !== 0;
  $('queueEmpty').replaceChildren(...(total === 0 ? [emptyState()] : []));
  $('queueCount').textContent = total === 0 ? 'Sin ' + noun
    : 'Mostrando ' + formatInt(start + 1) + '–' + formatInt(start + visible.length) + ' de ' + formatInt(total) + ' ' + noun;
  $('pageInfo').textContent = 'Página ' + formatInt(state.page) + ' de ' + formatInt(pages);
  $('prevPage').disabled = state.page <= 1;
  $('nextPage').disabled = state.page >= pages;
}

function wireQueue() {
  buildFilters();
  $('sortSelect').addEventListener('change', (event) => {
    state.sort = event.target.value;
    state.page = 1;
    renderQueue();
  });
  $('prevPage').addEventListener('click', () => { state.page -= 1; renderQueue(); });
  $('nextPage').addEventListener('click', () => { state.page += 1; renderQueue(); });
}

// ---------- Panel del flujo ----------

function markSelected() {
  for (const row of $('queueTable').querySelectorAll('tbody tr')) {
    row.classList.toggle('is-selected', row.dataset.id === String(state.selectedId));
  }
}

function openFlow(flow, flowId = flow ? flow.id : null) {
  const a = state.analysis;
  // Primero se cierra el panel anterior: su onClose quita la marca y el flow de la dirección.
  closeFlowPanel({ restoreFocus: false });
  state.selectedId = flow ? flow.id : null;
  markSelected();
  setUrl({ analysis: a.analysis_id, flow: flowId });
  openFlowPanel({
    analysisId: a.analysis_id, flowId, flow, hasLabels: a.has_labels, threshold: a.model.threshold,
    onClose: () => {
      state.selectedId = null;
      markSelected();
      setUrl({ analysis: a.analysis_id });
    },
  });
}

// Enlace directo a un flujo: muestra su fila (filtro y página) y abre el panel.
function openFromLink(flowParam) {
  const { flows } = state.analysis;
  const index = flows.findIndex((f) => String(f.id) === flowParam);
  if (index < 0) {
    // No está en el análisis: el panel muestra el error flow_not_found de la API.
    openFlow(null, flowParam);
    return;
  }
  const flow = flows[index];
  selectFilter(flow.is_alert ? 'alerts' : 'all');
  state.page = Math.floor(filteredIndices().indexOf(index) / PAGE_SIZE) + 1;
  renderQueue();
  openFlow(flow);
}

// ---------- Inicio ----------

async function start() {
  wireUpload();
  wireQueue();
  state.models = await initPage();
  const params = new URLSearchParams(window.location.search);
  const analysisId = params.get('analysis');
  if (analysisId) {
    loadFromLink(analysisId, params.get('flow'));
  } else {
    // Sin ?analysis= (menú o logo): el último análisis de esta pestaña, si hay.
    const last = readLastAnalysis();
    if (last && last.analysisId) loadFromLink(last.analysisId, null);
  }
}

// Al volver con «Atrás», el navegador puede mostrar la página guardada sin ejecutarla de nuevo
// (bfcache): se recarga para que la muestra y la cabecera sigan al modelo elegido.
window.addEventListener('pageshow', (event) => {
  if (event.persisted) window.location.reload();
});

start();
