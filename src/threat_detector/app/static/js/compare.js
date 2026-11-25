// Modelos: métricas oficiales de cada modelo (GET /api/metrics), comparación y elección del modelo.
// Muestra las métricas de la API sin recalcularlas; solo las ordena y marca el mejor valor.
import {
  ATTACK_TYPE_DESCRIPTIONS, attackType, errorNotice, fetchMetrics, formatDecimal, formatInt,
  formatPercent, formatScore, getChosenModel, h, icon, initHeader, initPage, setChosenModel,
  showToast,
} from './common.js';

const $ = (id) => document.getElementById(id);
const state = { models: null, entries: [], selected: null };

// ---------- Formato ----------

function formatSeconds(seconds) {
  if (seconds < 60) return formatDecimal(seconds, 1) + ' s';
  const minutes = Math.floor(seconds / 60);
  return minutes + ' min ' + String(Math.round(seconds - minutes * 60)).padStart(2, '0') + ' s';
}

const complexityOf = (entry) => entry.metrics.complexity;

// Filas de la comparación. dir: 'max' o 'min' si se marca el mejor valor; null si no.
const GROUPS = [
  {
    title: 'Detección de ataques',
    rows: [
      { label: 'Detección (recall)', get: (e) => e.metrics.detection.detection_rate, format: formatPercent, dir: 'max' },
      { label: 'Falsas alarmas', get: (e) => e.metrics.detection.false_alarm_rate, format: formatPercent, dir: 'min' },
      { label: 'Precisión', get: (e) => e.metrics.detection.precision, format: formatPercent, dir: 'max' },
      { label: 'F1', get: (e) => e.metrics.detection.f1, format: formatScore, dir: 'max' },
      { label: 'PR-AUC', get: (e) => e.metrics.detection.pr_auc, format: formatScore, dir: 'max' },
      { label: 'ROC-AUC', get: (e) => e.metrics.detection.roc_auc, format: formatScore, dir: 'max' },
      { label: 'Exactitud (solo referencia)', get: (e) => e.metrics.detection.accuracy, format: formatPercent, dir: null, secondary: true },
    ],
  },
  {
    title: 'Tipo de ataque',
    rows: [{ label: 'F1 macro (9 tipos)', get: (e) => e.metrics.attack_type.macro_f1, format: formatScore, dir: 'max' }],
  },
  {
    title: 'Umbral de alerta',
    rows: [{ label: 'Umbral', get: (e) => e.model.threshold, format: (v) => formatDecimal(v), dir: null }],
  },
  {
    title: 'Complejidad',
    complexity: true,
    rows: [
      { label: 'Tiempo de entrenamiento', get: (e) => complexityOf(e)?.training_seconds, format: formatSeconds, dir: 'min' },
      { label: 'Flujos de entrenamiento', get: (e) => complexityOf(e)?.training_flows, format: formatInt, dir: null },
      { label: 'Predicción por 1.000 flujos', get: (e) => complexityOf(e)?.prediction_ms_per_1000_flows, format: (v) => formatDecimal(v, 1) + ' ms', dir: 'min' },
      { label: 'Tamaño del modelo', get: (e) => complexityOf(e)?.model_size_mb, format: (v) => formatDecimal(v, 1) + ' MB', dir: 'min' },
      { label: 'Equipo usado', get: (e) => complexityOf(e)?.hardware, format: (v) => v, dir: null },
    ],
  },
];

// ---------- Elección del modelo ----------

const chosenName = () => getChosenModel(state.models)?.name;
const trained = () => state.entries.filter((e) => !e.model.is_mock);

function choose(entry) {
  setChosenModel(entry.model.name);
  initHeader(state.models);
  renderCards();
  renderComparison();
  showToast('Ahora la consola y la simulación usan «' + entry.model.display_name + '»');
}

// ---------- Tarjetas ----------

function mockTag() {
  return h('span', { class: 'tag tag-mock' }, icon('flask-conical', { size: 'sm' }), 'Simulado');
}

function feature(yes, textYes, textNo) {
  return h('span', { class: yes ? 'feature-yes' : 'feature-no' }, icon(yes ? 'check' : 'circle-minus'), yes ? textYes : textNo);
}

function renderCards() {
  const chosen = chosenName();
  const sameFlows = new Set(state.entries.map((e) => e.metrics.test_flows)).size === 1;
  $('modelCards').replaceChildren(...state.entries.map((entry) => {
    const { model, metrics } = entry;
    const inUse = model.name === chosen;
    return h('article', { class: 'card model-card' + (inUse ? ' is-active' : ''), 'aria-label': model.display_name },
      h('h3', {}, model.display_name, model.is_mock ? mockTag() : null),
      h('div', { class: 'model-tags' },
        feature(model.use_ttl, 'Usa variables de TTL', 'Sin variables de TTL'),
        feature(model.can_explain, 'Explica sus decisiones', 'No explica sus decisiones')),
      model.is_mock ? h('div', { class: 'notice notice-warn' }, icon('flask-conical'),
        h('p', {}, h('strong', {}, 'Métricas inventadas.'), ' No sirven para evaluar el modelo.')) : null,
      h('dl', { class: 'mini-metrics' },
        h('div', {}, h('dt', {}, 'Detección (recall)'), h('dd', {}, formatPercent(metrics.detection.detection_rate))),
        h('div', {}, h('dt', {}, 'Falsas alarmas'), h('dd', {}, formatPercent(metrics.detection.false_alarm_rate))),
        h('div', {}, h('dt', {}, 'PR-AUC'), h('dd', {}, formatScore(metrics.detection.pr_auc))),
        h('div', {}, h('dt', {}, 'Umbral'), h('dd', {}, formatDecimal(model.threshold)))),
      sameFlows ? null : h('p', { class: 'help' }, formatInt(metrics.test_flows) + ' flujos de prueba'),
      h('div', { class: 'card-action' }, inUse
        ? h('span', { class: 'in-use' }, icon('circle-check'), 'En uso en la consola y la simulación')
        : h('button', { type: 'button', class: 'btn btn-secondary btn-block', onclick: () => choose(entry) }, 'Usar este modelo')));
  }));
  $('testFlows').textContent = sameFlows && state.entries.length ? ' (' + formatInt(state.entries[0].metrics.test_flows) + ' flujos)' : '';
}

// ---------- Comparación lado a lado ----------

// Mejor valor de una fila: solo entre modelos entrenados y solo si hay al menos dos.
function bestValue(row) {
  if (!row.dir || trained().length < 2) return null;
  const values = trained().map(row.get).filter((v) => v !== null && v !== undefined);
  if (!values.length) return null;
  return row.dir === 'max' ? Math.max(...values) : Math.min(...values);
}

function renderComparison() {
  const chosen = chosenName();
  const head = h('thead', {}, h('tr', {},
    h('th', { scope: 'col' }, 'Métrica'),
    state.entries.map((e) => h('th', { scope: 'col' },
      h('span', { class: 'model-name' }, e.model.display_name,
        e.model.name === chosen ? h('span', { class: 'tag' }, 'En uso') : null,
        e.model.is_mock ? mockTag() : null)))));
  const body = h('tbody', {});
  for (const group of GROUPS) {
    body.append(h('tr', { class: 'group' }, h('td', { colspan: String(state.entries.length + 1) }, group.title)));
    for (const row of group.rows) {
      const best = bestValue(row);
      body.append(h('tr', { class: row.secondary ? 'secondary' : null },
        h('td', {}, row.label),
        state.entries.map((e) => {
          if (group.complexity && complexityOf(e) === null) return h('td', { class: 'na' }, 'No aplica');
          const value = row.get(e);
          if (value === null || value === undefined) return h('td', { class: 'na' }, '—');
          const isBest = best !== null && !e.model.is_mock && value === best;
          return h('td', { class: isBest ? 'best' : null },
            isBest ? [icon('star'), h('span', { class: 'sr-only' }, 'mejor valor: ')] : null, row.format(value));
        })));
    }
  }
  $('compareTable').replaceChildren(head, body);
  $('bestNote').textContent = trained().length < 2
    ? 'El mejor valor de cada métrica se marca cuando hay al menos dos modelos entrenados.'
    : 'La estrella marca el mejor valor entre los modelos entrenados; el modelo simulado no se compara.';
}

// ---------- Detalle por modelo ----------

function bar(label, value, format, ref = false) {
  return h('div', { class: 'hbar' + (ref ? ' ref' : '') },
    h('dt', {}, label),
    h('div', { class: 'track', 'aria-hidden': 'true' },
      value === null ? null : h('span', { class: 'fill', style: 'width:' + (value * 100).toFixed(1) + '%' })),
    h('dd', {}, value === null ? '—' : format(value)));
}

function detectionBlock(entry) {
  const d = entry.metrics.detection;
  const c = d.confusion;
  const cell = (n, label, good) => h('div', { class: 'cell ' + (good ? 'good' : 'bad') }, h('b', {}, formatInt(n)), h('span', {}, label));
  return h('div', { class: 'detail-block' },
    h('h3', {}, 'Detección de ataques'),
    h('dl', { class: 'hbars' },
      bar('Detección (recall)', d.detection_rate, formatPercent), bar('Falsas alarmas', d.false_alarm_rate, formatPercent),
      bar('Precisión', d.precision, formatPercent), bar('F1', d.f1, formatScore),
      bar('PR-AUC', d.pr_auc, formatScore), bar('ROC-AUC', d.roc_auc, formatScore),
      bar('Exactitud (referencia)', d.accuracy, formatPercent, true)),
    h('div', { class: 'cm2', role: 'table', 'aria-label': 'Matriz de confusión de la detección' },
      h('div', { role: 'row', style: 'display:contents' },
        h('span', { role: 'columnheader' }), h('span', { class: 'hd', role: 'columnheader' }, 'Predicho: ataque'),
        h('span', { class: 'hd', role: 'columnheader' }, 'Predicho: normal')),
      h('div', { role: 'row', style: 'display:contents' },
        h('span', { class: 'rh', role: 'rowheader' }, 'Real: ataque'),
        h('span', { role: 'cell', style: 'display:contents' }, cell(c.tp, 'Verdaderos positivos', true)),
        h('span', { role: 'cell', style: 'display:contents' }, cell(c.fn, 'Falsos negativos', false))),
      h('div', { role: 'row', style: 'display:contents' },
        h('span', { class: 'rh', role: 'rowheader' }, 'Real: normal'),
        h('span', { role: 'cell', style: 'display:contents' }, cell(c.fp, 'Falsos positivos', false)),
        h('span', { role: 'cell', style: 'display:contents' }, cell(c.tn, 'Verdaderos negativos', true)))));
}

function thresholdBlock(entry) {
  return h('div', { class: 'detail-block' },
    h('h3', {}, 'Umbral de alerta'),
    h('span', { class: 'threshold-value' }, formatDecimal(entry.model.threshold)),
    h('p', { class: 'help' }, 'El umbral de cada modelo se fija con los datos de validación para detectar al menos el 95 % de los ataques.'));
}

function complexityBlock(entry) {
  const c = complexityOf(entry);
  const content = c === null
    ? h('p', { class: 'help' }, 'No aplica: el modelo simulado no se entrena.')
    : h('dl', { class: 'complex' },
      h('div', {}, h('dt', {}, 'Tiempo de entrenamiento'), h('dd', {}, formatSeconds(c.training_seconds))),
      h('div', {}, h('dt', {}, 'Flujos de entrenamiento'), h('dd', {}, formatInt(c.training_flows))),
      h('div', {}, h('dt', {}, 'Predicción por 1.000 flujos'), h('dd', {}, formatDecimal(c.prediction_ms_per_1000_flows, 1) + ' ms')),
      h('div', {}, h('dt', {}, 'Tamaño del modelo'), h('dd', {}, formatDecimal(c.model_size_mb, 1) + ' MB')),
      h('div', {}, h('dt', {}, 'Equipo usado'), h('dd', {}, c.hardware)));
  return h('div', { class: 'detail-block' }, h('h3', {}, 'Complejidad'), content);
}

function typeBlock(entry) {
  const t = entry.metrics.attack_type;
  const f1 = (v) => (v === null ? '—' : h('span', { class: 'f1-cell' },
    h('span', { class: 'f1-bar', 'aria-hidden': 'true' }, h('span', { style: 'width:' + (v * 100).toFixed(1) + '%' })), formatScore(v)));
  return h('div', { class: 'detail-block' },
    h('h3', {}, 'Tipo de ataque ', h('small', {},
      'F1 macro ' + formatScore(t.macro_f1) + ' · medido sobre ' + formatInt(t.evaluated_flows) + ' ataques reales que dieron alerta')),
    h('div', { class: 'compare-wrap' }, h('table', { class: 'type-table' },
      h('thead', {}, h('tr', {}, ['Tipo', 'Precisión', 'Recall', 'F1', 'Flujos'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', {}, t.per_class.map((c) => h('tr', {},
        h('td', {}, attackType(c.attack_cat)),
        h('td', {}, formatPercent(c.precision)),
        h('td', {}, formatPercent(c.recall)),
        h('td', {}, f1(c.f1)),
        h('td', {}, formatInt(c.support))))))));
}

function matrixBlock(entry) {
  const { labels, matrix } = entry.metrics.attack_type.confusion;
  const table = h('table', { class: 'cm9' },
    h('caption', { class: 'sr-only' }, 'Matriz de confusión entre los 9 tipos de ataque: la fila es el tipo real y la columna el tipo predicho'),
    h('thead', {}, h('tr', {}, h('th', { class: 'axis', scope: 'col' }, 'Real ↓ · Predicho →'),
      labels.map((l) => h('th', { scope: 'col', title: ATTACK_TYPE_DESCRIPTIONS[l] || null }, l)))),
    h('tbody', {}, matrix.map((row, i) => {
      const total = row.reduce((sum, v) => sum + v, 0);
      return h('tr', {}, h('th', { scope: 'row' }, labels[i]), row.map((v, j) => h('td', {
        class: i === j ? 'diag' : null,
        // Intensidad = parte de la fila; el CSS la escala a --heat-max.
        style: '--share:' + (total ? v / total : 0).toFixed(4),
        title: labels[i] + ' → ' + labels[j] + ': ' + formatInt(v),
      }, formatInt(v))));
    })));
  return h('div', { class: 'detail-block' },
    h('h3', {}, 'Matriz de confusión 9×9 ', h('small', {}, 'tipo real contra tipo predicho')),
    h('div', { class: 'heat-legend' }, 'Menos', h('span', { class: 'ramp', 'aria-hidden': 'true' }), 'Más (parte de la fila)'),
    h('div', { class: 'cm9-wrap', tabindex: '0', role: 'region', 'aria-label': 'Matriz de confusión 9×9' }, table));
}

function renderTabs() {
  const tabs = $('tabs');
  tabs.replaceChildren(...state.entries.map((e) => h('button', {
    type: 'button', role: 'tab', id: 'tab-' + e.model.name, 'aria-controls': 'tabPanel',
    'aria-selected': String(e.model.name === state.selected), tabindex: e.model.name === state.selected ? '0' : '-1',
    onclick: () => selectTab(e.model.name),
  }, e.model.display_name)));
}

function selectTab(name, focus = false) {
  state.selected = name;
  renderTabs();
  const entry = state.entries.find((e) => e.model.name === name);
  $('tabPanel').setAttribute('aria-labelledby', 'tab-' + name);
  $('tabPanel').replaceChildren(h('div', { class: 'detail-grid' },
    h('div', {}, detectionBlock(entry), thresholdBlock(entry), complexityBlock(entry)),
    h('div', {}, typeBlock(entry), matrixBlock(entry))));
  if (focus) $('tab-' + name).focus();
}

function wireTabs() {
  $('tabs').addEventListener('keydown', (event) => {
    const names = state.entries.map((e) => e.model.name);
    const index = names.indexOf(state.selected);
    const moves = { ArrowRight: 1, ArrowLeft: -1 };
    let next = null;
    if (event.key in moves) next = names[(index + moves[event.key] + names.length) % names.length];
    else if (event.key === 'Home') next = names[0];
    else if (event.key === 'End') next = names[names.length - 1];
    if (next === null) return;
    event.preventDefault();
    selectTab(next, true);
  });
}

// ---------- Inicio ----------

async function load() {
  $('modelsStatus').replaceChildren(h('div', { class: 'loader', role: 'status' },
    h('div', { class: 'loader-bar' }, h('span')), h('p', { class: 'help' }, 'Cargando las métricas…')));
  try {
    const metrics = await fetchMetrics();
    state.entries = state.models.models.map((model) => ({
      model, metrics: metrics.models.find((m) => m.name === model.name),
    })).filter((e) => e.metrics);
    state.selected = chosenName() || state.entries[0]?.model.name;
    $('modelsStatus').replaceChildren();
    renderCards();
    renderComparison();
    selectTab(state.selected);
    $('modelsContent').hidden = false;
  } catch (error) {
    $('modelsStatus').replaceChildren(errorNotice(error, { actionLabel: 'Reintentar', onAction: load }));
  }
}

async function start() {
  wireTabs();
  state.models = await initPage();
  if (state.models) load();
}

start();
