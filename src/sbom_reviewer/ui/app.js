'use strict';
const $ = id => document.getElementById(id);
let token = '', active = null, pending = false, dialogAction = null;
const outcomes = ['Allow', 'Needs review', 'Reject'];
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
function append(parent, ...children) { parent.append(...children); return parent; }
function badge(outcome) { return node('span', outcome, 'badge ' + outcome.toLowerCase().replaceAll(' ', '-')); }
function feedback(message, error = false) {
  $('status').textContent = message;
  $('status').className = 'status ' + (error ? 'error' : 'success');
}
function setBusy(value) {
  pending = value;
  document.querySelectorAll('button, #sbom, #saved, #fetch, #reviewer, #filter, #outcome, #reason').forEach(element => { element.disabled = value; });
  if (!value) $('run').disabled = !$('sbom').value;
  $('workspace').setAttribute('aria-busy', String(value));
}
async function api(path, body) {
  const options = body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Review-Token': token}, body: JSON.stringify(body)};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Local request failed.');
  return data;
}
function chooseOption(select, value, text) {
  const option = node('option', text === undefined ? value : text);
  option.value = value;
  select.append(option);
}
async function refresh() {
  const config = await api('/api/config');
  token = config.token;
  const previous = $('sbom').value;
  $('sbom').replaceChildren();
  if (!config.sboms.length) chooseOption($('sbom'), '', 'No JSON files in the configured directory');
  config.sboms.forEach(name => chooseOption($('sbom'), name));
  if (config.sboms.includes(previous)) $('sbom').value = previous;
  $('saved').replaceChildren();
  chooseOption($('saved'), '', 'Choose saved review…');
  config.reviews.slice().reverse().forEach(name => chooseOption($('saved'), name));
  if (active && config.reviews.includes(active.id)) $('saved').value = active.id;
  feedback('Local workspace ready · Policy ' + config.policy_version + ' · ' + config.sboms.length + ' JSON files');
}
function rememberReview(data) {
  active = data;
  if (![...$('saved').options].some(option => option.value === data.id)) chooseOption($('saved'), data.id);
  $('saved').value = data.id;
  render();
}
function summaryPanel(title, counts, progress) {
  const section = node('section', undefined, 'summary-panel');
  append(section, node('h3', title));
  const row = node('div', undefined, 'count-row');
  counts.forEach(([label, value]) => append(row, append(node('div', undefined, 'count'), node('strong', value), node('span', label))));
  section.append(row);
  if (progress) {
    const track = node('div', undefined, 'progress'), fill = node('span');
    fill.style.width = (progress.total ? 100 * progress.recorded / progress.total : 0) + '%';
    track.append(fill);
    append(section, track, node('p', progress.recorded + ' of ' + progress.total + ' reviewed · ' + progress.pending + ' pending', 'progress-note'));
  }
  return section;
}
function fields(values) {
  const list = node('dl');
  values.forEach(([label, value]) => append(list, node('dt', label), node('dd', value ?? 'Not supplied')));
  return list;
}
function safeReference(value) {
  if (!value) return node('span', 'No URL supplied');
  try {
    const parsed = new URL(value);
    if (!/^https?:\/\//i.test(value) || /[\s\\\x00-\x1f\x7f]/.test(value) || !['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) throw new Error('Unsafe reference');
    const link = node('a', value);
    link.href = parsed.href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  } catch (_) { return node('span', value); }
}
function excerpt(evidence) {
  const section = node('div');
  append(section, append(node('p'), node('span', 'Evidence document: '), safeReference(evidence.document_url)), node('p', 'Lines ' + evidence.line_start + '–' + evidence.line_end), node('pre', evidence.excerpt));
  return section;
}
function evidenceDetails(component) {
  const details = node('details', undefined, 'evidence');
  details.append(node('summary', 'Sources & model-card evidence'));
  const content = node('div');
  content.append(fields([['Component ID', component.component_id], ['BOM reference', component.bom_ref]]));
  content.append(node('strong', 'Original source references'));
  if (!component.sources.length) content.append(node('p', 'No source references supplied.'));
  component.sources.forEach(source => {
    const reference = node('p');
    append(reference, node('span', source.kind + ': '), safeReference(source.url), node('br'), node('span', 'Original pointer: ' + source.pointer));
    content.append(reference);
  });
  content.append(node('strong', 'Model-card assessment'));
  const assessment = component.model_assessment;
  if (!assessment) content.append(node('p', 'No model-card assessment saved. Model-card evidence was not fetched or inspected.'));
  else {
    content.append(fields([['Status', assessment.status], ['Document SHA-256', assessment.document_sha256], ['Card license', assessment.card_license], ['Normalized license', assessment.normalized_license], ['License-only policy decision', assessment.license_policy_decision]]));
    append(content, append(node('p'), node('span', 'Document: '), safeReference(assessment.document_url)));
    if (assessment.license_evidence) append(content, node('strong', 'License metadata evidence'), excerpt(assessment.license_evidence));
    assessment.findings.forEach(finding => {
      const block = node('div', undefined, 'finding');
      append(block, node('strong', finding.code), node('p', finding.message));
      if (finding.evidence) block.append(excerpt(finding.evidence));
      content.append(block);
    });
    if (!assessment.findings.length) content.append(node('p', 'No model-card findings saved.'));
  }
  details.append(content);
  return details;
}
function eventDetails(event) {
  return fields([['Event ID', event.event_id], ['Component ID', event.component_id], ['Action', event.action === 'confirm' ? 'Confirm recommendation' : 'Override'], ['Outcome', event.decision], ['Reviewer', event.reviewer], ['Rationale', event.reason], ['Recorded at (UTC)', event.recorded_at]]);
}
function openDecision(component, action, trigger) {
  if (pending) return;
  if (!$('reviewer').value.trim()) {
    feedback('Enter your reviewer name or ID before recording a decision.', true);
    $('reviewer').focus();
    return;
  }
  dialogAction = {component, action, trigger};
  $('dialog-title').textContent = action === 'confirm' ? 'Confirm recommendation' : 'Override recommendation';
  $('dialog-description').textContent = component.name + ' · Original machine recommendation: ' + component.decision + (action === 'confirm' ? '. Your confirmation preserves this outcome.' : '. Choose a different human outcome.');
  $('outcome-label').hidden = action === 'confirm';
  $('outcome').replaceChildren();
  outcomes.filter(value => value !== component.decision).forEach(value => chooseOption($('outcome'), value));
  $('reason').value = '';
  $('dialog-error').textContent = '';
  $('decision-dialog').showModal();
  (action === 'confirm' ? $('reason') : $('outcome')).focus();
}
function componentCard(component, human) {
  const card = node('article', undefined, 'component');
  card.dataset.componentId = component.component_id;
  const heading = node('div', undefined, 'component-head');
  append(heading, append(node('div'), node('h3', component.name), node('p', (component.version || 'Version not supplied') + ' · ' + component.type, 'component-meta')), badge(component.decision));
  append(card, heading, node('p', component.reason, 'reason'), node('p', 'Declared licenses: ' + (component.declared_licenses.length ? component.declared_licenses.join(', ') : 'None declared; license evidence is missing.'), 'licenses'));
  const strip = node('div', undefined, 'decision-strip');
  const current = node('div', undefined, 'human');
  if (human) append(current, node('strong', 'Human decision: ' + human.decision), node('span', human.reviewer + ' · ' + (human.action === 'confirm' ? 'Confirmed' : 'Overridden')), node('p', human.reason));
  else append(current, node('strong', 'Pending human review'), node('span', 'No reviewer decision recorded'));
  const buttons = node('div', undefined, 'actions');
  [['confirm', 'Confirm recommendation'], ['override', 'Override']].forEach(([action, label]) => {
    const button = node('button', label, action === 'confirm' ? 'primary' : 'quiet');
    button.type = 'button';
    button.addEventListener('click', () => openDecision(component, action, button));
    buttons.append(button);
  });
  append(strip, current, buttons);
  append(card, strip, evidenceDetails(component));
  const history = active.review.audit_log.filter(event => event.component_id === component.component_id);
  if (history.length) {
    const details = node('details', undefined, 'evidence');
    append(details, node('summary', 'Decision history · ' + history.length + ' events'));
    history.forEach(event => append(details, append(node('div', undefined, 'event'), eventDetails(event))));
    card.append(details);
  }
  return card;
}
function render() {
  const review = active.review, machine = review.snapshot.summary, human = review.reviewer_summary;
  $('workspace').hidden = false;
  $('empty').hidden = true;
  $('review-title').textContent = active.id;
  $('review-meta').textContent = 'Policy ' + review.snapshot.policy_version + ' · Saved ' + new Date(review.saved_at).toLocaleString();
  $('download').href = '/api/reviews/' + encodeURIComponent(active.id) + '/report';
  $('summaries').replaceChildren(summaryPanel('Original machine recommendations', [['Total', machine.total], ['Allow', machine.allow], ['Needs review', machine.needs_review], ['Reject', machine.reject]]), summaryPanel('Current human decisions', [['Recorded', human.recorded], ['Allow', human.allow], ['Needs review', human.needs_review], ['Reject', human.reject]], human));
  const current = new Map(review.reviewer_decisions.map(event => [event.component_id, event]));
  const filter = $('filter').value;
  const components = review.snapshot.results.filter(component => filter === 'all' || (filter === 'pending' ? !current.has(component.component_id) : component.decision === filter));
  $('components').replaceChildren(...components.map(component => componentCard(component, current.get(component.component_id))));
  if (!components.length) $('components').append(node('p', 'No components match this view.', 'muted'));
  $('history-title').textContent = 'Complete decision history · ' + review.audit_log.length + ' events';
  $('history').replaceChildren(...review.audit_log.map(event => append(node('div', undefined, 'event'), eventDetails(event))));
  if (!review.audit_log.length) $('history').append(node('p', 'No reviewer actions recorded.'));
}
$('run-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (pending) return;
  setBusy(true);
  feedback('Running machine review' + ($('fetch').checked ? ' and fetching model-card evidence…' : '…'));
  try {
    const data = await api('/api/reviews', {sbom: $('sbom').value, fetch_model_cards: $('fetch').checked});
    $('filter').value = 'all';
    rememberReview(data);
    feedback('Machine review saved. ' + data.review.snapshot.summary.total + ' components ready for human review.');
  } catch (error) { feedback(error.message, true); }
  finally { setBusy(false); }
});
$('saved').addEventListener('change', async () => {
  if (!$('saved').value || pending) return;
  setBusy(true);
  feedback('Opening saved review…');
  try { rememberReview(await api('/api/reviews/' + encodeURIComponent($('saved').value))); feedback('Saved review reopened.'); }
  catch (error) { feedback(error.message, true); $('saved').value = active ? active.id : ''; }
  finally { setBusy(false); }
});
$('refresh').addEventListener('click', async () => {
  if (pending) return;
  setBusy(true);
  try { await refresh(); } catch (error) { feedback(error.message, true); }
  finally { setBusy(false); }
});
$('filter').addEventListener('change', () => { if (active) render(); });
$('sbom').addEventListener('change', () => { $('run').disabled = pending || !$('sbom').value; });
$('reviewer').addEventListener('input', () => { try { localStorage.setItem('sbom-reviewer.identity', $('reviewer').value); } catch (_) {} });
$('cancel').addEventListener('click', () => { if (!pending) $('decision-dialog').close(); });
$('decision-dialog').addEventListener('cancel', event => { if (pending) event.preventDefault(); });
$('decision-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (pending || !dialogAction) return;
  if (!$('reviewer').value.trim() || !$('reason').value.trim()) { $('dialog-error').textContent = 'A nonblank reviewer and rationale are required.'; return; }
  const {component, action} = dialogAction;
  const body = {component_id: component.component_id, action, reviewer: $('reviewer').value, reason: $('reason').value};
  if (action === 'override') body.outcome = $('outcome').value;
  setBusy(true);
  $('dialog-error').textContent = '';
  try {
    const data = await api('/api/reviews/' + encodeURIComponent(active.id) + '/decisions', body);
    $('decision-dialog').close();
    rememberReview(data);
    feedback('Decision saved for ' + component.name + '. Machine evidence preserved.');
    const card = [...$('components').children].find(element => element.dataset.componentId === component.component_id);
    if (card) card.querySelector('button').focus();
  } catch (error) { $('dialog-error').textContent = error.message; }
  finally { setBusy(false); }
});
try { $('reviewer').value = localStorage.getItem('sbom-reviewer.identity') || ''; } catch (_) {}
(async () => {
  setBusy(true);
  try { await refresh(); } catch (error) { feedback(error.message, true); }
  finally { setBusy(false); }
})();
