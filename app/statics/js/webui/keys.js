(() => {
  const API_BASE = '/webui/api/me';
  let keysCache = [];

  function text(key, fallback) {
    return typeof t === 'function' ? t(key) : fallback;
  }

  async function fetchKeys() {
    try {
      const resp = await fetch(`${API_BASE}/keys`, { headers: await authHeaders() });
      if (!resp.ok) throw new Error(resp.status);
      keysCache = await resp.json();
    } catch (e) {
      keysCache = [];
    }
    renderKeyList();
  }

  async function createKey(name) {
    const resp = await fetch(`${API_BASE}/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await authHeaders()) },
      body: JSON.stringify({ key_name: name || 'Default' }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to create key');
    }
    return resp.json();
  }

  async function deleteKey(id) {
    const resp = await fetch(`${API_BASE}/keys/${id}`, {
      method: 'DELETE',
      headers: await authHeaders(),
    });
    if (!resp.ok) throw new Error('Failed to delete key');
  }

  async function authHeaders() {
    try {
      const key = await webuiKey.get();
      return key ? { Authorization: `Bearer ${key}` } : {};
    } catch {
      return {};
    }
  }

  function renderKeyList() {
    const container = document.getElementById('keyList');
    if (!container) return;

    if (keysCache.length === 0) {
      container.innerHTML = `<div class="keys-empty">${text('keys.noKeys', 'No API keys yet.')}</div>`;
      return;
    }

    container.innerHTML = keysCache.map(k => `
      <div class="key-row" data-id="${k.id}">
        <div class="key-info">
          <span class="key-mono">${esc(k.key_prefix)}…</span>
          <span class="key-name">${esc(k.key_name)}</span>
        </div>
        <div class="key-meta">
          <span class="key-date">${formatDate(k.created_at)}</span>
          ${k.is_banned ? `<span class="key-badge key-badge-banned">${text('keys.banned', 'Banned')}</span>` : ''}
        </div>
        <button class="key-delete" data-id="${k.id}" title="${text('keys.delete', 'Delete')}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14"/></svg>
        </button>
      </div>
    `).join('');

    container.querySelectorAll('.key-delete').forEach(btn => {
      btn.addEventListener('click', () => handleDelete(btn.dataset.id));
    });
  }

  async function handleDelete(id) {
    if (!confirm(text('keys.confirmDelete', 'Delete this API key? It will stop working immediately.'))) return;
    try {
      await deleteKey(id);
      if (typeof showToast === 'function') showToast(text('keys.deleted', 'Key deleted.'), 'success');
      await fetchKeys();
    } catch {
      if (typeof showToast === 'function') showToast(text('keys.deleteError', 'Failed to delete key.'), 'error');
    }
  }

  function formatDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleDateString();
  }

  function esc(s) {
    const el = document.createElement('span');
    el.textContent = s;
    return el.innerHTML;
  }

  function showListView() {
    document.getElementById('keysListView').style.display = '';
    document.getElementById('keyCreateForm').style.display = 'none';
    document.getElementById('keyCreateResult').style.display = 'none';
  }

  function showCreateForm() {
    document.getElementById('keysListView').style.display = 'none';
    document.getElementById('keyCreateForm').style.display = '';
    document.getElementById('keyCreateResult').style.display = 'none';
    document.getElementById('keyNameInput').value = '';
  }

  function showResult(rawKey) {
    document.getElementById('keysListView').style.display = 'none';
    document.getElementById('keyCreateForm').style.display = 'none';
    document.getElementById('keyCreateResult').style.display = '';
    document.getElementById('rawKeyDisplay').textContent = rawKey;
  }

  async function openKeysModal() {
    const modal = document.getElementById('keyCreateModal');
    if (!modal) return;
    showListView();
    modal.style.display = 'flex';
    await fetchKeys();
  }

  function closeKeysModal() {
    document.getElementById('keyCreateModal').style.display = 'none';
  }

  async function handleCreate() {
    const input = document.getElementById('keyNameInput');
    const name = (input ? input.value.trim() : '') || 'Default';
    try {
      const result = await createKey(name);
      document.getElementById('copyRawKeyBtn').onclick = () => {
        navigator.clipboard.writeText(result.raw_key).then(() => {
          if (typeof showToast === 'function') showToast(text('keys.copied', 'Key copied!'), 'success');
        });
      };
      showResult(result.raw_key);
      await fetchKeys();
    } catch (e) {
      if (typeof showToast === 'function') showToast(e.message, 'error');
    }
  }

  function init() {
    // Modal buttons (static elements)
    const createBtn = document.getElementById('createKeyBtn');
    if (createBtn) createBtn.addEventListener('click', showCreateForm);

    const cancelBtn = document.getElementById('keyCreateCancel');
    if (cancelBtn) cancelBtn.addEventListener('click', showListView);

    const confirmBtn = document.getElementById('keyCreateConfirm');
    if (confirmBtn) confirmBtn.addEventListener('click', handleCreate);

    const closeBtn = document.getElementById('keysListClose');
    if (closeBtn) closeBtn.addEventListener('click', closeKeysModal);

    const modalBg = document.getElementById('keyCreateModal');
    if (modalBg) {
      modalBg.addEventListener('click', (e) => {
        if (e.target === modalBg) closeKeysModal();
      });
    }

    // Result close → back to list
    const resultClose = document.getElementById('keyCreateClose');
    if (resultClose) {
      resultClose.onclick = () => { showListView(); closeKeysModal(); };
    }
  }

  document.addEventListener('DOMContentLoaded', init);
  window.openKeysModal = openKeysModal;
  window.keysManager = { fetchKeys, createKey, deleteKey };
})();
