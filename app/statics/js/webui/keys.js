(() => {
  const API_BASE = '/webui/api/me';
  let keysCache = [];
  let panelVisible = false;

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
    const key = await webuiKey?.get?.();
    return key ? { Authorization: `Bearer ${key}` } : {};
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
      showToast?.(text('keys.deleted', 'Key deleted.'), 'success');
      await fetchKeys();
    } catch {
      showToast?.(text('keys.deleteError', 'Failed to delete key.'), 'error');
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

  function showCreateModal() {
    const modal = document.getElementById('keyCreateModal');
    if (!modal) return;
    document.getElementById('keyNameInput').value = '';
    document.getElementById('keyCreateResult').style.display = 'none';
    document.getElementById('keyCreateForm').style.display = '';
    modal.style.display = 'flex';
  }

  function hideCreateModal() {
    document.getElementById('keyCreateModal').style.display = 'none';
  }

  async function handleCreate() {
    const name = document.getElementById('keyNameInput').value.trim() || 'Default';
    try {
      const result = await createKey(name);
      document.getElementById('keyCreateForm').style.display = 'none';
      const resultDiv = document.getElementById('keyCreateResult');
      resultDiv.style.display = '';
      document.getElementById('rawKeyDisplay').textContent = result.raw_key;

      const copyBtn = document.getElementById('copyRawKeyBtn');
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(result.raw_key).then(() => {
          showToast?.(text('keys.copied', 'Key copied!'), 'success');
        });
      };

      await fetchKeys();
    } catch (e) {
      showToast?.(e.message, 'error');
    }
  }

  async function fetchProfile() {
    try {
      const resp = await fetch(`${API_BASE}/profile`, { headers: await authHeaders() });
      if (!resp.ok) return;
      const profile = await resp.json();
      renderProfile(profile);
    } catch {}
  }

  function renderProfile(p) {
    const el = document.getElementById('userProfile');
    if (!el) return;
    const avatar = p.avatar_url
      ? `<img class="profile-avatar" src="${esc(p.avatar_url)}" alt="" width="32" height="32">`
      : `<div class="profile-avatar-pl">${esc((p.name || p.username || '?')[0].toUpperCase())}</div>`;

    el.innerHTML = `
      ${avatar}
      <div class="profile-info">
        <div class="profile-name">${esc(p.name || p.username)}</div>
        <div class="profile-level">${p.trust_level ? `Level ${p.trust_level}` : ''}</div>
      </div>
    `;
    el.style.display = 'flex';
  }

  function togglePanel() {
    const panel = document.getElementById('keysPanel');
    if (!panel) return;
    panelVisible = !panelVisible;
    panel.style.display = panelVisible ? 'block' : 'none';
    if (panelVisible) fetchKeys();
  }

  function init() {
    const toggleBtn = document.getElementById('keysToggleBtn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', togglePanel);
    }

    const createBtn = document.getElementById('createKeyBtn');
    if (createBtn) {
      createBtn.addEventListener('click', showCreateModal);
    }

    const cancelModal = document.getElementById('keyCreateCancel');
    if (cancelModal) {
      cancelModal.addEventListener('click', hideCreateModal);
    }

    const confirmCreate = document.getElementById('keyCreateConfirm');
    if (confirmCreate) {
      confirmCreate.addEventListener('click', handleCreate);
    }

    const modalBg = document.getElementById('keyCreateModal');
    if (modalBg) {
      modalBg.addEventListener('click', (e) => {
        if (e.target === modalBg) hideCreateModal();
      });
    }

    fetchProfile();
  }

  document.addEventListener('DOMContentLoaded', init);
  window.keysManager = { fetchKeys, createKey, deleteKey, fetchProfile };
})();
