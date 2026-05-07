(function () {
  'use strict';

  var PROFILE_URL = '/webui/api/me/profile';
  var _state = { profile: null, fetched: false, pendingPromise: null, error: null };
  var _containers = [];

  function t(key, fallback) {
    return typeof window.t === 'function' ? window.t(key) : fallback;
  }

  function esc(s) {
    var el = document.createElement('span');
    el.textContent = s || '';
    return el.innerHTML;
  }

  function initials(name) {
    if (!name) return '?';
    return name.charAt(0).toUpperCase();
  }

  function getProfile() {
    if (_state.fetched && !_state.error) return Promise.resolve({ ok: true, profile: _state.profile });
    if (_state.pendingPromise) return _state.pendingPromise;

    _state.pendingPromise = (function () {
      var keyPromise;
      try {
        keyPromise = typeof webuiKey !== 'undefined' ? webuiKey.get() : Promise.resolve('');
      } catch (e) { keyPromise = Promise.resolve(''); }

      return keyPromise.then(function (key) {
        var headers = {};
        if (key) headers.Authorization = 'Bearer ' + key;
        return fetch(PROFILE_URL, { headers: headers });
      }).then(function (res) {
          if (res.status === 401) {
            _state.error = { status: 401, message: 'Unauthorized' };
            try { webuiKey.clear(); } catch (e) {}
            if (typeof webuiLogout === 'function') webuiLogout();
            return { ok: false, error: _state.error };
          }
          if (res.status === 404) {
            _state.error = { status: 404, message: 'Not Found' };
            return { ok: false, error: _state.error };
          }
          if (res.status === 403) {
            _state.error = { status: 403, message: 'Forbidden' };
            return { ok: false, error: _state.error };
          }
          if (!res.ok) {
            _state.error = { status: res.status, message: 'Unexpected' };
            return { ok: false, error: _state.error };
          }
          return res.json().then(function (data) {
            var profile = data && data.user ? data.user : data;
            _state.profile = profile;
            return { ok: true, profile: profile };
          });
        })
        .catch(function (err) {
          _state.error = { status: 0, message: err.message || 'Network error' };
          return { ok: false, error: _state.error };
        })
        .finally(function () {
          _state.fetched = true;
          _state.pendingPromise = null;
        });
    })();

    return _state.pendingPromise;
  }

  function renderAvatar(img, profile) {
    if (!img) return;
    img.classList.add('profile-avatar');
    img.alt = '';
    if (profile && profile.avatar_url) {
      img.src = profile.avatar_url;
      img.onerror = function () { img.replaceWith(avatarPlaceholder(profile)); };
    } else {
      img.replaceWith(avatarPlaceholder(profile));
    }
  }

  function avatarPlaceholder(profile) {
    var span = document.createElement('span');
    span.className = 'profile-avatar-pl';
    span.textContent = initials(profile && profile.username);
    return span;
  }

  function renderSidebar(container, options) {
    if (!container) return Promise.resolve();
    if (_containers.indexOf(container) === -1) _containers.push(container);

    return getProfile().then(function (result) {
      if (!result.ok) {
        if (result.error && result.error.status === 404) {
          container.innerHTML = '<span class="profile-name" data-i18n="profile.guest">' + t('profile.guest', 'Guest') + '</span>';
        }
        return;
      }
      var p = result.profile;
      if (!p) return;

      var avatars = container.querySelectorAll('.profile-avatar');
      for (var i = 0; i < avatars.length; i++) renderAvatar(avatars[i], p);

      var nameEls = container.querySelectorAll('.profile-name');
      for (var j = 0; j < nameEls.length; j++) {
        nameEls[j].textContent = p.username || '';
      }

      var levelEls = container.querySelectorAll('.profile-level');
      for (var k = 0; k < levelEls.length; k++) {
        levelEls[k].textContent = t('profile.trustLevel', 'Trust Level {level}').replace('{level}', p.trust_level || 0);
      }

      if (window.I18n && I18n.apply) I18n.apply(container);
    });
  }

  function updateHeader(rootEl) {
    if (!rootEl) return Promise.resolve();

    return getProfile().then(function (result) {
      if (!result.ok || !result.profile) return;
      var p = result.profile;
      var userLink = rootEl.querySelector('#hd-user');
      if (!userLink) return;

      var avatar = document.createElement('img');
      avatar.className = 'profile-avatar';
      avatar.width = 20;
      avatar.height = 20;
      avatar.style.cssText = 'margin-right:4px;vertical-align:middle';
      if (p.avatar_url) {
        avatar.src = p.avatar_url;
        avatar.onerror = function () { avatar.remove(); };
      } else {
        avatar.remove();
      }

      userLink.textContent = '';
      if (p.avatar_url) userLink.appendChild(avatar);
      userLink.appendChild(document.createTextNode(p.username || ''));
    });
  }

  function reset() {
    _state = { profile: null, fetched: false, pendingPromise: null, error: null };
    _containers = [];
  }

  function renderWebuiProfile(container) {
    return renderSidebar(container);
  }

  window.WebuiProfile = {
    getProfile: getProfile,
    renderSidebar: renderSidebar,
    updateHeader: updateHeader,
    reset: reset
  };

  window.renderWebuiProfile = renderWebuiProfile;

  if (window.I18n && I18n.onReady) {
    I18n.onReady(function () {
      for (var i = 0; i < _containers.length; i++) {
        renderSidebar(_containers[i]);
      }
    });
  }
})();
