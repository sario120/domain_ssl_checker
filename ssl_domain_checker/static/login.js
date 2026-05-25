(function () {
  var savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') document.body.classList.add('light');

  var toggleThemeBtn = document.getElementById('login-theme-toggle');
  function updateThemeIcon() {
    var isLight = document.body.classList.contains('light');
    toggleThemeBtn.textContent = isLight ? '☀️' : '🌙';
    toggleThemeBtn.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
  }
  if (toggleThemeBtn) {
    updateThemeIcon();
    toggleThemeBtn.addEventListener('click', function () {
      document.body.classList.toggle('light');
      localStorage.setItem('theme', document.body.classList.contains('light') ? 'light' : 'dark');
      updateThemeIcon();
    });
  }

  var togglePw = document.getElementById('toggle-pw');
  var pwInput = document.getElementById('password');
  if (togglePw && pwInput) {
    togglePw.addEventListener('click', function () {
      var isPassword = pwInput.type === 'password';
      pwInput.type = isPassword ? 'text' : 'password';
      togglePw.textContent = isPassword ? '🙈' : '👁️';
      togglePw.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }

  var loginForm = document.getElementById('login-form');
  var loginBtn = document.getElementById('login-btn');
  var errEl = document.getElementById('login-error');
  var loginBox = document.querySelector('.login-box');
  var usernameInput = document.getElementById('username');
  var rememberInput = document.getElementById('remember-me');
  var inputs = [usernameInput, pwInput].filter(Boolean);
  var dismissTimer = null;

  function loadRememberedUsername() {
    try {
      var stored = localStorage.getItem('vigil-remembered-username');
      if (stored) {
        usernameInput.value = stored;
        if (rememberInput) rememberInput.checked = true;
      }
    } catch (e) {}
  }

  function saveRememberedUsername() {
    try {
      if (rememberInput && rememberInput.checked && usernameInput.value.trim()) {
        localStorage.setItem('vigil-remembered-username', usernameInput.value.trim());
      } else {
        localStorage.removeItem('vigil-remembered-username');
      }
    } catch (e) {}
  }

  loadRememberedUsername();

  function clearError() {
    if (dismissTimer) { clearTimeout(dismissTimer); dismissTimer = null; }
    errEl.style.display = 'none';
    errEl.classList.remove('locked');
    errEl.innerHTML = '';
    loginBox.classList.remove('shake');
    inputs.forEach(function (el) { el.classList.remove('error'); });
  }

  function scheduleDismiss() {
    if (dismissTimer) clearTimeout(dismissTimer);
    dismissTimer = setTimeout(clearError, 3000);
  }

  function showError(msg, isLocked) {
    errEl.style.display = 'block';
    loginBox.classList.add('shake');
    inputs.forEach(function (el) { el.classList.add('error'); });

    if (isLocked) {
      errEl.classList.add('locked');
      errEl.innerHTML = '<span class="lock-icon">🔒</span><span>' + msg + '</span><button type="button" class="err-close" id="err-close" aria-label="Dismiss">&times;</button>';
    } else {
      errEl.innerHTML = msg + '<button type="button" class="err-close" id="err-close" aria-label="Dismiss">&times;</button>';
    }

    var closeBtn = document.getElementById('err-close');
    if (closeBtn) closeBtn.addEventListener('click', clearError, { once: true });

    scheduleDismiss();
  }

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    loginBtn.classList.add('btn-loading');
    loginBtn.disabled = true;
    clearError();

    try {
      saveRememberedUsername();
      var res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: usernameInput.value.trim(),
          password: pwInput.value
        })
      });
      var data = await res.json();
      if (!res.ok) throw { message: data.error || 'Login failed', status: res.status };
      loginBox.classList.add('fade-out');
      await new Promise(function (r) { setTimeout(r, 250); });
      window.location.href = '/dashboard';
    } catch (err) {
      var isLocked = err.status === 429;
      showError(err.message, isLocked);
    } finally {
      loginBtn.classList.remove('btn-loading');
      loginBtn.disabled = false;
    }
  });

  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      loginForm.dispatchEvent(new Event('submit'));
    }
  });

  inputs.forEach(function (el) {
    el.addEventListener('input', function () {
      el.classList.remove('error');
      if (errEl.style.display !== 'none') scheduleDismiss();
    });
  });
})();
