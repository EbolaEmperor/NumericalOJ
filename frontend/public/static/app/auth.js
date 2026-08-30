(function () {
  'use strict';

  document.querySelectorAll('[data-auth-password-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.authPasswordToggle);
      if (!input) return;

      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      button.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码');
      button.setAttribute('aria-pressed', String(reveal));
      input.focus();
    });
  });

  const sendCodeButton = document.querySelector('[data-auth-send-code]');
  if (!sendCodeButton) return;

  const emailInput = document.getElementById('email');
  const status = document.querySelector('[data-auth-code-status]');
  let countdownTimer = null;

  function setStatus(message, tone) {
    if (!status) return;
    status.textContent = message;
    status.className = `numoj-auth-field-status${tone ? ` is-${tone}` : ''}`;
    status.hidden = !message;
  }

  function startCountdown() {
    let seconds = 60;
    sendCodeButton.disabled = true;
    sendCodeButton.textContent = `${seconds} 秒后重发`;
    countdownTimer = window.setInterval(() => {
      seconds -= 1;
      if (seconds <= 0) {
        window.clearInterval(countdownTimer);
        countdownTimer = null;
        sendCodeButton.disabled = false;
        sendCodeButton.textContent = '获取验证码';
        return;
      }
      sendCodeButton.textContent = `${seconds} 秒后重发`;
    }, 1000);
  }

  sendCodeButton.addEventListener('click', async () => {
    if (!emailInput || !emailInput.value.trim() || !emailInput.checkValidity()) {
      emailInput?.reportValidity();
      return;
    }

    sendCodeButton.disabled = true;
    setStatus('正在发送…', '');

    try {
      const response = await fetch(sendCodeButton.dataset.sendCodeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: new URLSearchParams({ email: emailInput.value.trim() }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.success) {
        throw new Error(payload.message || '验证码发送失败');
      }
      setStatus(payload.message || '验证码已发送', 'success');
      startCountdown();
    } catch (error) {
      sendCodeButton.disabled = false;
      setStatus(error.message || '验证码发送失败，请稍后再试', 'error');
    }
  });
}());
