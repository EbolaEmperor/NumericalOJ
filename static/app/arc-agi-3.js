(function () {
  'use strict';

  const app = document.getElementById('arcGameApp');
  if (!app) {
    return;
  }

  const palette = [
    '#ffffff', '#cccccc', '#999999', '#666666',
    '#333333', '#000000', '#e53aa3', '#ff7bcc',
    '#f93c31', '#1e93ff', '#88d8f1', '#ffdc00',
    '#ff851b', '#921231', '#4fcc30', '#a356d6',
  ];
  const canvas = document.getElementById('arcGameCanvas');
  const context = canvas.getContext('2d', { alpha: false });
  const loader = document.getElementById('arcBoardLoader');
  const loaderText = document.getElementById('arcLoaderText');
  const boardMessage = document.getElementById('arcBoardMessage');
  const boardMessageTitle = document.getElementById('arcBoardMessageTitle');
  const boardMessageText = document.getElementById('arcBoardMessageText');
  const levelsCompleted = document.getElementById('arcLevelsCompleted');
  const winLevels = document.getElementById('arcWinLevels');
  const actionCount = document.getElementById('arcActionCount');
  const statusText = document.getElementById('arcStatusText');
  const stateBadge = document.getElementById('arcStateBadge');
  const frameNotice = document.getElementById('arcFrameNotice');
  const keyboardHint = document.getElementById('arcKeyboardHint');
  const clickHint = document.getElementById('arcClickHint');
  const resetButton = document.getElementById('arcResetLevel');
  const restartButton = document.getElementById('arcRestartGame');
  const actionButtons = Array.from(document.querySelectorAll('[data-arc-action]'));

  let sessionId = '';
  let busy = true;
  let gameState = 'NOT_PLAYED';
  let availableActions = new Set();
  let currentFrame = null;
  let animationSequence = 0;

  function showLoader(message) {
    loaderText.textContent = message;
    loader.hidden = false;
  }

  function hideLoader() {
    loader.hidden = true;
  }

  function showBoardMessage(title, message) {
    boardMessageTitle.textContent = title;
    boardMessageText.textContent = message;
    boardMessage.hidden = false;
  }

  function hideBoardMessage() {
    boardMessage.hidden = true;
  }

  function setStatus(message) {
    statusText.textContent = message;
  }

  function setBusy(nextBusy) {
    busy = nextBusy;
    updateControls();
  }

  function updateControls() {
    const finished = gameState === 'WIN' || gameState === 'GAME_OVER';
    actionButtons.forEach(function (button) {
      const action = Number(button.dataset.arcAction);
      button.disabled = busy || finished || !availableActions.has(action);
    });
    resetButton.disabled = busy || !sessionId;
    restartButton.disabled = busy;
    canvas.classList.toggle(
      'is-clickable',
      !busy && !finished && availableActions.has(6)
    );

    const hasKeyboard = [1, 2, 3, 4, 5].some(function (action) {
      return availableActions.has(action);
    });
    keyboardHint.classList.toggle('is-unavailable', !hasKeyboard);
    clickHint.classList.toggle('is-unavailable', !availableActions.has(6));
  }

  function updateState(game) {
    gameState = game.state;
    availableActions = new Set(game.available_actions || []);
    levelsCompleted.textContent = String(game.levels_completed || 0);
    winLevels.textContent = String(game.win_levels || 0);
    actionCount.textContent = String(game.action_count || 0);
    frameNotice.textContent = game.skipped_frames
      ? '动画已压缩 ' + String(game.skipped_frames) + ' 帧'
      : '';

    stateBadge.classList.remove('is-win', 'is-over');
    if (gameState === 'WIN') {
      stateBadge.textContent = '已完成';
      stateBadge.classList.add('is-win');
      setStatus('环境已完成。你找到了它的规则。');
      showBoardMessage('ENVIRONMENT CLEARED', '全部关卡已完成');
    } else if (gameState === 'GAME_OVER') {
      stateBadge.textContent = '本轮结束';
      stateBadge.classList.add('is-over');
      setStatus('本轮结束。可以重置本关或重新开始。');
      showBoardMessage('TRY AGAIN', '根据刚才的反馈调整策略');
    } else {
      stateBadge.textContent = '探索中';
      setStatus('观察画面，然后选择下一步。');
      hideBoardMessage();
    }
    updateControls();
  }

  function drawFrame(frame) {
    if (!Array.isArray(frame) || !frame.length || !Array.isArray(frame[0])) {
      return;
    }
    const height = frame.length;
    const width = frame[0].length;
    canvas.width = width;
    canvas.height = height;
    context.imageSmoothingEnabled = false;
    for (let y = 0; y < height; y += 1) {
      const row = frame[y];
      for (let x = 0; x < width; x += 1) {
        const colorIndex = Number(row[x]);
        context.fillStyle = palette[colorIndex] || '#000000';
        context.fillRect(x, y, 1, 1);
      }
    }
    currentFrame = frame;
  }

  function animateFrames(frames, fps) {
    const sequence = ++animationSequence;
    if (!Array.isArray(frames) || !frames.length) {
      return Promise.resolve();
    }
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const delay = reducedMotion
      ? 0
      : Math.max(16, Math.round(1000 / Math.max(1, Math.min(Number(fps) || 10, 30))));

    return new Promise(function (resolve) {
      let index = 0;
      function nextFrame() {
        if (sequence !== animationSequence) {
          resolve();
          return;
        }
        drawFrame(frames[index]);
        index += 1;
        if (index >= frames.length || delay === 0) {
          if (delay === 0) {
            drawFrame(frames[frames.length - 1]);
          }
          resolve();
          return;
        }
        window.setTimeout(function () {
          window.requestAnimationFrame(nextFrame);
        }, delay);
      }
      nextFrame();
    });
  }

  async function requestJson(url, options) {
    const response = await fetch(url, Object.assign({
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
    }, options || {}));
    const payload = await response.json().catch(function () {
      return {};
    });
    if (!response.ok || payload.success === false) {
      throw new Error(payload.message || '请求失败，请稍后重试。');
    }
    return payload;
  }

  async function applyGamePayload(game) {
    hideLoader();
    await animateFrames(game.frames || [], game.default_fps);
    updateState(game);
  }

  async function startGame() {
    animationSequence += 1;
    sessionId = '';
    gameState = 'NOT_PLAYED';
    availableActions = new Set();
    hideBoardMessage();
    showLoader('正在加载环境');
    setStatus('正在建立本地对局…');
    setBusy(true);
    try {
      const payload = await requestJson(app.dataset.startUrl, {
        method: 'POST',
        body: '{}',
      });
      sessionId = payload.session_id;
      await applyGamePayload(payload.game);
    } catch (error) {
      hideLoader();
      showBoardMessage('LOAD FAILED', error.message);
      stateBadge.textContent = '加载失败';
      setStatus(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function submitAction(actionId, data) {
    if (busy || !sessionId) {
      return;
    }
    if (actionId !== 0 && !availableActions.has(actionId)) {
      return;
    }
    setBusy(true);
    hideBoardMessage();
    setStatus(actionId === 0 ? '正在重置本关…' : '正在执行操作…');
    try {
      const actionUrl = app.dataset.actionUrlTemplate.replace('SESSION_ID', sessionId);
      const payload = await requestJson(actionUrl, {
        method: 'POST',
        body: JSON.stringify({
          action_id: actionId,
          data: data || {},
        }),
      });
      await applyGamePayload(payload.game);
    } catch (error) {
      setStatus(error.message);
      showBoardMessage('ACTION FAILED', error.message);
    } finally {
      setBusy(false);
    }
  }

  actionButtons.forEach(function (button) {
    button.addEventListener('click', function () {
      submitAction(Number(button.dataset.arcAction));
    });
  });

  resetButton.addEventListener('click', function () {
    submitAction(0);
  });

  restartButton.addEventListener('click', startGame);

  canvas.addEventListener('click', function (event) {
    if (busy || !availableActions.has(6) || !currentFrame) {
      return;
    }
    const bounds = canvas.getBoundingClientRect();
    const x = Math.max(0, Math.min(
      canvas.width - 1,
      Math.floor((event.clientX - bounds.left) * canvas.width / bounds.width)
    ));
    const y = Math.max(0, Math.min(
      canvas.height - 1,
      Math.floor((event.clientY - bounds.top) * canvas.height / bounds.height)
    ));
    submitAction(6, { x: x, y: y });
  });

  document.addEventListener('keydown', function (event) {
    if (event.repeat || busy || event.metaKey || event.ctrlKey || event.altKey) {
      return;
    }
    const target = event.target;
    if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) {
      return;
    }
    const keyMap = {
      ArrowUp: 1,
      w: 1,
      W: 1,
      ArrowDown: 2,
      s: 2,
      S: 2,
      ArrowLeft: 3,
      a: 3,
      A: 3,
      ArrowRight: 4,
      d: 4,
      D: 4,
      Enter: 5,
      ' ': 5,
      z: 7,
      Z: 7,
      Backspace: 7,
    };
    const action = keyMap[event.key];
    if (!action || !availableActions.has(action)) {
      return;
    }
    event.preventDefault();
    submitAction(action);
  });

  startGame();
})();
