(function () {
  'use strict';

  var shell = document.querySelector('[data-ranking-detail]');
  if (!shell || shell.getAttribute('data-ranking-detail-ready') === 'true') return;
  shell.setAttribute('data-ranking-detail-ready', 'true');

  var panelHost = shell.querySelector('[data-ranking-panel-host]');
  var panelStage = shell.querySelector('[data-ranking-panel-stage]');
  var contentScroll = shell.querySelector('[data-ranking-content-scroll]');
  var rail = shell.querySelector('[data-ranking-rail]');
  var railOpenButton = shell.querySelector('[data-ranking-rail-open]');
  var railCloseButton = shell.querySelector('[data-ranking-rail-close]');
  var railBackdrop = shell.querySelector('[data-ranking-rail-backdrop]');
  var detailUrl = new URL(shell.getAttribute('data-ranking-detail-url'), window.location.origin);
  var navigationUrl = shell.getAttribute('data-ranking-navigation-url');
  var initialTab = shell.getAttribute('data-ranking-initial-tab') || 'description';
  var revision = String(shell.getAttribute('data-ranking-revision') || '');
  var revisionGeneration = 0;
  var cache = new Map();
  var controlBaselines = new WeakMap();
  var observedPanels = new WeakSet();
  var loadedScriptUrls = new Set();
  var activeRequest = null;
  var requestSerial = 0;
  var pollPromise = null;
  var pollTimer = 0;
  var hardReloadPending = false;
  var unloadAllowed = false;
  var previousRailFocus = null;
  var railOpenToken = 0;
  var railInertState = new Map();
  var displayedTab = initialTab;
  var displayedUrl = canonicalUrl(window.location.href);
  var targetTab = initialTab;
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  var mobileRail = window.matchMedia('(max-width: 991.98px)');

  if (!panelHost || !panelStage || !contentScroll || !rail) return;

  document.querySelectorAll('script[src]').forEach(function (script) {
    loadedScriptUrls.add(new URL(script.src, window.location.href).toString());
  });

  function canonicalUrl(value) {
    var url = new URL(value, window.location.href);
    url.searchParams.delete('fragment');
    url.hash = '';
    return url;
  }

  function tabFromUrl(url) {
    return (url.searchParams.get('tab') || 'description').trim().toLowerCase();
  }

  function sameDetailPath(url) {
    return url.origin === window.location.origin && url.pathname === detailUrl.pathname;
  }

  function directPanel() {
    return Array.prototype.find.call(panelHost.children, function (child) {
      return child.hasAttribute && child.hasAttribute('data-ranking-panel');
    }) || null;
  }

  function markInitialScripts(root) {
    root.querySelectorAll('script').forEach(function (script) {
      script.setAttribute('data-ranking-script-executed', 'true');
    });
  }

  function scriptIsExecutable(script) {
    var type = (script.getAttribute('type') || '').trim().toLowerCase();
    return !type || type === 'text/javascript' || type === 'application/javascript' || type === 'module';
  }

  async function activateScripts(root) {
    var scripts = Array.prototype.slice.call(root.querySelectorAll('script'));
    for (var index = 0; index < scripts.length; index += 1) {
      var oldScript = scripts[index];
      if (oldScript.getAttribute('data-ranking-script-executed') === 'true') continue;
      if (!scriptIsExecutable(oldScript)) {
        oldScript.setAttribute('data-ranking-script-executed', 'true');
        continue;
      }

      var sourceUrl = oldScript.src ? new URL(oldScript.src, window.location.href).toString() : '';
      if (sourceUrl && loadedScriptUrls.has(sourceUrl)) {
        oldScript.remove();
        continue;
      }

      var replacement = document.createElement('script');
      Array.prototype.forEach.call(oldScript.attributes, function (attribute) {
        if (attribute.name !== 'data-ranking-script-executed') {
          replacement.setAttribute(attribute.name, attribute.value);
        }
      });
      replacement.setAttribute('data-ranking-script-executed', 'true');
      if (!oldScript.src) replacement.textContent = oldScript.textContent;

      if (oldScript.src) {
        loadedScriptUrls.add(sourceUrl);
        await new Promise(function (resolve) {
          replacement.addEventListener('load', resolve, {once: true});
          replacement.addEventListener('error', function () {
            loadedScriptUrls.delete(sourceUrl);
            console.warn('ranking fragment script failed:', oldScript.src);
            resolve();
          }, {once: true});
          oldScript.replaceWith(replacement);
        });
      } else {
        oldScript.replaceWith(replacement);
      }
    }
  }

  function paintIdenticons(root) {
    var identicon = window.NumojIdenticon;
    if (!identicon) return;
    root.querySelectorAll('.numoj-avatar[data-avatar-seed]').forEach(function (avatar) {
      var seed = avatar.getAttribute('data-avatar-seed') || 'numericaloj';
      var label = avatar.getAttribute('data-avatar-label') || seed;
      identicon.paint(avatar, identicon.cellsForSeed(seed), label);
    });
  }

  function controlState(control) {
    if (control.type === 'file') {
      return Array.prototype.map.call(control.files || [], function (file) {
        return [file.name, file.size, file.lastModified].join(':');
      }).join('|');
    }
    if (control.type === 'checkbox' || control.type === 'radio') {
      return control.checked ? '1' : '0';
    }
    if (control.tagName === 'SELECT' && control.multiple) {
      return Array.prototype.filter.call(control.options, function (option) {
        return option.selected;
      }).map(function (option) {
        return option.value;
      }).join('\u0000');
    }
    return String(control.value == null ? '' : control.value);
  }

  function isDirtyControl(control) {
    var panel = control.closest('[data-ranking-panel]');
    if (!panel) return false;
    var tab = panel.getAttribute('data-ranking-tab') || '';
    if (tab !== 'submit' && tab !== 'edit') return false;

    // 弹窗字段只是编辑 JS 模型的临时副本；显式 managed 区域则由组件自己的
    // 服务端快照判断 dirty。两者都不能再参与通用控件 baseline，否则仅打开
    // 弹窗或 AJAX 保存成功后也会误报“尚未保存”。
    if (control.closest('.modal, [data-ranking-dirty-managed]')) return false;
    if (['button', 'submit', 'reset', 'image'].indexOf(control.type) >= 0) return false;

    if (tab === 'submit') {
      // 提交页的模式/节点选择可随时重选；只有实际表单输入（例如已选择文件）
      // 离开时才有必要保护。隐藏的 UI 状态不应打扰用户。
      return control.type !== 'hidden' && Boolean(control.form && panel.contains(control.form));
    }

    // 编辑页只跟踪“基本信息”表单和已选择的上传文件。其它普通 POST
    // 按钮没有可丢失的输入，规则/端点等异步编辑器由 managed dirty 负责。
    return control.type === 'file' ||
      Boolean(control.form && control.form.id === 'rankingEditForm');
  }

  function captureControl(control) {
    if (!isDirtyControl(control) || controlBaselines.has(control)) return;
    controlBaselines.set(control, controlState(control));
  }

  function observeControls(root) {
    root.querySelectorAll('input, select, textarea').forEach(captureControl);
    if (observedPanels.has(root) || !window.MutationObserver) return;
    var observer = new MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(function (node) {
          if (node.nodeType !== 1) return;
          if (node.matches('input, select, textarea')) captureControl(node);
          node.querySelectorAll('input, select, textarea').forEach(captureControl);
        });
      });
    });
    observer.observe(root, {childList: true, subtree: true});
    observedPanels.add(root);
  }

  function hydrate(root) {
    if (!root) return;
    if (window.MathCurveLoader) window.MathCurveLoader.hydrate(root);
    if (window.ChoicePicker) window.ChoicePicker.init(root);
    if (window.EloTrajectoryViewer) window.EloTrajectoryViewer.init(root);
    paintIdenticons(root);
    observeControls(root);
    var markdownRoot = root.matches && root.matches('[data-numoj-markdown]') ?
      root : root.querySelector('[data-numoj-markdown]');
    if (markdownRoot && window.NumericalOJMarkdownRenderer) {
      window.NumericalOJMarkdownRenderer.enhanceAll(root).catch(function (error) {
        console.warn('ranking Markdown hydration failed:', error);
      });
    } else if (window.MathJax && typeof window.MathJax.typesetPromise === 'function') {
      window.MathJax.typesetPromise([root]).catch(function (error) {
        console.warn('ranking MathJax hydration failed:', error);
      });
    }
  }

  function parsePanel(html) {
    var template = document.createElement('template');
    template.innerHTML = String(html || '').trim();
    var panel = template.content.querySelector('[data-ranking-panel]');
    if (!panel) throw new Error('页面片段格式无效');
    return panel;
  }

  function historyUrlForTab(url, effectiveTab) {
    var next = canonicalUrl(url);
    next.searchParams.set('tab', effectiveTab || tabFromUrl(next));
    return next;
  }

  function updateHistory(url, mode, tab) {
    if (mode === 'none') return;
    var next = historyUrlForTab(url, tab);
    var state = {rankingDetail: true, tab: tab || tabFromUrl(next)};
    if (mode === 'replace') {
      window.history.replaceState(state, '', next.pathname + next.search);
    } else {
      window.history.pushState(state, '', next.pathname + next.search);
    }
  }

  function panelOwnsLocation(panel, expectedUrl) {
    if (!panel || panel !== directPanel() || !panel.isConnected) return false;
    var current = canonicalUrl(window.location.href).toString();
    var owned = panel.getAttribute('data-ranking-panel-url');
    if (!owned || canonicalUrl(owned).toString() !== current) return false;
    return !expectedUrl || canonicalUrl(expectedUrl).toString() === current;
  }

  function startQueryRequest(detail) {
    if (!detail || !detail.panel || !detail.url) return;
    var panel = detail.panel;
    if (!panelOwnsLocation(panel)) return;
    var next = canonicalUrl(detail.url);
    var tab = panel.getAttribute('data-ranking-tab') || '';
    if (!sameDetailPath(next) || !tab || displayedTab !== tab || tabFromUrl(next) !== tab) return;

    var generation = (
      Number.parseInt(panel.getAttribute('data-ranking-query-generation') || '0', 10) || 0
    ) + 1;
    panel.setAttribute('data-ranking-query-generation', String(generation));
    panel.setAttribute('data-ranking-query-pending', String(generation));
    panel.setAttribute('data-ranking-query-target', next.toString());
    detail.accepted = true;
    detail.generation = generation;
    detail.url = next.toString();
  }

  function commitQueryRequest(detail) {
    if (!detail || !detail.panel || !detail.url || detail.generation == null) return;
    var panel = detail.panel;
    var generation = String(detail.generation);
    var started = canonicalUrl(detail.startedUrl || detail.url);
    var next = canonicalUrl(detail.url);
    var tab = panel.getAttribute('data-ranking-tab') || '';
    if (
      panel.getAttribute('data-ranking-query-pending') !== generation ||
      panel.getAttribute('data-ranking-query-target') !== started.toString() ||
      !panelOwnsLocation(panel) ||
      !sameDetailPath(next) ||
      !tab ||
      displayedTab !== tab ||
      tabFromUrl(next) !== tab
    ) {
      return;
    }

    updateHistory(next, 'replace', tab);
    next = historyUrlForTab(next, tab);
    panel.setAttribute('data-ranking-panel-url', next.toString());
    var entry = cache.get(tab);
    if (entry && entry.node === panel) entry.url = canonicalUrl(next);
    displayedUrl = canonicalUrl(next);
    detail.accepted = true;
    detail.url = next.toString();
  }

  function resumePendingPanelRefresh(panel) {
    if (!panel || panel.hasAttribute('data-ranking-query-pending') ||
        panel.hasAttribute('data-ranking-refresh-blocked')) return;
    var tab = panel.getAttribute('data-ranking-tab') || '';
    var entry = cache.get(tab);
    if (
      entry &&
      entry.node === panel &&
      entry.stale &&
      entry.pendingRefresh &&
      !entry.refreshing &&
      displayedTab === tab &&
      directPanel() === panel
    ) {
      entry.pendingRefresh = false;
      window.setTimeout(function () { refreshReadTab(tab); }, 0);
    }
  }

  function settleQueryRequest(detail) {
    if (!detail || !detail.panel || detail.generation == null) return;
    var panel = detail.panel;
    var generation = String(detail.generation);
    if (panel.getAttribute('data-ranking-query-pending') !== generation) return;
    panel.removeAttribute('data-ranking-query-pending');
    panel.removeAttribute('data-ranking-query-target');

    resumePendingPanelRefresh(panel);
  }

  function invalidatePanelQuery(panel) {
    if (!panel || !panel.hasAttribute('data-ranking-query-pending')) return;
    var generation = (
      Number.parseInt(panel.getAttribute('data-ranking-query-generation') || '0', 10) || 0
    ) + 1;
    panel.setAttribute('data-ranking-query-generation', String(generation));
    panel.removeAttribute('data-ranking-query-pending');
    panel.removeAttribute('data-ranking-query-target');
  }

  function setActiveTab(tab) {
    targetTab = tab;
    shell.querySelectorAll('[data-ranking-tab-link]').forEach(function (link) {
      var active = link.getAttribute('data-ranking-tab') === tab;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  }

  function rememberDisplayedPanel() {
    var panel = directPanel();
    if (!panel || !displayedTab) return;
    invalidatePanelQuery(panel);
    if (displayedTab === 'batch_eval' && targetTab !== 'batch_eval') {
      cache.delete('batch_eval');
      panel.remove();
      return;
    }
    var locationUrl = canonicalUrl(window.location.href);
    if (tabFromUrl(locationUrl) === displayedTab) displayedUrl = locationUrl;
    var entry = cache.get(displayedTab) || {};
    entry.node = panel;
    entry.url = canonicalUrl(displayedUrl);
    panel.setAttribute('data-ranking-panel-url', entry.url.toString());
    entry.scrollTop = contentScroll.scrollTop;
    cache.set(displayedTab, entry);
    panel.remove();
  }

  function stopLoading() {
    shell.classList.remove('is-fragment-loading');
    panelStage.removeAttribute('aria-busy');
    if (activeRequest && activeRequest.slowTimer) {
      window.clearTimeout(activeRequest.slowTimer);
      activeRequest.slowTimer = 0;
    }
  }

  function showLargeLoader() {
    rememberDisplayedPanel();
    panelHost.innerHTML =
      '<div class="ranking-panel-loading" role="status">' +
        '<span class="math-curve-loader" data-math-curve-loader data-size="lg">' +
          '<span class="math-curve-loader__label">正在加载比赛内容…</span>' +
        '</span>' +
      '</div>';
    if (window.MathCurveLoader) window.MathCurveLoader.hydrate(panelHost);
  }

  function showError(message) {
    rememberDisplayedPanel();
    displayedTab = null;
    displayedUrl = canonicalUrl(window.location.href);
    panelHost.innerHTML =
      '<div class="ranking-panel-error" role="alert">' +
        '<div class="ranking-panel-error-card">' +
          '<span class="ranking-panel-error-mark" aria-hidden="true">!</span>' +
          '<h2>内容加载失败</h2>' +
          '<p></p>' +
          '<button type="button" data-ranking-retry><i class="fas fa-redo" aria-hidden="true"></i>重新加载</button>' +
        '</div>' +
      '</div>';
    panelHost.querySelector('p').textContent = message || '网络暂时不可用，请稍后重试。';
    panelHost.querySelector('[data-ranking-retry]').addEventListener('click', function () {
      navigate(window.location.href, {history: 'replace', force: true});
    });
  }

  function abortNavigation() {
    if (!activeRequest) return;
    activeRequest.controller.abort();
    if (activeRequest.slowTimer) window.clearTimeout(activeRequest.slowTimer);
    activeRequest = null;
    stopLoading();
    if (!directPanel() && displayedTab && cache.has(displayedTab)) {
      var entry = cache.get(displayedTab);
      panelHost.replaceChildren(entry.node);
      contentScroll.scrollTop = entry.scrollTop || 0;
    }
  }

  async function requestFragment(url, signal) {
    var endpoint = canonicalUrl(url);
    endpoint.searchParams.set('fragment', '1');
    var response = await window.fetch(endpoint.toString(), {
      credentials: 'same-origin',
      headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
      cache: 'no-store',
      signal: signal,
      mathCurveLoader: false
    });
    var data;
    try {
      data = await response.json();
    } catch (_error) {
      throw new Error('服务器返回了无法识别的内容');
    }
    if (!response.ok || !data.success) {
      throw new Error(data.message || ('请求失败（' + response.status + '）'));
    }
    return data;
  }

  function storeCurrentEntry(panel, tab, url) {
    var entry = cache.get(tab) || {};
    entry.node = panel;
    entry.url = canonicalUrl(url);
    panel.setAttribute('data-ranking-panel-url', entry.url.toString());
    if (!panel.hasAttribute('data-ranking-query-generation')) {
      panel.setAttribute('data-ranking-query-generation', '0');
    }
    entry.scrollTop = 0;
    entry.stale = false;
    entry.needsHistory = false;
    entry.refreshToken = (entry.refreshToken || 0) + 1;
    entry.refreshing = false;
    entry.pendingRefresh = false;
    cache.set(tab, entry);
    return entry;
  }

  function restoreCached(tab, entry) {
    if (displayedTab !== tab || directPanel() !== entry.node) rememberDisplayedPanel();
    panelHost.replaceChildren(entry.node);
    displayedTab = tab;
    displayedUrl = canonicalUrl(entry.url);
    hydrate(entry.node);
    contentScroll.scrollTop = entry.scrollTop || 0;
    if (entry.stale && tab === 'submit') {
      refreshWholeTab(tab);
    } else if (
      entry.stale &&
      (tab === 'leaderboard' || tab === 'matches' ||
       tab === 'all_submissions' || tab === 'appeals')
    ) {
      refreshReadTab(tab);
    } else if (entry.needsHistory && tab === 'submit') {
      refreshSubmitHistory();
    }
  }

  async function navigate(value, options) {
    var settings = options || {};
    var url = canonicalUrl(value);
    if (!sameDetailPath(url)) {
      window.location.assign(url.toString());
      return;
    }
    var requestedTab = tabFromUrl(url);
    abortNavigation();
    setActiveTab(requestedTab);
    closeRail();

    var cached = cache.get(requestedTab);
    if (!settings.force && displayedTab === requestedTab &&
        canonicalUrl(window.location.href).toString() === url.toString() && directPanel()) {
      return;
    }
    updateHistory(url, settings.history || 'push', requestedTab);
    if (!settings.force && cached && canonicalUrl(cached.url).toString() === url.toString()) {
      restoreCached(requestedTab, cached);
      return;
    }

    var serial = ++requestSerial;
    var controller = new AbortController();
    activeRequest = {serial: serial, controller: controller, slowTimer: 0};
    shell.classList.add('is-fragment-loading');
    panelStage.setAttribute('aria-busy', 'true');
    activeRequest.slowTimer = window.setTimeout(function () {
      if (activeRequest && activeRequest.serial === serial) showLargeLoader();
    }, 250);

    try {
      var fragmentGeneration = revisionGeneration;
      var data = await requestFragment(url, controller.signal);
      if (!activeRequest || activeRequest.serial !== serial) return;
      if (!fragmentMatchesGeneration(data, fragmentGeneration)) {
        // 轮询在请求期间看到了更新：再取一次，避免把已知旧片段直接展示。
        fragmentGeneration = revisionGeneration;
        data = await requestFragment(url, controller.signal);
        if (!activeRequest || activeRequest.serial !== serial) return;
      }
      if (activeRequest.slowTimer) {
        window.clearTimeout(activeRequest.slowTimer);
        activeRequest.slowTimer = 0;
      }
      var panel = parsePanel(data.html);
      var effectiveTab = data.tab || requestedTab;
      var effectiveUrl = historyUrlForTab(url, effectiveTab);
      if (effectiveTab !== requestedTab) {
        updateHistory(effectiveUrl, 'replace', effectiveTab);
        setActiveTab(effectiveTab);
      }

      rememberDisplayedPanel();
      panelHost.replaceChildren(panel);
      displayedTab = effectiveTab;
      displayedUrl = effectiveUrl;
      storeCurrentEntry(panel, effectiveTab, effectiveUrl);
      contentScroll.scrollTop = 0;
      await activateScripts(panel);
      if (!activeRequest || activeRequest.serial !== serial) return;
      hydrate(panel);
      applyFragmentState(data, effectiveTab, fragmentGeneration);
      stopLoading();
      activeRequest = null;
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      if (!activeRequest || activeRequest.serial !== serial) return;
      stopLoading();
      activeRequest = null;
      showError(error && error.message);
    }
  }

  function fragmentMatchesGeneration(data, requestGeneration) {
    if (requestGeneration == null || requestGeneration === revisionGeneration) return true;
    return data && data.revision != null && String(data.revision) === revision;
  }

  function applyFragmentState(data, freshTab, requestGeneration) {
    if (!data) return true;
    if (!fragmentMatchesGeneration(data, requestGeneration)) {
      markTabStale(freshTab);
      return false;
    }
    if (data.navigation) updateNavigation(data.navigation);
    if (data.revision == null) return true;
    var nextRevision = String(data.revision);
    if (nextRevision === revision) return true;
    revision = nextRevision;
    revisionGeneration += 1;
    handleRevisionChange(freshTab || null);
    return true;
  }

  function setCount(name, value) {
    shell.querySelectorAll('[data-ranking-count="' + name + '"]').forEach(function (node) {
      var text = '';
      var hidden = false;
      if (name === 'submit') {
        hidden = !value;
        if (value) text = String(value.remaining) + '/' + String(value.limit);
      } else {
        text = value == null ? '' : String(value);
      }
      if (node.textContent !== text) node.textContent = text;
      if (node.hidden !== hidden) node.hidden = hidden;
    });
  }

  function attemptPendingHardReload() {
    if (!hardReloadPending || isDirty()) return false;
    hardReloadPending = false;
    window.location.reload();
    return true;
  }

  function requestHardReload() {
    hardReloadPending = true;
    attemptPendingHardReload();
  }

  function updateNavigation(navigation) {
    if (!navigation) return;
    if (hardReloadPending) {
      attemptPendingHardReload();
      return;
    }
    var nextMode = String(navigation.scoring_mode || '').toLowerCase();
    var currentMode = String(shell.getAttribute('data-ranking-scoring-mode') || '').toLowerCase();
    var counts = navigation.counts || {};
    var previousAttachmentCount = Number.parseInt(
      shell.getAttribute('data-ranking-attachment-count') || '0', 10
    ) || 0;
    var nextAttachmentCount = Number.parseInt(counts.attachments || '0', 10) || 0;
    if (
      (currentMode && nextMode && nextMode !== currentMode) ||
      nextAttachmentCount !== previousAttachmentCount
    ) {
      requestHardReload();
      return;
    }

    if (nextMode) {
      var modeLabels = {
        absolute: 'ABSOLUTE',
        elo: 'ELO',
        agent_judge: 'AGENT JUDGE',
        reverse_judge: 'REVERSE JUDGE'
      };
      var modeNode = shell.querySelector('[data-ranking-mode]');
      if (modeNode) modeNode.textContent = modeLabels[nextMode] || nextMode.toUpperCase();
      shell.setAttribute('data-ranking-scoring-mode', nextMode);
    }

    var permissions = navigation.permissions || {};
    shell.querySelectorAll('[data-ranking-permission]').forEach(function (node) {
      var allowed = permissions[node.getAttribute('data-ranking-permission')] !== false;
      if (node.hidden === allowed) node.hidden = !allowed;
    });
    ['submit', 'leaderboard', 'matches', 'all_submissions', 'appeals', 'attachments'].forEach(function (name) {
      setCount(name, counts[name]);
    });

    var status = shell.querySelector('[data-ranking-status]');
    if (status) {
      var active = navigation.is_active === true;
      status.classList.toggle('is-offline', !active);
      var label = status.querySelector('span');
      var text = active ? 'LIVE' : 'OFFLINE';
      if (label && label.textContent !== text) label.textContent = text;
    }
  }

  function clearNavigationFailure() {
    var notice = shell.querySelector('[data-ranking-navigation-error]');
    if (notice) notice.remove();
  }

  function showNavigationFailure(status) {
    if (status !== 401 && status !== 403 && status !== 404) return;
    var existing = shell.querySelector('[data-ranking-navigation-error]');
    var message = status === 401 ?
      '登录状态已失效，请重新登录后继续。' :
      (status === 404 ? '比赛已被删除或不再存在。' : '比赛已下线或你已失去访问权限。');
    if (existing) {
      existing.querySelector('span').textContent = message;
      return;
    }

    var notice = document.createElement('div');
    notice.className = 'ranking-navigation-alert';
    notice.setAttribute('data-ranking-navigation-error', '');
    notice.setAttribute('role', 'alert');
    var label = document.createElement('span');
    label.textContent = message;
    var action = document.createElement('a');
    action.href = (shell.querySelector('.ranking-back-link') || {}).href || detailUrl.toString();
    action.textContent = '返回打榜赛列表';
    notice.append(label, action);
    panelStage.prepend(notice);

    var statusChip = shell.querySelector('[data-ranking-status]');
    if (statusChip) {
      statusChip.classList.add('is-offline');
      var statusLabel = statusChip.querySelector('span');
      if (statusLabel) statusLabel.textContent = 'OFFLINE';
    }
  }

  function rowMap(board) {
    var result = new Map();
    board.querySelectorAll('[data-ranking-row]').forEach(function (row) {
      result.set(row.getAttribute('data-ranking-user') || '', row);
    });
    return result;
  }

  function rankNumber(row) {
    return Number.parseInt(row.getAttribute('data-ranking-rank') || '0', 10) || 0;
  }

  function normalizedContentClone(node) {
    var clone = node.cloneNode(true);
    clone.querySelectorAll(
      '.ranking-rank-delta, .ranking-leader-exit'
    ).forEach(function (transient) {
      transient.remove();
    });
    clone.querySelectorAll('[data-avatar-seed]').forEach(function (avatar) {
      avatar.replaceChildren();
      avatar.removeAttribute('title');
      avatar.removeAttribute('aria-label');
    });
    return clone;
  }

  function renderContentEqual(current, fresh) {
    if (!current || !fresh) return false;
    return normalizedContentClone(current).isEqualNode(normalizedContentClone(fresh));
  }

  function updateLeaderboard(oldBoard, newBoard) {
    if (renderContentEqual(oldBoard, newBoard)) return false;
    var oldRows = rowMap(oldBoard);
    var newRows = rowMap(newBoard);
    var oldRects = new Map();
    var oldRanks = new Map();
    var boardRect = oldBoard.getBoundingClientRect();
    var changed = 0;

    oldRows.forEach(function (row, key) {
      oldRects.set(key, row.getBoundingClientRect());
      oldRanks.set(key, rankNumber(row));
      if (!newRows.has(key)) changed += 1;
    });
    newRows.forEach(function (row, key) {
      if (!oldRows.has(key) || oldRanks.get(key) !== rankNumber(row)) changed += 1;
    });

    var animate = changed > 0 && changed <= 8 && !reducedMotion.matches;
    var exiting = [];
    if (animate) {
      oldRows.forEach(function (row, key) {
        if (newRows.has(key)) return;
        var clone = row.cloneNode(true);
        var rect = oldRects.get(key);
        clone.classList.add('ranking-leader-exit');
        clone.style.top = (rect.top - boardRect.top + oldBoard.scrollTop) + 'px';
        clone.style.height = rect.height + 'px';
        exiting.push(clone);
      });
    }

    oldBoard.replaceChildren.apply(oldBoard, Array.prototype.slice.call(newBoard.childNodes));
    paintIdenticons(oldBoard);
    var currentRows = rowMap(oldBoard);

    if (!animate) return true;

    exiting.forEach(function (clone) {
      oldBoard.appendChild(clone);
      var animation = clone.animate(
        [{opacity: 1, transform: 'translateX(0)'}, {opacity: 0, transform: 'translateX(-12px)'}],
        {duration: 300, easing: 'ease-out', fill: 'forwards'}
      );
      animation.addEventListener('finish', function () { clone.remove(); }, {once: true});
    });

    window.requestAnimationFrame(function () {
      currentRows.forEach(function (row, key) {
        var oldRect = oldRects.get(key);
        if (!oldRect) {
          row.animate(
            [{opacity: 0, transform: 'translateY(9px)'}, {opacity: 1, transform: 'translateY(0)'}],
            {duration: 320, easing: 'cubic-bezier(.22,1,.36,1)'}
          );
          return;
        }
        var newRect = row.getBoundingClientRect();
        var deltaY = oldRect.top - newRect.top;
        if (Math.abs(deltaY) > 0.5) {
          row.animate(
            [{transform: 'translateY(' + deltaY + 'px)'}, {transform: 'translateY(0)'}],
            {duration: 420, easing: 'cubic-bezier(.22,1,.36,1)'}
          );
        }
        var previousRank = oldRanks.get(key);
        var nextRank = rankNumber(row);
        if (previousRank && nextRank && previousRank !== nextRank) {
          var delta = document.createElement('span');
          var rose = previousRank > nextRank;
          delta.className = 'ranking-rank-delta' + (rose ? '' : ' is-down');
          delta.textContent = (rose ? '↑' : '↓') + Math.abs(previousRank - nextRank);
          var rankLabel = row.querySelector('.lb-rank, [data-ranking-rank-label]') || row.firstElementChild;
          if (rankLabel) rankLabel.appendChild(delta);
          window.setTimeout(function () { delta.remove(); }, 1800);
        }
      });
    });
    return true;
  }

  async function refreshWholeTab(tab) {
    var entry = cache.get(tab);
    if (!entry) return;
    if (
      entry.node &&
      (entry.node.hasAttribute('data-ranking-query-pending') ||
       entry.node.hasAttribute('data-ranking-refresh-blocked'))
    ) {
      entry.stale = true;
      entry.pendingRefresh = true;
      return;
    }
    if (entry.refreshing) {
      entry.pendingRefresh = true;
      return;
    }
    entry.refreshing = true;
    entry.pendingRefresh = false;
    var refreshGeneration = revisionGeneration;
    var refreshNode = entry.node;
    var refreshQueryGeneration = refreshNode ?
      refreshNode.getAttribute('data-ranking-query-generation') : null;
    var refreshToken = (entry.refreshToken || 0) + 1;
    entry.refreshToken = refreshToken;
    var refreshUrl = displayedTab === tab ?
      canonicalUrl(window.location.href) : canonicalUrl(entry.url);
    try {
      var data = await requestFragment(refreshUrl, null);
      if (
        cache.get(tab) !== entry ||
        entry.node !== refreshNode ||
        entry.refreshToken !== refreshToken ||
        !refreshNode ||
        displayedTab !== tab ||
        refreshNode !== directPanel() ||
        !refreshNode.isConnected
      ) {
        return;
      }
      if (!fragmentMatchesGeneration(data, refreshGeneration)) {
        entry.stale = true;
        entry.pendingRefresh = true;
        return;
      }
      if (
        refreshNode.getAttribute('data-ranking-query-generation') !== refreshQueryGeneration ||
        refreshNode.hasAttribute('data-ranking-query-pending') ||
        refreshNode.hasAttribute('data-ranking-refresh-blocked') ||
        !panelOwnsLocation(refreshNode, refreshUrl)
      ) {
        entry.stale = true;
        entry.pendingRefresh = true;
        return;
      }
      var fresh = parsePanel(data.html);
      if ((fresh.getAttribute('data-ranking-tab') || tab) !== tab) {
        entry.pendingRefresh = false;
        window.location.reload();
        return;
      }
      var savedScrollTop = contentScroll.scrollTop;
      fresh.setAttribute('data-ranking-panel-url', refreshUrl.toString());
      fresh.setAttribute('data-ranking-query-generation', refreshQueryGeneration || '0');
      refreshNode.replaceWith(fresh);
      entry.node = fresh;
      entry.url = refreshUrl;
      entry.scrollTop = savedScrollTop;
      entry.stale = false;
      await activateScripts(fresh);
      if (
        cache.get(tab) === entry &&
        entry.node === fresh &&
        entry.refreshToken === refreshToken &&
        displayedTab === tab &&
        directPanel() === fresh
      ) {
        hydrate(fresh);
        contentScroll.scrollTop = savedScrollTop;
        applyFragmentState(data, tab, refreshGeneration);
      }
    } catch (error) {
      console.warn('ranking whole-panel refresh failed:', error);
      if (entry.refreshToken === refreshToken && entry.node === refreshNode) {
        entry.stale = true;
      }
    } finally {
      if (entry.refreshToken !== refreshToken) return;
      entry.refreshing = false;
      var retry = entry.pendingRefresh && entry.stale &&
        displayedTab === tab && directPanel() === entry.node;
      var queryPending = entry.node &&
        (entry.node.hasAttribute('data-ranking-query-pending') ||
         entry.node.hasAttribute('data-ranking-refresh-blocked'));
      if (retry && queryPending) {
        entry.pendingRefresh = true;
      } else {
        entry.pendingRefresh = false;
      }
      if (retry && !queryPending) {
        window.setTimeout(function () { refreshWholeTab(tab); }, 0);
      }
    }
  }

  async function refreshReadTab(tab) {
    if (tab === 'all_submissions' || tab === 'appeals') {
      await refreshWholeTab(tab);
      return;
    }
    var entry = cache.get(tab);
    if (!entry) return;
    if (entry.node && entry.node.hasAttribute('data-ranking-query-pending')) {
      entry.stale = true;
      entry.pendingRefresh = true;
      return;
    }
    if (entry.refreshing) {
      entry.pendingRefresh = true;
      return;
    }
    entry.refreshing = true;
    entry.pendingRefresh = false;
    var applied = false;
    var refreshGeneration = revisionGeneration;
    var refreshNode = entry.node;
    var refreshQueryGeneration = refreshNode ?
      refreshNode.getAttribute('data-ranking-query-generation') : null;
    try {
      var refreshUrl = displayedTab === tab ?
        canonicalUrl(window.location.href) : canonicalUrl(entry.url);
      var data = await requestFragment(refreshUrl, null);
      if (!fragmentMatchesGeneration(data, refreshGeneration)) {
        entry.stale = true;
        entry.pendingRefresh = true;
        return;
      }
      if (
        cache.get(tab) !== entry ||
        entry.node !== refreshNode ||
        !refreshNode ||
        refreshNode.getAttribute('data-ranking-query-generation') !== refreshQueryGeneration ||
        refreshNode.hasAttribute('data-ranking-query-pending') ||
        displayedTab !== tab ||
        !panelOwnsLocation(refreshNode, refreshUrl)
      ) {
        entry.stale = true;
        entry.pendingRefresh = true;
        return;
      }
      var fresh = parsePanel(data.html);
      if (tab === 'leaderboard') {
        var oldBoard = entry.node.querySelector('[data-ranking-leaderboard]');
        var newBoard = fresh.querySelector('[data-ranking-leaderboard]');
        if (oldBoard && newBoard) updateLeaderboard(oldBoard, newBoard);
      } else {
        var oldMatches = entry.node.querySelector('#matchesDynamic');
        var newMatches = fresh.querySelector('#matchesDynamic');
        if (oldMatches && newMatches && !renderContentEqual(oldMatches, newMatches)) {
          oldMatches.replaceChildren.apply(oldMatches, Array.prototype.slice.call(newMatches.childNodes));
          hydrate(oldMatches);
        }
      }
      entry.url = refreshUrl;
      entry.node.setAttribute('data-ranking-panel-url', refreshUrl.toString());
      applied = true;
      if (applied) entry.stale = false;
      applyFragmentState(data, tab, refreshGeneration);
    } catch (error) {
      console.warn('ranking background refresh failed:', error);
    } finally {
      entry.refreshing = false;
      var retry = entry.pendingRefresh && entry.stale &&
        displayedTab === tab && directPanel() === entry.node;
      var queryPending = entry.node &&
        entry.node.hasAttribute('data-ranking-query-pending');
      if (retry && queryPending) {
        entry.pendingRefresh = true;
      } else {
        entry.pendingRefresh = false;
      }
      if (retry && !queryPending) {
        window.setTimeout(function () { refreshReadTab(tab); }, 0);
      }
    }
  }

  async function refreshSubmitHistory() {
    var entry = cache.get('submit');
    if (!entry) return;
    if (entry.refreshingHistory) {
      entry.pendingHistoryRefresh = true;
      return;
    }
    entry.refreshingHistory = true;
    entry.pendingHistoryRefresh = false;
    var refreshGeneration = revisionGeneration;
    try {
      var data = await requestFragment(entry.url, null);
      if (!fragmentMatchesGeneration(data, refreshGeneration)) {
        entry.needsHistory = true;
        entry.pendingHistoryRefresh = true;
        return;
      }
      var fresh = parsePanel(data.html);
      var oldHistory = entry.node.querySelector('[data-ranking-submission-history]');
      var newHistory = fresh.querySelector('[data-ranking-submission-history]');
      if (!oldHistory || !newHistory) {
        entry.needsHistory = false;
        entry.stale = true;
        await refreshWholeTab('submit');
        return;
      }
      if (!renderContentEqual(oldHistory, newHistory)) {
        oldHistory.replaceChildren.apply(oldHistory, Array.prototype.slice.call(newHistory.childNodes));
        hydrate(oldHistory);
      }
      entry.needsHistory = false;
      applyFragmentState(data, 'submit', refreshGeneration);
    } catch (error) {
      console.warn('ranking submission history refresh failed:', error);
    } finally {
      entry.refreshingHistory = false;
      var retry = entry.pendingHistoryRefresh && entry.needsHistory;
      entry.pendingHistoryRefresh = false;
      if (retry) {
        window.setTimeout(refreshSubmitHistory, 0);
      }
    }
  }

  function markTabStale(tab) {
    var entry = cache.get(tab);
    if (!entry) return;
    if (
      tab === 'leaderboard' || tab === 'matches' ||
      tab === 'all_submissions' || tab === 'appeals'
    ) {
      entry.stale = true;
      if (entry.refreshing) entry.pendingRefresh = true;
      else if (displayedTab === tab) refreshReadTab(tab);
      return;
    }
    if (tab === 'submit') {
      entry.needsHistory = true;
      if (entry.refreshingHistory) entry.pendingHistoryRefresh = true;
      else if (displayedTab === 'submit') refreshSubmitHistory();
      return;
    }
  }

  function handleRevisionChange(freshTab) {
    ['leaderboard', 'matches'].forEach(function (tab) {
      if (tab === freshTab) return;
      markTabStale(tab);
    });
    if (freshTab !== 'submit') markTabStale('submit');
    ['all_submissions', 'appeals'].forEach(function (tab) {
      if (tab === freshTab) return;
      markTabStale(tab);
    });
  }

  async function pollNavigationState() {
    if (document.hidden || pollPromise || activeRequest) return;
    pollPromise = window.fetch(navigationUrl, {
      credentials: 'same-origin',
      headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
      cache: 'no-store',
      mathCurveLoader: false
    }).then(function (response) {
      return response.json().catch(function () {
        return {};
      }).then(function (data) {
        if (!response.ok) {
          var error = new Error(data.message || ('navigation state ' + response.status));
          error.status = response.status;
          throw error;
        }
        return data;
      });
    }).then(function (data) {
      if (!data.success) throw new Error(data.message || 'navigation state failed');
      clearNavigationFailure();
      var nextRevision = String(data.revision == null ? '' : data.revision);
      if (nextRevision === revision) return;
      revision = nextRevision;
      revisionGeneration += 1;
      updateNavigation(data.navigation);
      handleRevisionChange();
    }).catch(function (error) {
      showNavigationFailure(error && error.status);
      console.warn('ranking navigation poll failed:', error);
    }).finally(function () {
      pollPromise = null;
    });
    return pollPromise;
  }

  function panelIsDirty(root) {
    if (!root) return false;
    if (
      root.matches('[data-ranking-dirty-managed][data-ranking-dirty="true"]') ||
      root.querySelector('[data-ranking-dirty-managed][data-ranking-dirty="true"]')
    ) {
      return true;
    }

    var controls = root.querySelectorAll('input, select, textarea');
    for (var index = 0; index < controls.length; index += 1) {
      var control = controls[index];
      if (control.disabled || !isDirtyControl(control)) continue;
      if (!controlBaselines.has(control)) captureControl(control);
      if (controlBaselines.get(control) !== controlState(control)) return true;
    }
    return false;
  }

  function isDirty() {
    var roots = new Set();
    var current = directPanel();
    if (current) roots.add(current);
    cache.forEach(function (entry) {
      if (entry.node) roots.add(entry.node);
    });
    return Array.from(roots).some(panelIsDirty);
  }

  function focusableRailItems() {
    return Array.prototype.filter.call(
      rail.querySelectorAll('a[href]:not([hidden]), button:not([disabled]):not([hidden])'),
      function (item) { return item.offsetParent !== null; }
    );
  }

  function setRailBackgroundInert(active) {
    if (active) {
      [
        shell.querySelector('.ranking-competition-header'),
        contentScroll,
        document.querySelector('[data-numoj-sidebar]'),
        document.querySelector('[data-bs-target="#offcanvasNavbar"]'),
        document.querySelector('#offcanvasNavbar')
      ].filter(Boolean).forEach(function (target) {
        if (railInertState.has(target)) return;
        railInertState.set(target, {
          inert: Boolean(target.inert),
          ariaHidden: target.getAttribute('aria-hidden')
        });
        target.inert = true;
        target.setAttribute('aria-hidden', 'true');
      });
      return;
    }
    railInertState.forEach(function (previous, target) {
      target.inert = previous.inert;
      if (previous.ariaHidden == null) target.removeAttribute('aria-hidden');
      else target.setAttribute('aria-hidden', previous.ariaHidden);
    });
    railInertState.clear();
  }

  function syncRailMode() {
    if (mobileRail.matches) {
      var open = rail.classList.contains('is-open');
      rail.setAttribute('aria-hidden', open ? 'false' : 'true');
      rail.setAttribute('role', 'dialog');
      rail.setAttribute('aria-modal', 'true');
    } else {
      setRailBackgroundInert(false);
      rail.classList.remove('is-open');
      rail.setAttribute('aria-hidden', 'false');
      rail.removeAttribute('role');
      rail.removeAttribute('aria-modal');
      railBackdrop.hidden = true;
      document.body.classList.remove('ranking-rail-is-open');
      railOpenButton.setAttribute('aria-expanded', 'false');
    }
  }

  function revealRail(token) {
    if (token !== railOpenToken || !mobileRail.matches) return;
    rail.classList.add('is-open');
    rail.setAttribute('aria-hidden', 'false');
    railBackdrop.hidden = false;
    railOpenButton.setAttribute('aria-expanded', 'true');
    document.body.classList.add('ranking-rail-is-open');
    setRailBackgroundInert(true);
    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        if (token !== railOpenToken) return;
        (railCloseButton || focusableRailItems()[0]).focus();
      });
    });
  }

  function openRail() {
    if (!mobileRail.matches) return;
    previousRailFocus = document.activeElement;
    var token = ++railOpenToken;
    var openOffcanvas = document.querySelector('.offcanvas.show');
    if (openOffcanvas && window.bootstrap) {
      var finished = false;
      var afterHidden = function () {
        if (finished) return;
        finished = true;
        revealRail(token);
      };
      openOffcanvas.addEventListener('hidden.bs.offcanvas', afterHidden, {once: true});
      window.bootstrap.Offcanvas.getOrCreateInstance(openOffcanvas).hide();
      window.setTimeout(afterHidden, 360);
      return;
    }
    revealRail(token);
  }

  function closeRail() {
    railOpenToken += 1;
    var wasOpen = rail.classList.contains('is-open');
    setRailBackgroundInert(false);
    rail.classList.remove('is-open');
    railBackdrop.hidden = true;
    railOpenButton.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('ranking-rail-is-open');
    if (mobileRail.matches) rail.setAttribute('aria-hidden', 'true');
    if (wasOpen && previousRailFocus && previousRailFocus.focus) previousRailFocus.focus();
  }

  function trapRailFocus(event) {
    if (event.key !== 'Tab' || !rail.classList.contains('is-open')) return;
    var items = focusableRailItems();
    if (!items.length) return;
    var first = items[0];
    var last = items[items.length - 1];
    if (!rail.contains(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function layoutAttachments() {
    var section = rail.querySelector('[data-ranking-attachments]');
    if (!section) return;
    var rows = Array.prototype.slice.call(section.querySelectorAll('[data-ranking-attachment-row]'));
    var toggle = section.querySelector('[data-ranking-attachments-toggle]');
    if (!rows.length || !toggle) return;
    var expanded = section.getAttribute('data-expanded') === 'true';
    rows.forEach(function (row) { row.hidden = false; });
    if (expanded) {
      toggle.hidden = false;
      toggle.textContent = '收起附件';
      toggle.setAttribute('aria-expanded', 'true');
      return;
    }

    toggle.hidden = true;
    var sectionStyle = window.getComputedStyle(section);
    var bottomPadding = Number.parseFloat(sectionStyle.paddingBottom) || 0;
    var available = rail.clientHeight - section.offsetTop - bottomPadding - 18;
    var label = section.querySelector('.ranking-attachment-label');
    var labelHeight = label ? label.getBoundingClientRect().height + 8 : 0;
    var totalHeight = rows.reduce(function (sum, row) {
      return sum + row.getBoundingClientRect().height;
    }, 0);
    if (labelHeight + totalHeight <= available) return;

    toggle.hidden = false;
    toggle.textContent = '查看全部 ' + toggle.getAttribute('data-total') + ' 个';
    toggle.setAttribute('aria-expanded', 'false');
    var toggleStyle = window.getComputedStyle(toggle);
    var toggleHeight = toggle.getBoundingClientRect().height +
      (Number.parseFloat(toggleStyle.marginTop) || 0);
    var budget = Math.max(0, available - labelHeight - toggleHeight);
    var used = 0;
    rows.forEach(function (row, index) {
      var rowHeight = row.getBoundingClientRect().height;
      var visible = used + rowHeight <= budget;
      if (index === 0 && budget > 0) visible = true;
      row.hidden = !visible;
      if (visible) used += rowHeight;
    });
  }

  function scheduleAttachmentLayout() {
    window.requestAnimationFrame(layoutAttachments);
  }

  markInitialScripts(panelHost);
  var initialPanel = directPanel();
  displayedUrl = historyUrlForTab(displayedUrl, initialTab);
  updateHistory(displayedUrl, 'replace', initialTab);
  if (initialPanel) {
    hydrate(initialPanel);
    storeCurrentEntry(initialPanel, initialTab, displayedUrl);
  }
  setActiveTab(initialTab);
  syncRailMode();
  scheduleAttachmentLayout();

  shell.addEventListener('click', function (event) {
    var tabLink = event.target.closest('[data-ranking-tab-link]');
    if (tabLink && shell.contains(tabLink)) {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      navigate(tabLink.href, {history: 'push'});
      return;
    }
    var retry = event.target.closest('[data-ranking-retry]');
    if (retry) {
      event.preventDefault();
      navigate(window.location.href, {history: 'replace', force: true});
    }
  });

  document.addEventListener('click', function (event) {
    if (event.defaultPrevented || event.button !== 0 ||
        event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    var link = event.target.closest('a[href]');
    if (!link || link.hasAttribute('download')) return;
    if (link.target && link.target !== '_self') return;
    var url;
    try { url = canonicalUrl(link.href); } catch (_error) { return; }
    if (!sameDetailPath(url)) {
      if (url.origin !== window.location.origin || !isDirty()) return;
      event.preventDefault();
      if (!window.confirm('当前页面有尚未保存的修改，确认离开吗？')) return;
      unloadAllowed = true;
      window.location.assign(url.toString());
      return;
    }
    if (!panelHost.contains(link)) return;
    event.preventDefault();
    navigate(url, {history: 'push'});
  });

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var method = (form.method || 'get').toLowerCase();
    if (method !== 'get') {
      unloadAllowed = true;
      window.setTimeout(function () {
        if (event.defaultPrevented) unloadAllowed = false;
      }, 0);
      return;
    }
    if (!panelHost.contains(form) || event.defaultPrevented) return;
    var url = new URL(form.action || detailUrl, window.location.href);
    if (!sameDetailPath(url)) return;
    event.preventDefault();
    url.search = '';
    new FormData(form, event.submitter).forEach(function (value, key) {
      url.searchParams.append(key, String(value));
    });
    navigate(url, {history: 'push'});
  });

  window.addEventListener('popstate', function () {
    var url = canonicalUrl(window.location.href);
    if (sameDetailPath(url)) navigate(url, {history: 'none'});
  });

  window.addEventListener('ranking:query-start', function (event) {
    startQueryRequest(event.detail);
  });
  window.addEventListener('ranking:query-commit', function (event) {
    commitQueryRequest(event.detail);
  });
  window.addEventListener('ranking:query-settle', function (event) {
    settleQueryRequest(event.detail);
  });
  window.addEventListener('ranking:refresh-resume', function (event) {
    resumePendingPanelRefresh(event.detail && event.detail.panel);
  });
  window.addEventListener('ranking:allow-unload', function () {
    unloadAllowed = true;
  });
  function schedulePendingHardReload() {
    if (!hardReloadPending) return;
    window.setTimeout(attemptPendingHardReload, 0);
  }
  document.addEventListener('input', schedulePendingHardReload);
  document.addEventListener('change', schedulePendingHardReload);
  document.addEventListener('reset', schedulePendingHardReload);
  window.addEventListener('ranking:dirty-state-change', schedulePendingHardReload);

  window.addEventListener('beforeunload', function (event) {
    if (unloadAllowed || !isDirty()) return;
    event.preventDefault();
    event.returnValue = '';
  });

  railOpenButton.addEventListener('click', openRail);
  railCloseButton.addEventListener('click', closeRail);
  railBackdrop.addEventListener('click', closeRail);
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') closeRail();
    else trapRailFocus(event);
  });
  document.addEventListener('show.bs.offcanvas', closeRail);

  var attachmentToggle = rail.querySelector('[data-ranking-attachments-toggle]');
  if (attachmentToggle) {
    attachmentToggle.addEventListener('click', function () {
      var section = attachmentToggle.closest('[data-ranking-attachments]');
      var expanded = section.getAttribute('data-expanded') !== 'true';
      section.setAttribute('data-expanded', expanded ? 'true' : 'false');
      layoutAttachments();
      if (!expanded) rail.scrollTop = 0;
    });
  }

  if (window.ResizeObserver) {
    var attachmentObserver = new ResizeObserver(scheduleAttachmentLayout);
    attachmentObserver.observe(rail);
    attachmentObserver.observe(rail.querySelector('.ranking-rail-nav'));
  } else {
    window.addEventListener('resize', scheduleAttachmentLayout);
  }

  if (typeof mobileRail.addEventListener === 'function') {
    mobileRail.addEventListener('change', function () {
      syncRailMode();
      scheduleAttachmentLayout();
    });
  }

  window.addEventListener('focus', pollNavigationState);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) pollNavigationState();
  });
  pollTimer = window.setInterval(pollNavigationState, 10000);
  window.addEventListener('pagehide', function () {
    window.clearInterval(pollTimer);
    abortNavigation();
  }, {once: true});
}());
