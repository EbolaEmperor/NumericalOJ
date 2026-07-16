(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DEFAULT_PALETTE = ['#111111', '#000000'];
  const PALETTES = [
    ['#2563eb', '#7c3aed'],
    ['#0891b2', '#2563eb'],
    ['#f97316', '#db2777'],
    ['#059669', '#06b6d4'],
    ['#7c3aed', '#ec4899'],
    ['#dc2626', '#f59e0b'],
    ['#4f46e5', '#22d3ee'],
    ['#e11d48', '#9333ea']
  ];

  // 从画廊前 8 个动画中排除 Rose Curve 与 Rose Four：
  // 保留三个重花环、Rose Orbit、Rose Two、Rose Three，并加入 Spiral Search。
  const CURVES = [
    customRose(7, 64, 0.38, 4600, 4200, 28000),
    customRose(5, 62, 0.38, 4600, 4200, 28000),
    customRose(9, 68, 0.39, 4700, 4200, 30000),
    {
      particleCount: 72,
      trailSpan: 0.42,
      durationMs: 5200,
      pulseDurationMs: 4600,
      rotationDurationMs: 28000,
      strokeWidth: 5.2,
      point(progress, detailScale) {
        const t = progress * Math.PI * 2;
        const r = 7 - 2.7 * detailScale * Math.cos(7 * t);
        return { x: 50 + Math.cos(t) * r * 3.9, y: 50 + Math.sin(t) * r * 3.9 };
      }
    },
    polarRose(2, 74, 0.30, 5200, 4300, 4.6),
    polarRose(3, 76, 0.31, 5300, 4400, 4.6),
    spiralSearch()
  ];

  const instances = new Set();
  let animationFrame = 0;
  let gradientSerial = 0;
  let lastInteractionAt = 0;
  let lastInteractionTarget = null;
  let overlay = null;
  const overlayRequests = new Map();

  function customRose(petals, particleCount, trailSpan, durationMs, pulseDurationMs, rotationDurationMs) {
    return {
      particleCount,
      trailSpan,
      durationMs,
      pulseDurationMs,
      rotationDurationMs,
      strokeWidth: 5.5,
      point(progress, detailScale) {
        const t = progress * Math.PI * 2;
        const x = 7 * Math.cos(t) - 3 * detailScale * Math.cos(petals * t);
        const y = 7 * Math.sin(t) - 3 * detailScale * Math.sin(petals * t);
        return { x: 50 + x * 3.9, y: 50 + y * 3.9 };
      }
    };
  }

  function polarRose(petals, particleCount, trailSpan, durationMs, pulseDurationMs, strokeWidth) {
    return {
      particleCount,
      trailSpan,
      durationMs,
      pulseDurationMs,
      rotationDurationMs: 28000,
      strokeWidth,
      point(progress, detailScale) {
        const t = progress * Math.PI * 2;
        const a = 9.2 + detailScale * 0.6;
        const r = a * (0.72 + detailScale * 0.28) * Math.cos(petals * t);
        return { x: 50 + Math.cos(t) * r * 3.25, y: 50 + Math.sin(t) * r * 3.25 };
      }
    };
  }

  function spiralSearch() {
    return {
      particleCount: 86,
      trailSpan: 0.28,
      durationMs: 7800,
      pulseDurationMs: 6800,
      rotationDurationMs: 44000,
      strokeWidth: 4.3,
      rotate: false,
      point(progress, detailScale) {
        const t = progress * Math.PI * 2;
        const angle = t * 4;
        const radius = 8 + (1 - Math.cos(t)) * (8.5 + detailScale * 2.4);
        return {
          x: 50 + Math.cos(angle) * radius,
          y: 50 + Math.sin(angle) * radius
        };
      }
    };
  }

  function normalizeProgress(progress) {
    return ((progress % 1) + 1) % 1;
  }

  function detailScale(time, config, phaseOffset) {
    const progress = ((time + phaseOffset * config.pulseDurationMs) % config.pulseDurationMs) /
      config.pulseDurationMs;
    return 0.52 + ((Math.sin(progress * Math.PI * 2 + 0.55) + 1) / 2) * 0.48;
  }

  function pointOnTrail(config, particleCount, index, progress, scale, strokeScale) {
    const tailOffset = index / Math.max(1, particleCount - 1);
    const point = config.point(normalizeProgress(progress - tailOffset * config.trailSpan), scale);
    const fade = Math.pow(1 - tailOffset, 0.56);
    return {
      x: point.x,
      y: point.y,
      radius: (0.9 + fade * 2.7) * strokeScale,
      opacity: 0.04 + fade * 0.96
    };
  }

  function buildPath(config, scale) {
    const segments = 150;
    const commands = [];
    for (let index = 0; index <= segments; index += 1) {
      const point = config.point(index / segments, scale);
      commands.push(`${index === 0 ? 'M' : 'L'} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`);
    }
    return commands.join(' ');
  }

  function createSvg(instance) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'math-curve-loader__svg');
    svg.setAttribute('viewBox', '0 0 100 100');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('aria-hidden', 'true');

    const gradientId = `math-curve-gradient-${gradientSerial += 1}`;
    const defs = document.createElementNS(SVG_NS, 'defs');
    const gradient = document.createElementNS(SVG_NS, 'linearGradient');
    gradient.setAttribute('id', gradientId);
    gradient.setAttribute('x1', '10%');
    gradient.setAttribute('y1', '5%');
    gradient.setAttribute('x2', '90%');
    gradient.setAttribute('y2', '95%');
    const firstStop = document.createElementNS(SVG_NS, 'stop');
    firstStop.setAttribute('offset', '0%');
    firstStop.style.stopColor = 'var(--math-curve-color-a)';
    const secondStop = document.createElementNS(SVG_NS, 'stop');
    secondStop.setAttribute('offset', '100%');
    secondStop.style.stopColor = 'var(--math-curve-color-b)';
    gradient.append(firstStop, secondStop);
    defs.appendChild(gradient);
    svg.appendChild(defs);

    const group = document.createElementNS(SVG_NS, 'g');
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('stroke', `url(#${gradientId})`);
    path.setAttribute('stroke-width', String(instance.config.strokeWidth * instance.strokeScale));
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    path.setAttribute('opacity', '0');
    group.appendChild(path);

    const particles = [];
    for (let index = 0; index < instance.particleCount; index += 1) {
      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('fill', `url(#${gradientId})`);
      group.appendChild(circle);
      particles.push(circle);
    }
    svg.appendChild(group);
    instance.group = group;
    instance.path = path;
    instance.particles = particles;
    return svg;
  }

  function mount(element) {
    if (!element || element.dataset.mathCurveMounted === '1') return element;
    element.dataset.mathCurveMounted = '1';
    element.classList.add('math-curve-loader');
    if (!element.dataset.size) element.dataset.size = 'sm';
    if (!element.hasAttribute('role')) element.setAttribute('role', 'status');
    element.setAttribute('aria-live', 'polite');

    const requestedPalette = Number(element.dataset.palette);
    const palette = Number.isInteger(requestedPalette)
      ? PALETTES[Math.abs(requestedPalette) % PALETTES.length]
      : DEFAULT_PALETTE;
    const styleScope = element.closest(
      '[data-math-curve-color-a], [data-math-curve-color-b], [data-math-curve-stroke-scale]'
    );
    const scopedColorA = styleScope ? styleScope.dataset.mathCurveColorA : '';
    const scopedColorB = styleScope ? styleScope.dataset.mathCurveColorB : '';
    element.style.setProperty('--math-curve-color-a', element.dataset.colorA || scopedColorA || palette[0]);
    element.style.setProperty('--math-curve-color-b', element.dataset.colorB || scopedColorB || palette[1]);

    const scopedStrokeScale = styleScope ? styleScope.dataset.mathCurveStrokeScale : '';
    const requestedStrokeScale = Number(element.dataset.strokeScale || scopedStrokeScale);
    const strokeScale = Number.isFinite(requestedStrokeScale) && requestedStrokeScale > 0
      ? Math.min(requestedStrokeScale, 3)
      : 1;

    const requestedCurve = Number(element.dataset.curve);
    const curveIndex = Number.isInteger(requestedCurve)
      ? Math.abs(requestedCurve) % CURVES.length
      : Math.floor(Math.random() * CURVES.length);
    const instance = {
      element,
      config: CURVES[curveIndex],
      strokeScale,
      particleCount: ({xs: 24, sm: 36, md: 52, lg: CURVES[curveIndex].particleCount})[element.dataset.size] || 36,
      startTime: performance.now(),
      phaseOffset: Math.random(),
      lastPathAt: 0
    };
    const canvas = document.createElement('span');
    canvas.className = 'math-curve-loader__canvas';
    canvas.appendChild(createSvg(instance));
    element.prepend(canvas);

    if (element.dataset.iconOnly !== 'true' && !element.querySelector('.math-curve-loader__label')) {
      const label = document.createElement('span');
      label.className = 'math-curve-loader__label';
      label.textContent = element.dataset.label || '正在处理…';
      element.appendChild(label);
    }
    instances.add(instance);
    startAnimation();
    return element;
  }

  function render(instance, now, reducedMotion) {
    if (!instance.element.isConnected) {
      instances.delete(instance);
      return;
    }
    if (!reducedMotion && instance.element.getClientRects().length === 0) return;
    const time = reducedMotion ? 0 : now - instance.startTime;
    const config = instance.config;
    const progress = ((time + instance.phaseOffset * config.durationMs) % config.durationMs) /
      config.durationMs;
    const scale = detailScale(time, config, instance.phaseOffset);
    const rotation = reducedMotion || config.rotate === false ? 0 : -(
      ((time + instance.phaseOffset * config.rotationDurationMs) % config.rotationDurationMs) /
      config.rotationDurationMs
    ) * 360;
    instance.group.setAttribute('transform', `rotate(${rotation} 50 50)`);
    if (reducedMotion || now - instance.lastPathAt >= 50) {
      instance.path.setAttribute('d', buildPath(config, scale));
      instance.lastPathAt = now;
    }
    instance.particles.forEach((particleNode, index) => {
      const particle = pointOnTrail(
        config,
        instance.particleCount,
        index,
        progress,
        scale,
        instance.strokeScale
      );
      particleNode.setAttribute('cx', particle.x.toFixed(2));
      particleNode.setAttribute('cy', particle.y.toFixed(2));
      particleNode.setAttribute('r', particle.radius.toFixed(2));
      particleNode.setAttribute('opacity', particle.opacity.toFixed(3));
    });
  }

  function tick(now) {
    animationFrame = 0;
    if (document.hidden || instances.size === 0) return;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    instances.forEach(instance => render(instance, now, reducedMotion));
    if (!reducedMotion && instances.size > 0) animationFrame = requestAnimationFrame(tick);
  }

  function startAnimation() {
    if (animationFrame || document.hidden || instances.size === 0) return;
    animationFrame = requestAnimationFrame(tick);
  }

  function hydrate(root) {
    if (!root) return;
    if (root.nodeType === 1 && root.matches('[data-math-curve-loader]')) mount(root);
    if (root.querySelectorAll) root.querySelectorAll('[data-math-curve-loader]').forEach(mount);
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function markup(label, size, className) {
    return `<span class="math-curve-loader ${escapeHtml(className || '')}" data-math-curve-loader data-size="${escapeHtml(size || 'sm')}">` +
      `<span class="math-curve-loader__label">${escapeHtml(label || '正在处理…')}</span></span>`;
  }

  function replace(target, label, options) {
    if (!target) return null;
    const settings = options || {};
    target.innerHTML = markup(label, settings.size || 'sm', settings.className || '');
    const loader = target.querySelector('[data-math-curve-loader]');
    return mount(loader);
  }

  function update(target, label, options) {
    if (!target) return null;
    const settings = options || {};
    const loader = target.matches && target.matches('[data-math-curve-loader]')
      ? target
      : target.querySelector && target.querySelector('[data-math-curve-loader]');
    if (!loader) return replace(target, label, settings);
    if (settings.size) loader.dataset.size = settings.size;
    const labelElement = loader.querySelector('.math-curve-loader__label');
    if (labelElement) labelElement.textContent = label || '正在处理…';
    return loader;
  }

  function ensureOverlay() {
    if (overlay && overlay.isConnected) return overlay;
    overlay = document.createElement('div');
    overlay.className = 'math-curve-loader-overlay';
    overlay.setAttribute('aria-hidden', 'true');
    overlay.innerHTML = '<div class="math-curve-loader-overlay__card"></div>';
    document.body.appendChild(overlay);
    return overlay;
  }

  function begin(label, options) {
    const settings = options || {};
    const token = Symbol('math-curve-request');
    const state = { shown: false, timer: 0, label: label || '正在处理…' };
    overlayRequests.set(token, state);
    state.timer = window.setTimeout(() => {
      if (!overlayRequests.has(token)) return;
      state.shown = true;
      const layer = ensureOverlay();
      replace(layer.querySelector('.math-curve-loader-overlay__card'), state.label, {
        size: 'lg'
      });
      layer.classList.add('is-visible');
      layer.setAttribute('aria-hidden', 'false');
    }, Math.max(0, Number(settings.delay == null ? 180 : settings.delay)));

    return function end() {
      const current = overlayRequests.get(token);
      if (!current) return;
      window.clearTimeout(current.timer);
      overlayRequests.delete(token);
      if (current.shown && !Array.from(overlayRequests.values()).some(item => item.shown)) {
        const layer = ensureOverlay();
        layer.classList.remove('is-visible');
        layer.setAttribute('aria-hidden', 'true');
      }
    };
  }

  function interactionLabel() {
    if (!lastInteractionTarget || !lastInteractionTarget.closest) return '正在处理…';
    const actionable = lastInteractionTarget.closest('[data-loader-label], button, input[type="submit"], a');
    if (!actionable) return '正在处理…';
    if (actionable.dataset.loaderLabel) return actionable.dataset.loaderLabel;
    const text = (actionable.textContent || actionable.value || '').trim().replace(/\s+/g, ' ');
    return text ? `${text.replace(/[.…]+$/, '')}中…` : '正在处理…';
  }

  function trackInteraction(event) {
    if (!event.isTrusted) return;
    lastInteractionAt = performance.now();
    lastInteractionTarget = event.target;
  }

  function installFetchTracking() {
    if (!window.fetch || window.fetch.__mathCurveTracked) return;
    const originalFetch = window.fetch.bind(window);
    const trackedFetch = function (input, init) {
      let requestInit = init;
      const explicit = init && Object.prototype.hasOwnProperty.call(init, 'mathCurveLoader')
        ? init.mathCurveLoader
        : undefined;
      if (explicit !== undefined) {
        requestInit = Object.assign({}, init);
        delete requestInit.mathCurveLoader;
      }
      const recentInteraction = performance.now() - lastInteractionAt < 900;
      const shouldShow = explicit === true || (explicit !== false && recentInteraction);
      const end = shouldShow ? begin(interactionLabel()) : null;
      let result;
      try {
        result = originalFetch(input, requestInit);
      } catch (error) {
        if (end) end();
        throw error;
      }
      return Promise.resolve(result).finally(() => { if (end) end(); });
    };
    trackedFetch.__mathCurveTracked = true;
    window.fetch = trackedFetch;
  }

  function installNavigationTracking() {
    document.addEventListener('submit', event => {
      window.setTimeout(() => {
        const form = event.target;
        if (event.defaultPrevented || !form || form.dataset.noMathCurveLoader === 'true') return;
        if (form.target && form.target !== '_self') return;
        begin(form.dataset.loaderLabel || '正在提交…', { delay: 120 });
      }, 0);
    });

    document.addEventListener('click', event => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = event.target.closest && event.target.closest('a[href]');
      if (!link || link.dataset.noMathCurveLoader === 'true' || link.hasAttribute('download')) return;
      if (link.target && link.target !== '_self') return;
      const href = link.getAttribute('href') || '';
      if (!href || href === '#' || href.startsWith('#') || href.startsWith('javascript:')) return;
      let destination;
      try { destination = new URL(link.href, window.location.href); } catch (error) { return; }
      if (destination.origin !== window.location.origin) return;
      window.setTimeout(() => {
        if (!event.defaultPrevented) begin(link.dataset.loaderLabel || '正在加载页面…', { delay: 140 });
      }, 0);
    });
  }

  window.MathCurveLoader = {
    begin,
    hydrate,
    markup,
    mount,
    replace,
    update,
    withOverlay(promise, label, options) {
      const end = begin(label, options);
      return Promise.resolve(promise).finally(end);
    }
  };

  document.addEventListener('pointerdown', trackInteraction, true);
  document.addEventListener('click', trackInteraction, true);
  document.addEventListener('keydown', trackInteraction, true);
  document.addEventListener('change', trackInteraction, true);
  document.addEventListener('input', trackInteraction, true);
  document.addEventListener('visibilitychange', startAnimation);
  window.addEventListener('pageshow', () => {
    overlayRequests.clear();
    if (overlay) {
      overlay.classList.remove('is-visible');
      overlay.setAttribute('aria-hidden', 'true');
    }
  });

  installFetchTracking();
  installNavigationTracking();

  const initialize = function () {
    hydrate(document);
    const observer = new MutationObserver(records => {
      records.forEach(record => record.addedNodes.forEach(node => hydrate(node)));
    });
    observer.observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize, { once: true });
  } else {
    initialize();
  }
})();
