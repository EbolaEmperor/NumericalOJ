(() => {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const STRIDE = 63;
  const MAX_VISIBLE = 31;
  const TIMING = { insert: 700, pop: 450, replace: 360, swap: 200, top: 500, idle: 300 };

  function create({ heapA, heapB, conveyor, inputs, reducedMotion = () => false }) {
    const document = heapA.ownerDocument;
    const belt = conveyor.parentElement?.querySelector('.belt-line');
    const records = new Map();
    const blocks = new Map();
    const inputOrigins = new Map();
    const active = new Set();
    let offset = 0;
    let rate = 1;
    let lastFrame;

    function svg(name, attrs = {}, text) {
      const element = document.createElementNS(NS, name);
      Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, String(value)));
      if (text !== undefined) element.textContent = text;
      return element;
    }

    const heaps = [heapA, heapB].map((element) => {
      const edges = svg('g', { class: 'heap-edges' });
      const nodes = svg('g', { class: 'heap-nodes' });
      const notes = svg('g', { class: 'heap-notes' });
      element.replaceChildren(edges, nodes, notes);
      return { element, edges, nodes, notes, edgeRecords: new Map() };
    });

    function animate(element, keyframes, duration, cleanup) {
      let cleaned = false;
      const finishCleanup = () => {
        if (cleaned) return;
        cleaned = true;
        cleanup?.();
      };
      if (!duration || reducedMotion() || typeof element.animate !== 'function') {
        finishCleanup();
        return Promise.resolve();
      }
      let animation;
      try {
        animation = element.animate(keyframes, {
          duration, easing: 'cubic-bezier(.22,.68,.22,1)', fill: 'none',
        });
        animation.playbackRate = rate;
      } catch {
        finishCleanup();
        return Promise.resolve();
      }
      const record = { animation, finishCleanup };
      active.add(record);
      return Promise.resolve(animation.finished).catch(() => {}).then(() => {
        active.delete(record);
        finishCleanup();
      });
    }

    function settleAnimations(cancel = false) {
      for (const record of [...active]) {
        try { cancel ? record.animation.cancel() : record.animation.finish(); } catch { /* 已结束的动画无需处理。 */ }
        record.finishCleanup();
        active.delete(record);
      }
    }

    function matrix(element) {
      const value = element.getScreenCTM?.();
      if (value && Number.isFinite(value.a) && value.a * value.d - value.b * value.c) return value;
      const bounds = element.getBoundingClientRect();
      const scale = Math.min((bounds.width || 400) / 400, (bounds.height || 245) / 245);
      return { a: scale, b: 0, c: 0, d: scale,
        e: bounds.left + ((bounds.width || 400) - 400 * scale) / 2,
        f: bounds.top + ((bounds.height || 245) - 245 * scale) / 2 };
    }

    function screenPoint(element, x, y) {
      const m = matrix(element);
      return { x: m.a * x + m.c * y + m.e, y: m.b * x + m.d * y + m.f };
    }

    function localPoint(element, x, y) {
      const m = matrix(element);
      const determinant = m.a * m.d - m.b * m.c;
      return { x: (m.d * (x - m.e) - m.c * (y - m.f)) / determinant,
        y: (-m.b * (x - m.e) + m.a * (y - m.f)) / determinant };
    }

    function nodeRect(record) {
      const point = screenPoint(record.svg, record.x, record.y);
      const m = matrix(record.svg);
      const width = 2 * record.radius * Math.hypot(m.a, m.b);
      const height = 2 * record.radius * Math.hypot(m.c, m.d);
      return { left: point.x - width / 2, top: point.y - height / 2, width, height };
    }

    function oldOrigin(id, before) {
      if (before.has(id)) return before.get(id);
      const record = records.get(id);
      if (record?.lastRect) return record.lastRect;
      for (const [name, heap] of [['left', heapA], ['right', heapB]]) {
        if (lastFrame?.[name]?.some((node) => node.id === id)) {
          const p = screenPoint(heap, 200, 238);
          return { left: p.x - 12, top: p.y - 12, width: 24, height: 24 };
        }
      }
      return undefined;
    }

    function renderConveyor(frame, duration) {
      const jobs = [];
      const values = inputs() || [];
      const nextOffset = Math.max(0, Math.min(values.length, frame.conveyorOffset ?? (frame.round || 0) + (frame.checked ? 1 : 0)));
      const oldOffset = offset;
      const wanted = new Set();
      for (let index = nextOffset; index < Math.min(values.length, nextOffset + 11); index++) wanted.add(index);
      // 让刚离开的方块也走完这一格，再从裁剪窗口移除。
      if (duration) for (const index of blocks.keys()) if (index < nextOffset && index >= oldOffset) wanted.add(index);
      conveyor.querySelector('.quiet')?.remove();
      for (const index of wanted) {
        let record = blocks.get(index);
        if (!record) {
          const element = document.createElement('div');
          element.className = 'number-block';
          element.setAttribute('data-input-index', String(index));
          element.textContent = values[index];
          conveyor.append(element);
          record = { element, x: (index - oldOffset) * STRIDE };
          blocks.set(index, record);
        }
        const from = record.x;
        const to = (index - nextOffset) * STRIDE;
        record.element.classList.toggle('is-current', index === nextOffset);
        record.element.classList.toggle('active', Boolean(frame.entering) && index === nextOffset);
        record.element.style.transform = `translate3d(${to}px, 0, 0)`;
        record.x = to;
        const cleanup = () => {
          if (index < offset && blocks.get(index) === record) {
            record.element.remove();
            blocks.delete(index);
          }
        };
        if (duration && from !== to) {
          jobs.push(animate(record.element, [
            { transform: `translate3d(${from}px, 0, 0)` },
            { transform: `translate3d(${to}px, 0, 0)` },
          ], duration, cleanup));
        } else if (index < nextOffset) cleanup();
      }
      for (const [index, record] of blocks) {
        if (!wanted.has(index)) { record.element.remove(); blocks.delete(index); }
      }
      if (belt) {
        belt.style.backgroundPosition = `${-nextOffset * STRIDE}px 0px`;
        if (duration && oldOffset !== nextOffset) jobs.push(animate(belt, [
          { backgroundPosition: `${-oldOffset * STRIDE}px 0px` },
          { backgroundPosition: `${-nextOffset * STRIDE}px 0px` },
        ], duration));
      }
      offset = nextOffset;
      if (offset >= values.length && values.length) {
        const text = document.createElement('span');
        text.className = 'quiet';
        text.textContent = '本次输入已全部处理';
        conveyor.append(text);
      }
      return jobs;
    }

    function layout(items) {
      const shown = items.filter((node, index) => (node.index ?? index) < MAX_VISIBLE);
      const maxSlot = Math.max(0, ...shown.map((node, index) => node.index ?? index));
      const depth = Math.floor(Math.log2(maxSlot + 1));
      const gap = depth > 3 ? 43 : 53;
      const radius = depth > 3 ? 12 : depth > 2 ? 15 : 19;
      const coordinates = (slot) => {
        const level = Math.floor(Math.log2(slot + 1));
        return { x: 400 * (slot - (2 ** level - 1) + 0.5) / 2 ** level, y: 39 + level * gap };
      };
      return { shown, radius, coordinates };
    }

    function makeNode(node) {
      const group = svg('g', { class: 'heap-node', 'data-node-id': node.id });
      const visual = svg('g', { class: 'heap-node-visual' });
      const circle = svg('circle');
      const text = svg('text', {}, node.value);
      visual.append(circle, text);
      group.append(visual);
      group.style.transformOrigin = '0 0';
      group.style.transformBox = 'view-box';
      const record = { group, visual, circle, text, value: node.value, visible: false };
      records.set(node.id, record);
      return record;
    }

    function fly(record, from, source, duration, fromHeap) {
      if (!from) return Promise.resolve();
      const to = nodeRect(record);
      const flight = document.createElement('div');
      const blue = record.svg === heapB;
      const fontSize = Number.parseFloat(record.text.style.fontSize) * Math.hypot(matrix(record.svg).a, matrix(record.svg).b);
      flight.className = `heap-flight${blue ? ' heap-flight-b' : ''}`;
      flight.setAttribute('aria-hidden', 'true');
      flight.textContent = record.value;
      Object.assign(flight.style, { position: 'fixed', left: `${to.left}px`, top: `${to.top}px`,
        width: `${to.width}px`, height: `${to.height}px`, borderRadius: '50%',
        fontSize: `${fontSize}px` });
      source?.classList.add('is-picked');
      record.group.classList.add('is-arriving');
      document.body.append(flight);
      const end = { left: `${to.left}px`, top: `${to.top}px`, width: `${to.width}px`, height: `${to.height}px`,
        borderRadius: '50%', fontSize: `${fontSize}px`,
        backgroundColor: blue ? '#edf4ff' : '#fff5ea', borderColor: blue ? '#7fa1ce' : '#dca171',
        color: blue ? '#4d76a7' : '#a86e45', boxShadow: '0 0 0 rgba(0,0,0,0)' };
      return animate(flight, [
        { ...end, left: `${from.left}px`, top: `${from.top}px`, width: `${from.width}px`, height: `${from.height}px`,
          borderRadius: fromHeap ? '50%' : '9px', fontSize: fromHeap ? `${Math.min(from.width, from.height) * 0.4}px` : '18px',
          backgroundColor: fromHeap === 'B' ? '#edf4ff' : fromHeap ? '#fff5ea' : '#fff4e8',
          borderColor: fromHeap === 'B' ? '#7fa1ce' : '#dca171',
          color: fromHeap === 'B' ? '#4d76a7' : '#a86e45', boxShadow: '0 3px 0 rgba(190,159,125,.25)' },
        { ...end, offset: 0.8, left: `${to.left}px`, top: `${to.top - 5}px` },
        end,
      ], duration, () => {
        flight.remove();
        source?.classList.remove('is-picked');
        record.group.classList.remove('is-arriving');
      });
    }

    function render(frame, { animate: shouldAnimate = true } = {}) {
      settleAnimations();
      const motion = frame.motion || { kind: 'idle' };
      const duration = shouldAnimate && !reducedMotion() ? frame.duration ?? TIMING[motion.kind] ?? 300 : 0;
      const before = new Map();
      for (const [id, record] of records) {
        if (record.visible) before.set(id, nodeRect(record));
        record.group.classList.remove('is-top', 'is-arriving', 'is-popped');
      }
      const sourceIndex = motion.from?.kind === 'conveyor' ? motion.from.round : undefined;
      const source = sourceIndex === undefined ? undefined : blocks.get(sourceIndex)?.element;
      const sourceRect = source?.getBoundingClientRect();
      if (sourceRect?.width) inputOrigins.set(sourceIndex, {
        left: sourceRect.left, top: sourceRect.top, width: sourceRect.width, height: sourceRect.height,
      });
      const jobs = renderConveyor(frame, duration);
      const wantedIds = new Set([...(frame.left || []), ...(frame.right || [])].map((node) => node.id));
      for (const [id, record] of records) {
        if (wantedIds.has(id) || !record.visible) continue;
        const origin = oldOrigin(id, before);
        record.lastRect = origin;
        record.visible = false;
        if (motion.kind === 'pop' && motion.nodeId === id && duration) {
          record.group.classList.add('is-popped');
          const from = { x: record.x, y: record.y };
          const end = screenPoint(record.svg, from.x, from.y - 24);
          const start = screenPoint(record.svg, from.x, from.y);
          record.lastRect = { ...origin, left: origin.left + end.x - start.x, top: origin.top + end.y - start.y };
          jobs.push(animate(record.group, [
            { transform: `translate(${from.x}px, ${from.y}px)` },
            { transform: `translate(${from.x}px, ${from.y - 24}px)` },
          ], duration));
          jobs.push(animate(record.visual, [
            { transform: 'scale(1)', opacity: 1 },
            { transform: 'scale(1.12)', opacity: 1, offset: 0.25 },
            { transform: 'scale(.45)', opacity: 0 },
          ], duration, () => { record.group.remove(); record.group.classList.remove('is-popped'); }));
        } else record.group.remove();
      }
      for (const [heapIndex, items] of [[0, frame.left || []], [1, frame.right || []]]) {
        const heap = heaps[heapIndex];
        const shape = layout(items);
        const visibleIds = new Set(shape.shown.map((node) => node.id));
        const occupied = new Set(shape.shown.map((node, index) => node.index ?? index));
        const edgeSlots = new Set();
        for (const slot of occupied) {
          if (!slot || !occupied.has(Math.floor((slot - 1) / 2))) continue;
          edgeSlots.add(slot);
          let line = heap.edgeRecords.get(slot);
          if (!line) {
            line = svg('line', { class: 'heap-edge' });
            heap.edges.append(line);
            heap.edgeRecords.set(slot, line);
            jobs.push(animate(line, [{ opacity: 0 }, { opacity: 1 }], Math.min(duration, 140)));
          }
          const a = shape.coordinates(Math.floor((slot - 1) / 2));
          const b = shape.coordinates(slot);
          for (const [key, value] of Object.entries({ x1: a.x, y1: a.y, x2: b.x, y2: b.y })) line.setAttribute(key, String(value));
        }
        for (const [slot, line] of heap.edgeRecords) {
          if (!edgeSlots.has(slot)) { line.remove(); heap.edgeRecords.delete(slot); }
        }
        heap.notes.replaceChildren();
        if (!items.length) heap.notes.append(svg('text', { x: 200, y: 126, class: 'empty-heap' }, '等待第一个数字'));
        if (items.length > shape.shown.length) heap.notes.append(svg('text', { x: 200, y: 238, class: 'heap-extra' }, `另有 ${items.length - shape.shown.length} 个节点，已省略显示`));
        for (const node of shape.shown) {
          const record = records.get(node.id) || makeNode(node);
          const origin = oldOrigin(node.id, before);
          const previousRadius = record.radius;
          const target = shape.coordinates(node.index ?? items.indexOf(node));
          record.svg = heap.element;
          record.x = target.x;
          record.y = target.y;
          record.radius = shape.radius;
          record.value = node.value;
          record.visible = true;
          record.group.setAttribute('transform', `translate(${target.x}, ${target.y})`);
          record.circle.setAttribute('r', String(shape.radius));
          record.text.textContent = node.value;
          record.text.style.fontSize = `${Math.abs(node.value) > 999 ? 9 : shape.radius < 15 ? 10 : 15}px`;
          if (record.group.parentElement !== heap.nodes) heap.nodes.append(record.group);
          if (motion.kind === 'insert' && motion.nodeId === node.id && duration) {
            const from = motion.from?.kind === 'parked' ? origin : inputOrigins.get(sourceIndex);
            jobs.push(fly(record, from, source, duration, motion.from?.kind === 'parked' ? motion.from.heap : undefined));
          } else if (origin && duration) {
            const previous = localPoint(heap.element, origin.left + origin.width / 2, origin.top + origin.height / 2);
            const distance = Math.hypot(previous.x - target.x, previous.y - target.y);
            if (distance > 0.1) {
              const path = [{ transform: `translate(${previous.x}px, ${previous.y}px)` }];
              if (motion.kind === 'swap' && (motion.nodeId === node.id || motion.otherNodeId === node.id)) {
                // 两个节点沿相反的弧线交错，避免交换途中重叠成一个数字。
                const bow = Math.min(24, distance / 3);
                path.push({ offset: 0.5, transform: `translate(${(previous.x + target.x) / 2 - (target.y - previous.y) / distance * bow}px, ${(previous.y + target.y) / 2 + (target.x - previous.x) / distance * bow}px)` });
              }
              path.push({ transform: `translate(${target.x}px, ${target.y}px)` });
              jobs.push(animate(record.group, path, duration));
            }
            if (previousRadius && previousRadius !== shape.radius) jobs.push(animate(record.visual, [
              { transform: `scale(${previousRadius / shape.radius})` }, { transform: 'scale(1)' },
            ], duration));
          }
          if (motion.kind === 'top' && motion.nodeId === node.id) {
            record.group.classList.add('is-top');
            jobs.push(animate(record.visual, [
              { transform: 'scale(1)' }, { transform: 'scale(1.18)', offset: 0.3 },
              { transform: 'scale(.94)', offset: 0.57 }, { transform: 'scale(1.045)', offset: 0.78 },
              { transform: 'scale(1)' },
            ], duration));
          }
        }
        for (const [id, record] of records) {
          if (record.svg === heap.element && record.visible && wantedIds.has(id) && !visibleIds.has(id)) {
            record.lastRect = nodeRect(record);
            record.visible = false;
            record.group.remove();
          }
        }
      }
      lastFrame = frame;
      return Promise.all(jobs).then(() => undefined);
    }

    return {
      render,
      pause() { for (const { animation } of active) animation.pause(); },
      resume() { for (const { animation } of active) animation.play(); },
      finish() { settleAnimations(); },
      setSpeed(value) {
        rate = Number.isFinite(value) && value > 0 ? value : 1;
        for (const { animation } of active) {
          if (animation.updatePlaybackRate) animation.updatePlaybackRate(rate);
          else animation.playbackRate = rate;
        }
      },
      reset() {
        settleAnimations(true);
        for (const record of records.values()) record.group.remove();
        records.clear();
        blocks.clear();
        inputOrigins.clear();
        conveyor.replaceChildren();
        if (belt) belt.style.backgroundPosition = '0px 0px';
        for (const heap of heaps) { heap.edges.replaceChildren(); heap.notes.replaceChildren(); heap.edgeRecords.clear(); }
        offset = 0;
        lastFrame = undefined;
      },
    };
  }
  globalThis.NumOJHeapMotion = Object.freeze({ create });
})();
