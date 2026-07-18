(function () {
  var editor = document.getElementById('rulesEditor');
  if (!editor) return;
  var topoView = document.getElementById('rulesTopoView');
  var topoCanvas = document.getElementById('rulesTopoCanvas');
  var addNodeBtn = document.getElementById('addTopoNodeBtn');
  var deleteNodeBtn = document.getElementById('deleteTopoNodeBtn');
  var confirmDeleteNodeBtn = document.getElementById('confirmDeleteTopoNodeBtn');
  var addEdgeBtn = document.getElementById('showAddEdgeBtn');
  var simplifyTopoBtn = document.getElementById('simplifyTopoBtn');
  var hintEl = document.getElementById('saveRulesHint');
  var activeView = 'text';
  var selectedEdge = null;
  var addEdgeMode = false;
  var pendingEdgeFrom = null;
  var deleteNodeMode = false;
  var pendingDeleteIndexes = {};
  var nodeW = 168, nodeH = 100, marginX = 24, marginY = 20, xGap = 88, yGap = 80;
  var modalEl = document.getElementById('ajRuleModal');
  var ruleModal = (modalEl && window.bootstrap) ? new bootstrap.Modal(modalEl) : null;
  var deleteModalEl = document.getElementById('ajDeleteRulesModal');
  var deleteRulesModal = (deleteModalEl && window.bootstrap) ? new bootstrap.Modal(deleteModalEl) : null;
  var pendingDeleteConfirmIndexes = [];
  var rules = (window.__JUDGE_RULES__ || []).map(function (r) {
    return {rule_id: r.rule_id, rule_name: r.rule_name || '', rule_text: r.rule_text, value: r.value,
            dependencies: (r.dependencies || []).slice()};
  });
  function reindex() {
    var oldToNew = {};
    rules.forEach(function (r, i) { oldToNew[parseInt(r.rule_id, 10)] = i + 1; });
    rules.forEach(function (r, i) {
      r.rule_id = i + 1;
      r.rule_name = (r.rule_name || '').slice(0, 120);
      var seen = {};
      r.dependencies = (r.dependencies || []).map(function (d) {
        return oldToNew[parseInt(d, 10)] || null;
      }).filter(function (d) {
        if (!d || d === r.rule_id || seen[d]) return false;
        seen[d] = true;
        return true;
      }).sort(function (a, b) { return a - b; });
    });
  }
  function resetTopoModes() {
    selectedEdge = null;
    addEdgeMode = false;
    pendingEdgeFrom = null;
    deleteNodeMode = false;
    pendingDeleteIndexes = {};
  }
  function createRule() {
    rules.push({rule_id: rules.length + 1, rule_name: '', rule_text: '', value: 0, dependencies: []});
    reindex();
    return rules.length - 1;
  }
  function deleteRuleAt(idx, opts) {
    opts = opts || {};
    idx = parseInt(idx, 10);
    var removed = rules[idx];
    if (!removed) return;
    var oldId = removed.rule_id;
    rules.splice(idx, 1);
    resetTopoModes();
    reindex();
    if (!opts.silent) setHint('已删除规则 ' + oldId + '，编号和依赖已重算。', 'text-success');
    renderCurrent();
  }
  function selectedDeleteIndexes() {
    return Object.keys(pendingDeleteIndexes).map(function (k) {
      return parseInt(k, 10);
    }).filter(function (idx) {
      return idx >= 0 && idx < rules.length && pendingDeleteIndexes[idx];
    }).sort(function (a, b) { return a - b; });
  }
  function deleteRulesAt(indexes) {
    indexes = (indexes || []).slice().sort(function (a, b) { return b - a; });
    if (!indexes.length) return;
    var ids = indexes.map(function (idx) {
      return rules[idx] ? rules[idx].rule_id : null;
    }).filter(function (id) { return id != null; }).sort(function (a, b) { return a - b; });
    indexes.forEach(function (idx) {
      if (rules[idx]) rules.splice(idx, 1);
    });
    resetTopoModes();
    reindex();
    setHint('已删除 ' + ids.length + ' 条规则，编号和依赖已重算。', 'text-success');
    renderCurrent();
  }
  function totalValue() { return rules.reduce(function (s, r) { return s + (parseFloat(r.value) || 0); }, 0); }
  function esc(s) { return (s || '').replace(/[&<>"]/g, function (c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
  function compact(s, n) {
    s = String(s || '').replace(/\s+/g, ' ').trim();
    if (!s) return '未填写规则内容';
    return s.length > n ? s.slice(0, n) + '…' : s;
  }
  function ruleTitle(r) { return (r.rule_name || '').trim() || compact(r.rule_text, 14); }
  function ruleOptionLabel(r) { return '规则 ' + r.rule_id + '：' + ruleTitle(r); }
  function setHint(text, cls) {
    if (!hintEl) return;
    hintEl.textContent = text || '';
    hintEl.className = 'small ' + (cls || 'text-muted');
  }
  function refreshStats() {
    var t = totalValue();
    document.getElementById('rulesTotalValue').textContent = (Math.round(t * 100) / 100);
    document.getElementById('rulesCountLabel').textContent = '共 ' + rules.length + ' 条规则';
  }
  function grow(t) { if (!t) return; t.style.height = 'auto'; t.style.height = t.scrollHeight + 'px'; }
  function buildAdj(skip) {
    var adj = {};
    rules.forEach(function (r) { adj[r.rule_id] = []; });
    rules.forEach(function (r) {
      (r.dependencies || []).forEach(function (d) {
        if (skip && skip.from === d && skip.to === r.rule_id) return;
        if (adj[d]) adj[d].push(r.rule_id);
      });
    });
    return adj;
  }
  function hasPath(start, target, skip) {
    var adj = buildAdj(skip), seen = {};
    function dfs(id) {
      if (id === target) return true;
      if (seen[id]) return false;
      seen[id] = true;
      return (adj[id] || []).some(dfs);
    }
    return dfs(start);
  }
  function createsCycle(from, to) { return hasPath(to, from, null); }
  function renderText() {
    reindex();
    selectedEdge = null;
    addEdgeMode = false;
    pendingEdgeFrom = null;
    deleteNodeMode = false;
    pendingDeleteIndexes = {};
    editor.innerHTML = '';
    rules.forEach(function (r, idx) {
      var pills = rules.filter(function (_, j) { return j !== idx; }).map(function (o) {
        var on = r.dependencies.indexOf(o.rule_id) >= 0 ? ' on' : '';
        return '<span class="aj-pill' + on + '" data-dep-toggle="' + idx + '" data-dep-id="' + o.rule_id + '">规则 ' + o.rule_id + '</span>';
      }).join('');
      var depsRow = rules.length > 1
        ? '<div class="aj-deps"><span class="aj-deps-label">前置依赖</span>' +
          (pills || '<span class="aj-deps-label">（无其它规则）</span>') + '</div>'
        : '';
      var card = document.createElement('div');
      card.className = 'aj-rule';
      card.style.animationDelay = (idx * 0.03) + 's';
      card.innerHTML =
        '<div class="aj-rule-top">' +
          '<div class="aj-no">' + r.rule_id + '</div>' +
          '<div class="aj-main-fields">' +
          '<input class="aj-name" data-name="' + idx + '" maxlength="120" placeholder="规则名称">' +
            '<textarea class="aj-desc" data-text="' + idx + '" rows="2" placeholder="用自然语言描述这条评分规则……"></textarea>' +
          '</div>' +
          '<div class="aj-val"><label>分值</label><div class="aj-stepper">' +
            '<button type="button" class="aj-step" data-step="-1" data-i="' + idx + '" tabindex="-1">−</button>' +
            '<input type="number" min="0" step="0.5" data-val="' + idx + '" value="' + (r.value || 0) + '">' +
            '<button type="button" class="aj-step" data-step="1" data-i="' + idx + '" tabindex="-1">+</button>' +
          '</div></div>' +
          '<button type="button" class="aj-del" data-del="' + idx + '" title="删除规则"><i class="fas fa-trash-can"></i></button>' +
        '</div>' + depsRow;
      editor.appendChild(card);
      var nameInput = card.querySelector('[data-name]'); nameInput.value = r.rule_name || '';
      var ta = card.querySelector('[data-text]'); ta.value = r.rule_text || ''; grow(ta);
    });
    if (!rules.length) {
      editor.innerHTML = '<div class="aj-empty"><i class="fas fa-list-check mb-2 d-block" style="font-size:1.4rem;opacity:.5;"></i>还没有评分规则</div>';
    }
    refreshStats();
    bind();
  }
  function renderTopoControls() {
    var disabled = rules.length < 2;
    if (disabled) {
      addEdgeMode = false;
      pendingEdgeFrom = null;
    }
    if (!rules.length) {
      deleteNodeMode = false;
      pendingDeleteIndexes = {};
    }
    if (addNodeBtn) addNodeBtn.disabled = deleteNodeMode;
    if (deleteNodeBtn) {
      deleteNodeBtn.disabled = !rules.length;
      deleteNodeBtn.classList.toggle('delete-active', deleteNodeMode);
    }
    if (confirmDeleteNodeBtn) {
      confirmDeleteNodeBtn.classList.toggle('show', deleteNodeMode);
      confirmDeleteNodeBtn.disabled = !deleteNodeMode || !selectedDeleteIndexes().length;
    }
    if (addEdgeBtn) {
      addEdgeBtn.disabled = disabled || deleteNodeMode;
      addEdgeBtn.classList.toggle('active', addEdgeMode);
    }
    if (simplifyTopoBtn) simplifyTopoBtn.disabled = !rules.length || deleteNodeMode;
  }
  var rulesTopology = window.RuleTopology.create({
    nodeWidth: nodeW, nodeHeight: nodeH,
    marginX: marginX, marginY: marginY,
    columnGap: xGap, rowGap: yGap,
    slotPadding: 42, maxSlotStep: 17
  });
  function topoLayout() {
    reindex();
    return rulesTopology.layout(rules);
  }
  var edgeKey = rulesTopology.edgeKey;
  var buildEdgeRoutes = rulesTopology.buildRoutes;
  var edgePath = rulesTopology.edgePath;
  function setTopoFocus(surface, ruleId, activeEdge) {
    if (addEdgeMode || deleteNodeMode) return;
    var active = ruleId != null || !!activeEdge;
    surface.classList.toggle('has-focus', active);
    var edgeParts = activeEdge ? activeEdge.split(':') : null;
    surface.querySelectorAll('.aj-topo-edge, .aj-topo-arrow').forEach(function (edge) {
      var on = activeEdge
        ? edge.dataset.edgeKey === activeEdge
        : (edge.dataset.edgeFrom === String(ruleId) || edge.dataset.edgeTo === String(ruleId));
      edge.classList.toggle('edge-active', !!on);
    });
    surface.querySelectorAll('.aj-topo-node').forEach(function (node) {
      var id = node.dataset.ruleId;
      var on = edgeParts
        ? (id === edgeParts[0] || id === edgeParts[1])
        : id === String(ruleId);
      node.classList.toggle('node-active', !!on);
    });
  }
  function appendTopoSurface(surface, layout) {
    var stage = document.createElement('div');
    stage.className = 'aj-topo-stage';
    stage.style.width = Math.ceil(layout.width) + 'px';
    stage.style.height = Math.ceil(layout.height) + 'px';
    surface.style.transform = 'none';
    stage.appendChild(surface);
    topoCanvas.appendChild(stage);
  }
  function appendTopoArrow(svg, route, edge, selected) {
    var arrow = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    var x = route.x2, tailY = route.y2, tipY = route.arrowTipY;
    arrow.setAttribute('class', 'aj-topo-arrow' + (selected ? ' selected' : ''));
    arrow.setAttribute('points', x + ' ' + tipY + ' ' + (x - 5) + ' ' + tailY + ' ' + (x + 5) + ' ' + tailY);
    arrow.dataset.edgeKey = edgeKey(edge.from, edge.to);
    arrow.dataset.edgeFrom = edge.from;
    arrow.dataset.edgeTo = edge.to;
    svg.appendChild(arrow);
  }
  function canAddEdge(from, to) {
    from = parseInt(from, 10);
    to = parseInt(to, 10);
    if (!from || !to || from === to) return false;
    var target = rules.filter(function (r) { return r.rule_id === to; })[0];
    if (!target || target.dependencies.indexOf(from) >= 0) return false;
    return !createsCycle(from, to);
  }
  function edgeNodeClass(ruleId) {
    if (!addEdgeMode) return '';
    if (!pendingEdgeFrom) return ' link-ready';
    if (pendingEdgeFrom === ruleId) return ' link-source';
    return canAddEdge(pendingEdgeFrom, ruleId) ? ' link-target' : ' link-blocked';
  }
  function topoNodeClass(ruleId, idx) {
    if (deleteNodeMode) return pendingDeleteIndexes[idx] ? ' delete-selected' : '';
    return edgeNodeClass(ruleId);
  }
  function handleTopoNodeClick(idx) {
    var r = rules[idx];
    if (!r) return;
    if (deleteNodeMode) {
      if (pendingDeleteIndexes[idx]) delete pendingDeleteIndexes[idx];
      else pendingDeleteIndexes[idx] = true;
      selectedEdge = null;
      renderTopo();
      return;
    }
    if (!addEdgeMode) {
      openRuleModal(idx);
      return;
    }
    var id = r.rule_id;
    selectedEdge = null;
    if (!pendingEdgeFrom) {
      pendingEdgeFrom = id;
      renderTopo();
      return;
    }
    if (pendingEdgeFrom === id) {
      pendingEdgeFrom = null;
      renderTopo();
      return;
    }
    if (!canAddEdge(pendingEdgeFrom, id)) return;
    var from = pendingEdgeFrom;
    addEdgeMode = false;
    pendingEdgeFrom = null;
    addEdge(from, id, {silent: true});
  }
  function renderTopo() {
    reindex();
    refreshStats();
    renderTopoControls();
    topoCanvas.innerHTML = '';
    if (!rules.length) {
      topoCanvas.innerHTML = '<div class="aj-topo-empty"><div><i class="fas fa-diagram-project mb-2 d-block" style="font-size:1.5rem;opacity:.5;"></i>还没有评分规则。</div></div>';
      return;
    }
    var layout = topoLayout();
    if (!layout) {
      topoCanvas.innerHTML = '<div class="aj-topo-empty text-danger">当前依赖存在环，无法生成 DAG。请切回文本视图调整。</div>';
      return;
    }
    var surface = document.createElement('div');
    surface.className = 'aj-topo-surface'
      + (addEdgeMode ? (' link-mode' + (pendingEdgeFrom ? ' link-has-source' : '')) : '')
      + (deleteNodeMode ? ' delete-mode' : '');
    surface.style.width = layout.width + 'px';
    surface.style.height = layout.height + 'px';
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'aj-topo-svg');
    svg.setAttribute('width', layout.width);
    svg.setAttribute('height', layout.height);
    svg.setAttribute('viewBox', '0 0 ' + layout.width + ' ' + layout.height);
    svg.innerHTML = '';
    surface.appendChild(svg);
    var edges = [];
    rules.forEach(function (r) {
      r.dependencies.forEach(function (dep) {
        edges.push({from: dep, to: r.rule_id});
      });
    });
    var edgeRoutes = buildEdgeRoutes(edges, layout);
    edges.forEach(function (edge) {
      var route = edgeRoutes[edgeKey(edge.from, edge.to)];
      if (!route) return;
      var selected = selectedEdge && selectedEdge.from === edge.from && selectedEdge.to === edge.to;
      var d = edgePath(route);
      var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('class', 'aj-topo-edge' + (selected ? ' selected' : ''));
      path.setAttribute('d', d);
      path.dataset.edgeKey = edgeKey(edge.from, edge.to);
      path.dataset.edgeFrom = edge.from;
      path.dataset.edgeTo = edge.to;
      svg.appendChild(path);
      appendTopoArrow(svg, route, edge, selected);
      var hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      hit.setAttribute('class', 'aj-topo-edge-hit');
      hit.setAttribute('d', d);
      hit.dataset.from = edge.from;
      hit.dataset.to = edge.to;
      hit.dataset.edgeKey = path.dataset.edgeKey;
      svg.appendChild(hit);
      if (selected) {
        var trash = document.createElement('button');
        trash.type = 'button';
        trash.className = 'aj-edge-trash';
        trash.title = '删除这条拓扑';
        trash.dataset.edgeDelete = edge.from + ':' + edge.to;
        trash.style.left = ((route.x1 + route.x2) / 2) + 'px';
        trash.style.top = route.laneY + 'px';
        trash.innerHTML = '<i class="fas fa-trash-can"></i>';
        surface.appendChild(trash);
      }
    });
    rules.forEach(function (r, idx) {
      var pos = layout.positions[r.rule_id];
      var node = document.createElement('button');
      node.type = 'button';
      node.className = 'aj-topo-node' + topoNodeClass(r.rule_id, idx);
      node.dataset.node = idx;
      node.dataset.ruleId = r.rule_id;
      node.title = r.rule_text || '未填写规则内容';
      node.style.left = pos.x + 'px';
      node.style.top = pos.y + 'px';
      node.innerHTML =
        '<span class="aj-topo-node-id">规则 ' + r.rule_id + ' · ' + (r.value || 0) + ' 分</span>' +
        '<span class="aj-topo-node-title">' + esc(ruleTitle(r)) + '</span>' +
        '<span class="aj-topo-node-text">' + esc(compact(r.rule_text, 42)) + '</span>';
      surface.appendChild(node);
    });
    appendTopoSurface(surface, layout);
    surface.querySelectorAll('.aj-topo-edge-hit').forEach(function (p) {
      p.onmouseenter = function () { setTopoFocus(surface, null, p.dataset.edgeKey); };
      p.onmouseleave = function () { setTopoFocus(surface, null, null); };
      p.onclick = function () {
        selectedEdge = {from: parseInt(p.dataset.from, 10), to: parseInt(p.dataset.to, 10)};
        renderTopo();
      };
    });
    surface.querySelectorAll('[data-edge-delete]').forEach(function (b) {
      b.onclick = function () {
        var parts = b.dataset.edgeDelete.split(':');
        removeEdge(parseInt(parts[0], 10), parseInt(parts[1], 10));
      };
    });
    surface.querySelectorAll('[data-node]').forEach(function (n) {
      n.onmouseenter = function () { setTopoFocus(surface, parseInt(n.dataset.ruleId, 10), null); };
      n.onmouseleave = function () { setTopoFocus(surface, null, null); };
      n.onfocus = function () { setTopoFocus(surface, parseInt(n.dataset.ruleId, 10), null); };
      n.onblur = function () { setTopoFocus(surface, null, null); };
      n.onclick = function () { handleTopoNodeClick(parseInt(n.dataset.node, 10)); };
    });
  }
  function renderCurrent() {
    refreshStats();
    if (activeView === 'topo') renderTopo();
    else renderText();
  }
  function bind() {
    editor.querySelectorAll('[data-del]').forEach(function (b) {
      b.onclick = function () { deleteRuleAt(parseInt(b.dataset.del, 10)); };
    });
    editor.querySelectorAll('[data-name]').forEach(function (n) {
      n.oninput = function () { rules[parseInt(n.dataset.name, 10)].rule_name = n.value; };
    });
    editor.querySelectorAll('[data-text]').forEach(function (t) {
      t.oninput = function () { rules[parseInt(t.dataset.text, 10)].rule_text = t.value; grow(t); };
    });
    editor.querySelectorAll('[data-val]').forEach(function (v) {
      v.oninput = function () {
        var val = parseFloat(v.value); if (!isFinite(val) || val < 0) val = 0;
        rules[parseInt(v.dataset.val, 10)].value = val; refreshStats();
      };
    });
    editor.querySelectorAll('.aj-step').forEach(function (b) {
      b.onclick = function () {
        var i = parseInt(b.dataset.i, 10), d = parseInt(b.dataset.step, 10);
        var nv = Math.max(0, (parseFloat(rules[i].value) || 0) + d);
        rules[i].value = nv;
        var inp = editor.querySelector('[data-val="' + i + '"]'); if (inp) inp.value = nv;
        refreshStats();
      };
    });
    editor.querySelectorAll('[data-dep-toggle]').forEach(function (p) {
      p.onclick = function () {
        var i = parseInt(p.dataset.depToggle, 10), id = parseInt(p.dataset.depId, 10);
        var arr = rules[i].dependencies, pos = arr.indexOf(id);
        if (pos >= 0) { arr.splice(pos, 1); p.classList.remove('on'); }
        else {
          if (createsCycle(id, rules[i].rule_id)) {
            setHint('不能添加这条依赖：会形成环。', 'text-danger');
            return;
          }
          arr.push(id);
          arr.sort(function (a, b) { return a - b; });
          p.classList.add('on');
        }
      };
    });
  }
  function addEdge(from, to, opts) {
    opts = opts || {};
    from = parseInt(from, 10); to = parseInt(to, 10);
    if (!from || !to || from === to) {
      if (!opts.silent) setHint('请选择两条不同规则。', 'text-danger');
      return;
    }
    var target = rules.filter(function (r) { return r.rule_id === to; })[0];
    if (!target) return;
    if (target.dependencies.indexOf(from) >= 0) {
      if (!opts.silent) setHint('这条拓扑已经存在。', 'text-muted');
      return;
    }
    if (createsCycle(from, to)) {
      if (!opts.silent) setHint('不能添加这条拓扑：会形成环。', 'text-danger');
      return;
    }
    target.dependencies.push(from);
    target.dependencies.sort(function (a, b) { return a - b; });
    selectedEdge = {from: from, to: to};
    if (!opts.silent) setHint('已添加拓扑：规则 ' + from + ' → 规则 ' + to, 'text-success');
    renderTopo();
  }
  function removeEdge(from, to) {
    var target = rules.filter(function (r) { return r.rule_id === to; })[0];
    if (!target) return;
    target.dependencies = target.dependencies.filter(function (d) { return d !== from; });
    selectedEdge = null;
    setHint('已删除拓扑：规则 ' + from + ' → 规则 ' + to, 'text-success');
    renderTopo();
  }
  function simplifyTopology() {
    reindex();
    var removed = 0;
    rules.forEach(function (r) {
      r.dependencies = r.dependencies.filter(function (dep) {
        if (hasPath(dep, r.rule_id, {from: dep, to: r.rule_id})) {
          removed += 1;
          return false;
        }
        return true;
      });
    });
    selectedEdge = null;
    setHint(removed ? ('已简化拓扑，删除 ' + removed + ' 条冗余边。') : '当前拓扑已经是最简关系。', removed ? 'text-success' : 'text-muted');
    renderTopo();
  }
  function openRuleModal(idx) {
    var r = rules[idx];
    if (!r) return;
    if (!ruleModal) {
      var nextText = window.prompt('规则原文', r.rule_text || '');
      if (nextText !== null) { r.rule_text = nextText; renderCurrent(); }
      return;
    }
    document.getElementById('ajRuleModalIndex').value = idx;
    document.getElementById('ajRuleModalName').value = r.rule_name || '';
    document.getElementById('ajRuleModalText').value = r.rule_text || '';
    document.getElementById('ajRuleModalValue').value = r.value || 0;
    document.getElementById('ajRuleModalLabel').textContent = '编辑规则 ' + r.rule_id;
    ruleModal.show();
  }
  function openDeleteRulesModal(indexes) {
    pendingDeleteConfirmIndexes = (indexes || []).slice();
    var ids = pendingDeleteConfirmIndexes.map(function (idx) { return rules[idx].rule_id; });
    var summary = document.getElementById('ajDeleteRulesSummary');
    if (summary) summary.textContent = '将删除规则 ' + ids.join('、');
    if (deleteRulesModal) deleteRulesModal.show();
    else deleteRulesAt(pendingDeleteConfirmIndexes);
  }
  var deleteRulesConfirmBtn = document.getElementById('ajDeleteRulesConfirm');
  if (deleteRulesConfirmBtn) deleteRulesConfirmBtn.onclick = function () {
    var indexes = pendingDeleteConfirmIndexes.slice();
    pendingDeleteConfirmIndexes = [];
    if (deleteRulesModal) deleteRulesModal.hide();
    deleteRulesAt(indexes);
  };
  document.getElementById('ajRuleModalSave').onclick = function () {
    var idx = parseInt(document.getElementById('ajRuleModalIndex').value, 10);
    var r = rules[idx];
    if (!r) return;
    r.rule_name = document.getElementById('ajRuleModalName').value.slice(0, 120);
    r.rule_text = document.getElementById('ajRuleModalText').value;
    var val = parseFloat(document.getElementById('ajRuleModalValue').value);
    r.value = (!isFinite(val) || val < 0) ? 0 : val;
    if (ruleModal) ruleModal.hide();
    renderCurrent();
  };
  document.querySelectorAll('[data-rules-view]').forEach(function (tab) {
    tab.onclick = function () {
      activeView = tab.dataset.rulesView;
      document.querySelectorAll('[data-rules-view]').forEach(function (t) {
        var on = t.dataset.rulesView === activeView;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      editor.hidden = activeView !== 'text';
      topoView.hidden = activeView !== 'topo';
      renderCurrent();
    };
  });
  if (addNodeBtn) addNodeBtn.onclick = function () {
    if (deleteNodeMode) return;
    addEdgeMode = false;
    pendingEdgeFrom = null;
    selectedEdge = null;
    var idx = createRule();
    renderTopo();
    openRuleModal(idx);
  };
  if (deleteNodeBtn) deleteNodeBtn.onclick = function () {
    if (!rules.length) return;
    deleteNodeMode = !deleteNodeMode;
    addEdgeMode = false;
    pendingEdgeFrom = null;
    selectedEdge = null;
    pendingDeleteIndexes = {};
    setHint(deleteNodeMode ? '请选择要删除的节点。' : '已退出删除模式。', deleteNodeMode ? 'text-muted' : 'text-muted');
    renderTopo();
  };
  if (confirmDeleteNodeBtn) confirmDeleteNodeBtn.onclick = function () {
    if (!deleteNodeMode) return;
    var indexes = selectedDeleteIndexes();
    if (!indexes.length) return;
    openDeleteRulesModal(indexes);
  };
  if (addEdgeBtn) addEdgeBtn.onclick = function () {
    if (rules.length < 2) return;
    deleteNodeMode = false;
    pendingDeleteIndexes = {};
    addEdgeMode = !addEdgeMode;
    pendingEdgeFrom = null;
    selectedEdge = null;
    renderTopo();
  };
  if (simplifyTopoBtn) simplifyTopoBtn.onclick = function () {
    addEdgeMode = false;
    pendingEdgeFrom = null;
    deleteNodeMode = false;
    pendingDeleteIndexes = {};
    simplifyTopology();
  };
  document.getElementById('addRuleBtn').onclick = function () {
    resetTopoModes();
    var idx = createRule();
    renderCurrent();
    if (activeView === 'topo') openRuleModal(idx);
    else {
      var last = editor.querySelector('.aj-rule:last-child .aj-desc'); if (last) last.focus();
    }
  };
  document.getElementById('saveRulesBtn').onclick = function () {
    reindex();
    setHint('保存中…', 'text-muted');
    fetch(window.__SAVE_RULES_URL__, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
      body: JSON.stringify({rules: rules})
    }).then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (res.ok && res.b.success) {
          setHint('✓ 已保存 ' + res.b.count + ' 条规则，满分 ' + res.b.max_score + ' 分', 'text-success');
        } else {
          setHint('保存失败：' + (res.b.message || '未知错误'), 'text-danger');
        }
      }).catch(function (e) { setHint('网络错误：' + e, 'text-danger'); });
  };
  renderCurrent();
})();
