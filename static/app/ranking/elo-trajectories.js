(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function svgElement(tag, attributes) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attributes || {}).forEach(function (name) {
      node.setAttribute(name, String(attributes[name]));
    });
    return node;
  }

  function ratingText(value) {
    var number = Number(value);
    return Number.isFinite(number) ? number.toFixed(2) : '—';
  }

  function compactRating(value) {
    var number = Number(value);
    return Number.isFinite(number) ? number.toFixed(0) : '—';
  }

  function deltaText(value) {
    var number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return (number >= 0 ? '+' : '') + number.toFixed(2);
  }

  function axisDayKey(point) {
    var value = String((point && point.created_at) || '');
    return value.length >= 10 ? value.slice(0, 10) : '';
  }

  function axisTimeText(point, showDate) {
    if (!point || Number(point.sequence) === 0) return '起始';
    var value = String(point.created_at || '');
    if (value.length < 16) return 'T' + point.sequence;
    return (showDate ? value.slice(5, 16) : value.slice(11, 16)).replace('T', ' ');
  }

  function seriesColor(index, count) {
    var start = 18;
    var end = count <= 1 ? 42 : 72;
    var lightness = count <= 1 ? 36 : start + ((end - start) * index / (count - 1));
    return 'hsl(207 55% ' + lightness.toFixed(1) + '%)';
  }

  function initViewer(viewer) {
    if (!viewer || viewer.getAttribute('data-elo-trajectory-ready') === 'true') return;
    viewer.setAttribute('data-elo-trajectory-ready', 'true');

    var modal = viewer.closest('.elo-trajectory-modal');
    var searchUrl = viewer.getAttribute('data-search-url');
    var trajectoryUrl = viewer.getAttribute('data-trajectory-url');
    var maxSelected = parseInt(viewer.getAttribute('data-max-selected') || '6', 10) || 6;
    var searchInput = viewer.querySelector('[data-elo-search-input]');
    var searchResults = viewer.querySelector('[data-elo-search-results]');
    var searchNote = viewer.querySelector('[data-elo-search-note]');
    var selectedList = viewer.querySelector('[data-elo-selected-list]');
    var analyzeButton = viewer.querySelector('[data-elo-analyze]');
    var analysisStatus = viewer.querySelector('[data-elo-analysis-status]');
    var result = viewer.querySelector('[data-elo-result]');
    var chart = viewer.querySelector('[data-elo-chart]');
    var chartShell = viewer.querySelector('[data-elo-chart-shell]');
    var tooltip = viewer.querySelector('[data-elo-tooltip]');
    var legend = viewer.querySelector('[data-elo-legend]');
    var selected = new Map();
    var currentResults = [];
    var searchTimer = 0;
    var searchController = null;
    var analysisController = null;
    var searchSerial = 0;
    var renderedSeries = [];
    var chartResizeTimer = 0;

    if (!searchUrl || !trajectoryUrl || !searchInput || !searchResults || !selectedList ||
        !analyzeButton || !analysisStatus ||
        !result || !chart || !chartShell || !tooltip || !legend) return;

    function setSearchOpen(open) {
      var shouldOpen = Boolean(open) && document.activeElement === searchInput;
      searchResults.hidden = !shouldOpen;
      searchInput.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
    }

    function setSearchNote(message, isError) {
      searchNote.textContent = message;
      searchNote.classList.toggle('is-error', Boolean(isError));
    }

    function setStatus(message, isError) {
      analysisStatus.textContent = message || '';
      analysisStatus.hidden = !message;
      analysisStatus.classList.toggle('is-error', Boolean(isError));
    }

    function invalidateAnalysis() {
      result.hidden = true;
      renderedSeries = [];
      setStatus('', false);
      tooltip.hidden = true;
    }

    function optionMeta(record) {
      var date = String(record.created_at || '').slice(0, 16);
      return '#' + record.id + ' · ' + record.match_count + ' 战' + (date ? ' · ' + date : '');
    }

    function renderSearchResults() {
      searchResults.replaceChildren();
      if (!currentResults.length) {
        searchResults.appendChild(element('div', 'elo-observer-dropdown-state', '没有匹配的在役提交'));
        return;
      }
      currentResults.forEach(function (record) {
        var recordId = Number(record.id);
        var checked = selected.has(recordId);
        var label = element('label', 'elo-observer-option' + (checked ? ' is-selected' : ''));
        label.setAttribute('role', 'option');
        label.setAttribute('aria-selected', checked ? 'true' : 'false');

        var checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = checked;
        checkbox.disabled = !checked && selected.size >= maxSelected;
        checkbox.setAttribute('aria-label', '选择 ' + record.username + ' 的提交 #' + record.id);

        var main = element('span', 'elo-observer-option-main');
        main.appendChild(element('strong', '', record.username));
        main.appendChild(element('small', '', optionMeta(record)));
        var rating = element('span', 'elo-observer-option-rating', compactRating(record.rating));

        checkbox.addEventListener('change', function () {
          if (checkbox.checked) {
            if (selected.size >= maxSelected) {
              checkbox.checked = false;
              setSearchNote('单次最多观察 ' + maxSelected + ' 条提交。', true);
              return;
            }
            selected.set(recordId, record);
          } else {
            selected.delete(recordId);
          }
          invalidateAnalysis();
          renderSelected();
          renderSearchResults();
        });

        label.appendChild(checkbox);
        label.appendChild(main);
        label.appendChild(rating);
        searchResults.appendChild(label);
      });
    }

    function renderSelected() {
      selectedList.replaceChildren();
      if (!selected.size) {
        var empty = element('div', 'elo-observer-selected-empty');
        var icon = element('i', 'fas fa-wave-square');
        icon.setAttribute('aria-hidden', 'true');
        empty.appendChild(icon);
        empty.appendChild(element('span', '', '尚未选择提交'));
        selectedList.appendChild(empty);
      } else {
        selected.forEach(function (record, recordId) {
          var chip = element('div', 'elo-observer-chip');
          var label = element('span', '', record.username);
          label.appendChild(element('small', '', '#' + record.id));
          var remove = element('button', '', '×');
          remove.type = 'button';
          remove.setAttribute('aria-label', '移除 ' + record.username + ' 的提交 #' + record.id);
          remove.addEventListener('click', function () {
            selected.delete(recordId);
            invalidateAnalysis();
            renderSelected();
            renderSearchResults();
          });
          chip.appendChild(label);
          chip.appendChild(remove);
          selectedList.appendChild(chip);
        });
      }
      analyzeButton.disabled = selected.size === 0;
    }

    function search(query) {
      if (searchController) searchController.abort();
      var controller = new AbortController();
      searchController = controller;
      var serial = ++searchSerial;
      searchResults.replaceChildren(
        element('div', 'elo-observer-dropdown-state', '正在查找在役提交…')
      );
      setSearchOpen(true);
      setSearchNote('正在匹配 username…', false);

      var url = new URL(searchUrl, window.location.href);
      if (query) url.searchParams.set('q', query);
      window.fetch(url.toString(), {
        credentials: 'same-origin',
        headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
        cache: 'no-store',
        signal: controller.signal,
        mathCurveLoader: false
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok || !data.success) {
            throw new Error(data.message || ('搜索失败（' + response.status + '）'));
          }
          return data;
        });
      }).then(function (data) {
        if (serial !== searchSerial) return;
        currentResults = Array.isArray(data.submissions) ? data.submissions : [];
        renderSearchResults();
        setSearchNote('', false);
      }).catch(function (error) {
        if (error && error.name === 'AbortError') return;
        if (serial !== searchSerial) return;
        currentResults = [];
        searchResults.replaceChildren(
          element('div', 'elo-observer-dropdown-state', error.message || '搜索失败')
        );
        setSearchNote(error.message || '搜索失败，请稍后重试。', true);
      }).finally(function () {
        if (searchController === controller) searchController = null;
      });
    }

    function resultLabel(value) {
      return {
        win: '胜', loss: '负', draw: '平', failed: '未结算', initial: '起始'
      }[value] || value || '';
    }

    function showTooltip(event, series, point, color) {
      tooltip.replaceChildren();
      var title = element('strong', '', series.username + ' · #' + series.submission_id);
      title.style.color = color;
      tooltip.appendChild(title);
      if (point.match_id == null) {
        tooltip.appendChild(element('span', '', '起始 ELO · ' + ratingText(point.rating)));
      } else {
        tooltip.appendChild(element(
          'span', '',
          String(point.created_at || ('时间点 ' + point.sequence)) +
            ' · #' + point.match_id + ' · ' + resultLabel(point.result)
        ));
        tooltip.appendChild(element(
          'span', '',
          ratingText(point.rating) + '（' + deltaText(point.delta) + '）'
        ));
        if (point.opponent) tooltip.appendChild(element('span', '', '对手 · ' + point.opponent));
      }
      if (point.created_at) tooltip.appendChild(element('span', '', String(point.created_at)));
      tooltip.hidden = false;

      var shellRect = chartShell.getBoundingClientRect();
      var eventX = event.clientX || shellRect.left + 80;
      var eventY = event.clientY || shellRect.top + 80;
      var left = eventX - shellRect.left + chartShell.scrollLeft + 12;
      var top = eventY - shellRect.top + chartShell.scrollTop + 12;
      left = Math.max(8, Math.min(left, chartShell.scrollWidth - 260));
      top = Math.max(8, Math.min(top, chartShell.scrollHeight - 110));
      tooltip.style.left = left + 'px';
      tooltip.style.top = top + 'px';
    }

    function renderLegend(seriesList, colors) {
      legend.replaceChildren();
      seriesList.forEach(function (series, index) {
        var item = element('div', 'elo-trajectory-legend-item');
        var swatch = element('span', 'elo-trajectory-legend-swatch');
        swatch.style.backgroundColor = colors[index];
        var text = element('span', 'elo-trajectory-legend-copy');
        text.appendChild(element('strong', '', series.username + ' · #' + series.submission_id));
        item.appendChild(swatch);
        item.appendChild(text);
        item.appendChild(element('b', '', ratingText(series.current_rating)));
        legend.appendChild(item);
      });
    }

    function renderChart(seriesList) {
      renderedSeries = seriesList;
      chart.replaceChildren();
      tooltip.hidden = true;
      var allPoints = [];
      var maxSequence = 0;
      var timelinePoints = (seriesList[0] && seriesList[0].points) || [];
      seriesList.forEach(function (series) {
        (series.points || []).forEach(function (point) {
          allPoints.push(point);
          maxSequence = Math.max(maxSequence, Number(point.sequence) || 0);
        });
      });
      if (!allPoints.length) {
        chart.appendChild(element('div', 'elo-observer-dropdown-state', '所选提交暂无轨迹数据'));
        legend.replaceChildren();
        return;
      }

      var ratings = allPoints.map(function (point) { return Number(point.rating); })
        .filter(Number.isFinite);
      var rawMin = Math.min.apply(Math, ratings);
      var rawMax = Math.max.apply(Math, ratings);
      if (rawMin === rawMax) {
        rawMin -= 25;
        rawMax += 25;
      }
      var yStep = Math.max(10, Math.ceil((rawMax - rawMin) / 5 / 10) * 10);
      var yMin = Math.floor((rawMin - yStep * .45) / yStep) * yStep;
      var yMax = Math.ceil((rawMax + yStep * .45) / yStep) * yStep;
      if (yMax <= yMin) yMax = yMin + yStep;

      var width = Math.max(280, Math.floor(chartShell.clientWidth || viewer.clientWidth || 760));
      var height = 390;
      var padding = {left: 58, right: 26, top: 24, bottom: 43};
      var plotWidth = width - padding.left - padding.right;
      var plotHeight = height - padding.top - padding.bottom;
      var x = function (sequence) {
        if (maxSequence <= 0) return padding.left;
        return padding.left + (Number(sequence) / maxSequence) * plotWidth;
      };
      var y = function (rating) {
        return padding.top + (yMax - Number(rating)) / (yMax - yMin) * plotHeight;
      };

      var svg = svgElement('svg', {
        class: 'elo-trajectory-svg',
        width: width,
        height: height,
        viewBox: '0 0 ' + width + ' ' + height,
        role: 'img',
        'aria-label': '所选提交按公共对战时间线排列的 ELO 得分变化曲线'
      });
      svg.style.width = '100%';

      for (var gridIndex = 0; gridIndex <= 5; gridIndex += 1) {
        var value = yMin + (yMax - yMin) * gridIndex / 5;
        var gridY = y(value);
        svg.appendChild(svgElement('line', {
          class: 'elo-trajectory-grid-line',
          x1: padding.left,
          y1: gridY,
          x2: width - padding.right,
          y2: gridY
        }));
        var yLabel = svgElement('text', {
          class: 'elo-trajectory-axis-label',
          x: padding.left - 9,
          y: gridY + 3,
          'text-anchor': 'end'
        });
        yLabel.textContent = compactRating(value);
        svg.appendChild(yLabel);
      }

      var targetTickCount = Math.max(2, Math.floor(plotWidth / 110));
      var xTickStep = Math.max(1, Math.ceil(Math.max(1, maxSequence) / targetTickCount));
      var lastTickDay = '';
      for (var sequence = 0; sequence <= maxSequence; sequence += xTickStep) {
        var tickPoint = timelinePoints[sequence];
        var tickDay = sequence > 0 ? axisDayKey(tickPoint) : '';
        var tickX = x(sequence);
        var tick = svgElement('text', {
          class: 'elo-trajectory-axis-label',
          x: tickX,
          y: height - 16,
          'text-anchor': sequence === 0 ? 'start' :
            (sequence === maxSequence ? 'end' : 'middle')
        });
        tick.textContent = axisTimeText(tickPoint, Boolean(tickDay) && tickDay !== lastTickDay);
        svg.appendChild(tick);
        if (tickDay) lastTickDay = tickDay;
      }
      if (maxSequence > 0 && maxSequence % xTickStep !== 0) {
        var finalPoint = timelinePoints[maxSequence];
        var finalDay = axisDayKey(finalPoint);
        var lastTick = svgElement('text', {
          class: 'elo-trajectory-axis-label',
          x: x(maxSequence),
          y: height - 16,
          'text-anchor': 'end'
        });
        lastTick.textContent = axisTimeText(
          finalPoint,
          Boolean(finalDay) && finalDay !== lastTickDay
        );
        svg.appendChild(lastTick);
      }

      var colors = seriesList.map(function (_series, index) {
        return seriesColor(index, seriesList.length);
      });
      seriesList.forEach(function (series, seriesIndex) {
        var points = Array.isArray(series.points) ? series.points : [];
        var linePoints = points.filter(function (point, pointIndex) {
          return pointIndex === 0 || point.participated;
        });
        var pathData = linePoints.map(function (point, pointIndex) {
          var pointX = x(point.sequence).toFixed(2);
          var pointY = y(point.rating).toFixed(2);
          return (pointIndex ? 'L' : 'M') + pointX + ' ' + pointY;
        }).join(' ');
        if (pathData) {
          svg.appendChild(svgElement('path', {
            class: 'elo-trajectory-line',
            d: pathData,
            stroke: colors[seriesIndex]
          }));
        }
        points.forEach(function (point) {
          if (!point.participated) return;
          var circle = svgElement('circle', {
            class: 'elo-trajectory-point',
            cx: x(point.sequence),
            cy: y(point.rating),
            r: point.match_id == null ? 3.3 : 4,
            fill: colors[seriesIndex],
            tabindex: 0,
            role: 'button',
            'aria-label': series.username + ' 在 ' + String(point.created_at || '该时间点') +
              ' 对战后的 ELO ' + ratingText(point.rating)
          });
          circle.addEventListener('mouseenter', function (event) {
            showTooltip(event, series, point, colors[seriesIndex]);
          });
          circle.addEventListener('mousemove', function (event) {
            showTooltip(event, series, point, colors[seriesIndex]);
          });
          circle.addEventListener('focus', function (event) {
            showTooltip(event, series, point, colors[seriesIndex]);
          });
          circle.addEventListener('mouseleave', function () { tooltip.hidden = true; });
          circle.addEventListener('blur', function () { tooltip.hidden = true; });
          svg.appendChild(circle);
        });
      });
      chart.appendChild(svg);
      renderLegend(seriesList, colors);
    }

    function scheduleChartResize() {
      if (result.hidden || !renderedSeries.length) return;
      window.clearTimeout(chartResizeTimer);
      chartResizeTimer = window.setTimeout(function () {
        renderChart(renderedSeries);
      }, 80);
    }

    if (window.ResizeObserver) {
      new ResizeObserver(scheduleChartResize).observe(chartShell);
    } else {
      window.addEventListener('resize', scheduleChartResize);
    }

    function analyze() {
      if (!selected.size || analysisController) return;
      var controller = new AbortController();
      analysisController = controller;
      if (modal) modal.classList.add('is-expanded');
      analyzeButton.disabled = true;
      analyzeButton.setAttribute('aria-busy', 'true');
      setStatus('正在从数据库整理所选提交的完整对战轨迹…', false);
      result.hidden = true;

      window.fetch(trajectoryUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({submission_ids: Array.from(selected.keys())}),
        signal: controller.signal,
        mathCurveLoader: false
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok || !data.success) {
            var error = new Error(data.message || ('分析失败（' + response.status + '）'));
            error.missingIds = data.missing_submission_ids || [];
            throw error;
          }
          return data;
        });
      }).then(function (data) {
        var seriesList = Array.isArray(data.series) ? data.series : [];
        result.hidden = false;
        renderChart(seriesList);
        setStatus('', false);
        result.scrollIntoView({behavior: 'smooth', block: 'nearest'});
      }).catch(function (error) {
        if (error && error.name === 'AbortError') return;
        (error.missingIds || []).forEach(function (submissionId) {
          selected.delete(Number(submissionId));
        });
        renderSelected();
        renderSearchResults();
        setStatus(error.message || '分析失败，请稍后重试。', true);
      }).finally(function () {
        if (analysisController === controller) analysisController = null;
        analyzeButton.removeAttribute('aria-busy');
        analyzeButton.disabled = selected.size === 0;
      });
    }

    searchInput.addEventListener('focus', function () {
      if (currentResults.length) {
        setSearchOpen(true);
      } else {
        search((searchInput.value || '').trim());
      }
    });
    searchInput.addEventListener('blur', function () {
      setSearchOpen(false);
    });
    searchInput.addEventListener('input', function () {
      window.clearTimeout(searchTimer);
      var query = (searchInput.value || '').trim();
      searchTimer = window.setTimeout(function () { search(query); }, 220);
    });
    searchResults.addEventListener('pointerdown', function (event) {
      if (event.target.closest('.elo-observer-option')) event.preventDefault();
    });
    analyzeButton.addEventListener('click', analyze);
    viewer.addEventListener('click', function (event) {
      if (!event.target.closest('.elo-observer-search-panel')) setSearchOpen(false);
    });
    if (modal) {
      modal.addEventListener('hidden.bs.modal', function () {
        setSearchOpen(false);
        tooltip.hidden = true;
        if (searchController) searchController.abort();
        modal.classList.remove('is-expanded');
        result.hidden = true;
        renderedSeries = [];
        chart.replaceChildren();
        legend.replaceChildren();
        setStatus('', false);
      });
      modal.addEventListener('hide.bs.modal', function () {
        if (analysisController) analysisController.abort();
      });
    }
    renderSelected();
  }

  function init(root) {
    if (!root) return;
    if (root.matches && root.matches('[data-elo-trajectory-viewer]')) initViewer(root);
    root.querySelectorAll('[data-elo-trajectory-viewer]').forEach(initViewer);
  }

  window.EloTrajectoryViewer = {init: init};
}());
