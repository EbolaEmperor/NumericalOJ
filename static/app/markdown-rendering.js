(function () {
  "use strict";

  if (window.NumericalOJMarkdownRenderer) return;

  const MERMAID_MAX_TEXT_SIZE = 50_000;
  const MERMAID_MAX_EDGES = 500;
  const MERMAID_MAX_DIAGRAMS_PER_ROOT = 64;
  const CPP_SEMANTIC_MAX_BLOCKS_PER_ROOT = 16;
  const CPP_SEMANTIC_MAX_INFLIGHT_PER_PAGE = 2;
  const CPP_SEMANTIC_MAX_SOURCE_BYTES = 512 * 1024;
  const CPP_SEMANTIC_MAX_TOKENS_PER_BLOCK = 12_000;
  const CPP_LANGUAGE_CLASSES = new Set([
    "language-cpp",
    "language-c++",
    "language-cc",
    "language-cxx",
  ]);

  let mermaidRenderer = null;
  let mermaidRenderSequence = 0;
  let semanticRenderSequence = 0;
  let semanticWarningShown = false;
  let semanticActiveTasks = 0;
  const semanticTaskQueue = [];
  const semanticControllers = new WeakMap();

  function getMermaidRenderer() {
    const candidate = window.mermaid;
    if (!candidate || typeof candidate.initialize !== "function") return null;
    if (mermaidRenderer === candidate) return mermaidRenderer;

    try {
      candidate.initialize({
        startOnLoad: false,
        securityLevel: "sandbox",
        secure: [
          "secure",
          "securityLevel",
          "startOnLoad",
          "maxTextSize",
          "maxEdges",
          "suppressErrorRendering",
          "htmlLabels",
          "dompurifyConfig",
          "theme",
          "themeCSS",
          "themeVariables",
        ],
        suppressErrorRendering: true,
        maxTextSize: MERMAID_MAX_TEXT_SIZE,
        maxEdges: MERMAID_MAX_EDGES,
        htmlLabels: false,
        logLevel: "fatal",
        theme: "base",
        themeVariables: {
          background: "#ffffff",
          fontFamily: '"Avenir Next", "PingFang SC", "Microsoft YaHei", sans-serif',
          lineColor: "#71717a",
          primaryColor: "#fff7ed",
          primaryTextColor: "#18181b",
          primaryBorderColor: "#ea580c",
          secondaryColor: "#f4f4f5",
          secondaryTextColor: "#27272a",
          secondaryBorderColor: "#a1a1aa",
          tertiaryColor: "#ffffff",
          tertiaryTextColor: "#3f3f46",
          tertiaryBorderColor: "#d4d4d8",
        },
        flowchart: {
          htmlLabels: false,
          useMaxWidth: true,
        },
      });
      mermaidRenderer = candidate;
      return mermaidRenderer;
    } catch (_error) {
      mermaidRenderer = null;
      return null;
    }
  }

  function enhanceRenderedLinks(root) {
    root.querySelectorAll("a[href]").forEach((link) => {
      try {
        const url = new URL(link.href, window.location.href);
        if (url.origin !== window.location.origin) {
          link.target = "_blank";
          link.rel = "noopener noreferrer";
        }
      } catch (_error) {
        link.removeAttribute("href");
      }
    });
  }

  function isCppCodeBlock(block) {
    return Array.from(block.classList).some((name) => (
      CPP_LANGUAGE_CLASSES.has(name.toLowerCase())
    ));
  }

  function semanticCssName(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function lineStartOffsets(source) {
    const offsets = [0];
    for (let index = 0; index < source.length; index += 1) {
      if (source.charCodeAt(index) === 10) offsets.push(index + 1);
    }
    return offsets;
  }

  function cppSourceByteLength(source) {
    if (typeof TextEncoder === "function") {
      return new TextEncoder().encode(source).byteLength;
    }
    return new Blob([source]).size;
  }

  function decodeSemanticRanges(source, legend, data) {
    const tokenTypes = Array.isArray(legend && legend.tokenTypes)
      ? legend.tokenTypes
      : [];
    const tokenModifiers = Array.isArray(legend && legend.tokenModifiers)
      ? legend.tokenModifiers
      : [];
    const offsets = lineStartOffsets(source);
    const ranges = [];
    let serverLine = 0;
    let serverStart = 0;

    for (
      let index = 0;
      index < data.length && ranges.length < CPP_SEMANTIC_MAX_TOKENS_PER_BLOCK;
      index += 5
    ) {
      const deltaLine = Number(data[index]);
      const deltaStart = Number(data[index + 1]);
      const length = Number(data[index + 2]);
      const tokenTypeIndex = Number(data[index + 3]);
      const modifierBits = Number(data[index + 4]);
      if (
        !Number.isInteger(deltaLine)
        || !Number.isInteger(deltaStart)
        || !Number.isInteger(length)
        || !Number.isInteger(tokenTypeIndex)
        || !Number.isInteger(modifierBits)
        || deltaLine < 0
        || deltaStart < 0
        || length <= 0
        || tokenTypeIndex < 0
        || modifierBits < 0
      ) continue;

      serverLine += deltaLine;
      serverStart = deltaLine === 0 ? serverStart + deltaStart : deltaStart;
      const displayLine = serverLine;
      const tokenType = tokenTypes[tokenTypeIndex];
      if (!tokenType || displayLine >= offsets.length) continue;

      const lineStart = offsets[displayLine];
      let lineEnd = source.length;
      if (displayLine + 1 < offsets.length) {
        const newlineOffset = offsets[displayLine + 1] - 1;
        lineEnd = (
          newlineOffset > lineStart
          && source.charCodeAt(newlineOffset - 1) === 13
        ) ? newlineOffset - 1 : newlineOffset;
      }
      const start = lineStart + serverStart;
      const end = start + length;
      if (start < lineStart || end > lineEnd) continue;

      const modifiers = [];
      for (
        let modifierIndex = 0;
        modifierIndex < tokenModifiers.length && modifierIndex < 31;
        modifierIndex += 1
      ) {
        if ((modifierBits & (1 << modifierIndex)) !== 0) {
          modifiers.push(tokenModifiers[modifierIndex]);
        }
      }
      ranges.push({
        start,
        end,
        type: tokenType,
        modifiers,
      });
    }
    ranges.sort((left, right) => (
      left.start - right.start || left.end - right.end
    ));
    let previousEnd = 0;
    return ranges.filter((range) => {
      if (range.start < previousEnd) return false;
      previousEnd = range.end;
      return true;
    });
  }

  function textNodeEntries(code) {
    const entries = [];
    const walker = document.createTreeWalker(code, NodeFilter.SHOW_TEXT);
    let offset = 0;
    let node = walker.nextNode();
    while (node) {
      const length = node.data.length;
      entries.push({
        node,
        start: offset,
        end: offset + length,
      });
      offset += length;
      node = walker.nextNode();
    }
    return entries;
  }

  function applySemanticRanges(code, ranges) {
    const entries = textNodeEntries(code);
    let rangeIndex = 0;
    let applied = 0;

    entries.forEach((entry) => {
      while (
        rangeIndex < ranges.length
        && ranges[rangeIndex].end <= entry.start
      ) {
        rangeIndex += 1;
      }
      const segments = [];
      let scanIndex = rangeIndex;
      while (
        scanIndex < ranges.length
        && ranges[scanIndex].start < entry.end
      ) {
        const range = ranges[scanIndex];
        const segmentStart = Math.max(range.start, entry.start);
        const segmentEnd = Math.min(range.end, entry.end);
        if (segmentStart < segmentEnd) {
          segments.push({
            start: segmentStart - entry.start,
            end: segmentEnd - entry.start,
            range,
          });
        }
        scanIndex += 1;
      }

      segments.sort((left, right) => right.start - left.start);
      segments.forEach((segment) => {
        const length = segment.end - segment.start;
        if (
          segment.start < 0
          || length <= 0
          || segment.end > entry.node.length
        ) return;

        const selected = entry.node.splitText(segment.start);
        selected.splitText(length);
        const span = document.createElement("span");
        const typeName = semanticCssName(segment.range.type);
        span.classList.add("numoj-semantic-token");
        if (typeName) span.classList.add(`numoj-semantic-${typeName}`);
        segment.range.modifiers.forEach((modifier) => {
          const modifierName = semanticCssName(modifier);
          if (modifierName) span.classList.add(`numoj-semantic-${modifierName}`);
        });
        span.dataset.semanticType = segment.range.type;
        selected.replaceWith(span);
        span.appendChild(selected);
        applied += 1;
      });
    });
    return applied;
  }

  function drainSemanticTaskQueue() {
    while (
      semanticActiveTasks < CPP_SEMANTIC_MAX_INFLIGHT_PER_PAGE
      && semanticTaskQueue.length
    ) {
      const entry = semanticTaskQueue.shift();
      if (entry.signal.aborted) {
        entry.cleanup();
        entry.resolve();
        continue;
      }
      semanticActiveTasks += 1;
      Promise.resolve()
        .then(entry.task)
        .then(entry.resolve, entry.reject)
        .finally(() => {
          entry.cleanup();
          semanticActiveTasks -= 1;
          drainSemanticTaskQueue();
        });
    }
  }

  function scheduleSemanticTask(task, signal) {
    if (signal.aborted) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const entry = {
        cleanup: null,
        reject,
        resolve,
        signal,
        task,
      };
      const cancelQueuedTask = () => {
        const index = semanticTaskQueue.indexOf(entry);
        if (index === -1) return;
        semanticTaskQueue.splice(index, 1);
        entry.cleanup();
        resolve();
      };
      entry.cleanup = () => {
        signal.removeEventListener("abort", cancelQueuedTask);
      };
      signal.addEventListener("abort", cancelQueuedTask, { once: true });
      semanticTaskQueue.push(entry);
      drainSemanticTaskQueue();
    });
  }

  function semanticBlockIsCurrent(
    root, block, code, source, generation, signal,
  ) {
    return (
      !signal.aborted
      && root.isConnected
      && root.contains(block)
      && block.isConnected
      && code.isConnected
      && block.dataset.numojSemanticGeneration === generation
      && String(code.textContent || "") === source
    );
  }

  async function renderCppSemanticBlock(root, block, controller, legend) {
    const existingState = block.dataset.numojSemanticState;
    if (existingState && existingState !== "queued") return;
    const client = window.NumOJSemanticTokens;
    const code = block.querySelector("pre code");
    if (
      !client
      || typeof client.getLegend !== "function"
      || typeof client.requestTokens !== "function"
      || !code
    ) return;

    const source = String(code.textContent || "");
    if (!source) {
      block.dataset.numojSemanticState = "empty";
      return;
    }
    if (cppSourceByteLength(source) > CPP_SEMANTIC_MAX_SOURCE_BYTES) {
      block.dataset.numojSemanticState = "skipped-size";
      return;
    }

    const generation = String(++semanticRenderSequence);
    block.dataset.numojSemanticState = "rendering";
    block.dataset.numojSemanticGeneration = generation;
    block.setAttribute("aria-busy", "true");

    try {
      const payload = await client.requestTokens({
        context: "markdown",
        language: "cpp",
        source,
        signal: controller.signal,
      });
      if (!semanticBlockIsCurrent(
        root, block, code, source, generation, controller.signal,
      )) return;

      const ranges = decodeSemanticRanges(source, legend, payload.data);
      applySemanticRanges(code, ranges);
      block.dataset.numojSemanticState = "rendered";
      block.classList.add("has-semantic-highlighting");
    } catch (error) {
      if (!semanticBlockIsCurrent(
        root, block, code, source, generation, controller.signal,
      )) return;
      block.dataset.numojSemanticState = "fallback";
      if (!semanticWarningShown) {
        console.warn("C++ 代码块 clangd 高亮失败，已保留 Pygments 着色。", error);
        semanticWarningShown = true;
      }
    } finally {
      if (block.dataset.numojSemanticGeneration === generation) {
        block.removeAttribute("aria-busy");
      }
    }
  }

  async function renderCppSemanticHighlights(root) {
    const client = window.NumOJSemanticTokens;
    if (
      !client
      || typeof client.getLegend !== "function"
      || typeof client.requestTokens !== "function"
    ) return;

    const blocks = Array.from(root.querySelectorAll(".codehilite"))
      .filter((block) => (
        isCppCodeBlock(block) && !block.dataset.numojSemanticState
      ));
    const renderable = blocks.slice(0, CPP_SEMANTIC_MAX_BLOCKS_PER_ROOT);
    renderable.forEach((block) => {
      block.dataset.numojSemanticState = "queued";
    });
    blocks.slice(CPP_SEMANTIC_MAX_BLOCKS_PER_ROOT).forEach((block) => {
      block.dataset.numojSemanticState = "skipped";
    });
    if (!renderable.length) return;

    let controller = semanticControllers.get(root);
    if (!controller || controller.signal.aborted) {
      controller = new AbortController();
      semanticControllers.set(root, controller);
    }
    let legend;
    try {
      legend = await client.getLegend("cpp", {
        signal: controller.signal,
      });
    } catch (error) {
      if (!controller.signal.aborted && root.isConnected) {
        renderable.forEach((block) => {
          if (root.contains(block)) {
            block.dataset.numojSemanticState = "fallback";
          }
        });
        if (!semanticWarningShown) {
          console.warn(
            "C++ 代码块 clangd legend 获取失败，已保留 Pygments 着色。",
            error,
          );
          semanticWarningShown = true;
        }
      }
      return;
    }
    if (controller.signal.aborted || !root.isConnected) return;
    await Promise.all(renderable.map((block) => (
      scheduleSemanticTask(
        () => renderCppSemanticBlock(root, block, controller, legend),
        controller.signal,
      )
    )));
  }

  async function typesetMath(root) {
    const mathJax = window.MathJax;
    if (!mathJax) return;
    try {
      if (mathJax.startup && mathJax.startup.promise) {
        await mathJax.startup.promise;
      }
      if (typeof mathJax.typesetPromise === "function" && root.isConnected) {
        await mathJax.typesetPromise([root]);
      }
    } catch (_error) {
      // 公式错误只影响该段展示，不反转正文加载结果。
    }
  }

  function clear(root) {
    if (!root) return;
    const semanticController = semanticControllers.get(root);
    if (semanticController) {
      semanticController.abort();
      semanticControllers.delete(root);
    }
    const mathJax = window.MathJax;
    if (!mathJax || typeof mathJax.typesetClear !== "function") return;
    try {
      mathJax.typesetClear([root]);
    } catch (_error) {
      // 清理失败时仍允许调用方替换旧 DOM。
    }
  }

  function mermaidStatus(message) {
    const status = document.createElement("div");
    status.className = "numoj-mermaid-status";
    status.setAttribute("role", "status");
    status.textContent = message;
    return status;
  }

  function markMermaidSourceError(container, message) {
    if (container.dataset.numojMermaidState) return;
    container.dataset.numojMermaidState = "error";
    container.classList.add("numoj-mermaid-source", "is-error");
    container.prepend(mermaidStatus(message));
  }

  async function renderMermaidBlock(container) {
    const existingState = container.dataset.numojMermaidState;
    if (existingState && existingState !== "queued") return;
    const code = container.querySelector("pre code");
    const sourcePre = code && code.closest("pre");
    if (!code || !sourcePre) return;

    const source = String(code.textContent || "");
    const generation = String(++mermaidRenderSequence);
    container.dataset.numojMermaidState = "rendering";
    container.dataset.numojMermaidGeneration = generation;
    container.classList.add("numoj-mermaid-source");
    container.setAttribute("aria-busy", "true");

    const status = mermaidStatus("正在安全绘制 Mermaid 图…");
    const diagram = document.createElement("div");
    diagram.className = "numoj-mermaid-diagram mermaid";
    diagram.textContent = source;

    const sourceDetails = document.createElement("details");
    const sourceSummary = document.createElement("summary");
    sourceSummary.textContent = "查看 Mermaid 源码";
    sourceDetails.append(sourceSummary, sourcePre);
    container.replaceChildren(status, diagram, sourceDetails);

    try {
      const renderer = getMermaidRenderer();
      if (!renderer) throw new Error("renderer-unavailable");
      if (source.length > MERMAID_MAX_TEXT_SIZE) throw new Error("source-too-large");
      const parsed = await renderer.parse(source, { suppressErrors: true });
      if (!parsed) throw new Error("invalid-diagram");
      if (
        !container.isConnected
        || container.dataset.numojMermaidGeneration !== generation
      ) return;

      await renderer.run({ nodes: [diagram] });
      if (
        !container.isConnected
        || container.dataset.numojMermaidGeneration !== generation
      ) return;

      status.remove();
      container.dataset.numojMermaidState = "rendered";
    } catch (_error) {
      if (
        !container.isConnected
        || container.dataset.numojMermaidGeneration !== generation
      ) return;
      diagram.remove();
      status.textContent = "Mermaid 语法无效或图表过于复杂，已保留源码。";
      sourceDetails.open = true;
      container.dataset.numojMermaidState = "error";
      container.classList.add("is-error");
    } finally {
      if (container.dataset.numojMermaidGeneration === generation) {
        container.removeAttribute("aria-busy");
      }
    }
  }

  async function renderMermaidDiagrams(root) {
    const blocks = Array.from(
      root.querySelectorAll(
        ".codehilite.language-mermaid, .codehilite.language-mmd",
      ),
    ).filter((block) => !block.dataset.numojMermaidState);

    const renderable = blocks.slice(0, MERMAID_MAX_DIAGRAMS_PER_ROOT);
    renderable.forEach((block) => {
      block.dataset.numojMermaidState = "queued";
    });
    blocks.slice(MERMAID_MAX_DIAGRAMS_PER_ROOT).forEach((block) => {
      markMermaidSourceError(block, "本次页面中的图表数量过多，已保留源码。");
    });
    for (const block of renderable) {
      await renderMermaidBlock(block);
    }
  }

  async function enhance(root) {
    if (!root || typeof root.querySelectorAll !== "function") return;
    enhanceRenderedLinks(root);
    renderCppSemanticHighlights(root).catch((error) => {
      if (!semanticWarningShown) {
        console.warn("C++ 代码块 clangd 高亮任务失败。", error);
        semanticWarningShown = true;
      }
    });
    await renderMermaidDiagrams(root);
    if (root.isConnected) await typesetMath(root);
  }

  async function enhanceAll(scope) {
    const root = scope || document;
    const targets = [];
    if (root.matches && root.matches("[data-numoj-markdown]")) targets.push(root);
    root.querySelectorAll("[data-numoj-markdown]").forEach((target) => {
      targets.push(target);
    });
    await Promise.all(targets.map((target) => enhance(target)));
  }

  window.NumericalOJMarkdownRenderer = Object.freeze({
    clear,
    enhance,
    enhanceAll,
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      enhanceAll(document);
    }, { once: true });
  } else {
    enhanceAll(document);
  }
}());
