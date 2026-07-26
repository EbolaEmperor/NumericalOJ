(function () {
  "use strict";

  if (window.NumericalOJMarkdownRenderer) return;

  const MERMAID_MAX_TEXT_SIZE = 50_000;
  const MERMAID_MAX_EDGES = 500;
  const MERMAID_MAX_DIAGRAMS_PER_ROOT = 64;
  const BASH_TEXTMATE_MAX_BLOCKS_PER_ROOT = 64;
  const BASH_TEXTMATE_MAX_SOURCE_BYTES = 256 * 1024;
  const BASH_TEXTMATE_MAX_TOTAL_SOURCE_BYTES_PER_ROOT = 1024 * 1024;
  const CPP_SEMANTIC_MAX_BLOCKS_PER_ROOT = 16;
  const CPP_SEMANTIC_MAX_INFLIGHT_PER_PAGE = 2;
  const CPP_SEMANTIC_MAX_SOURCE_BYTES = 512 * 1024;
  const CPP_SEMANTIC_MAX_TOKENS_PER_BLOCK = 12_000;
  const CPP_INACTIVE_MAX_REGIONS_PER_BLOCK = 4_096;
  const CODE_COPY_RESET_DELAY_MS = 1_800;
  const BASH_LANGUAGE_CLASSES = new Set([
    "language-bash",
    "language-sh",
    "language-shell",
    "language-shellscript",
    "language-zsh",
    "language-ksh",
    "language-openrc",
  ]);
  const SHIKI_DARK_PLUS_COLORS = new Set([
    "000080",
    "4ec9b0",
    "4fc1ff",
    "569cd6",
    "646695",
    "6796e6",
    "6a9955",
    "808080",
    "9cdcfe",
    "b5cea8",
    "c586c0",
    "c8c8c8",
    "ce9178",
    "d16969",
    "d4d4d4",
    "d7ba7d",
    "dcdcaa",
    "f44747",
  ]);
  const CPP_LANGUAGE_CLASSES = new Set([
    "language-cpp",
    "language-c++",
    "language-cc",
    "language-cxx",
  ]);

  let mermaidRenderer = null;
  let mermaidRenderSequence = 0;
  let bashRenderSequence = 0;
  let bashWarningShown = false;
  let semanticRenderSequence = 0;
  let semanticWarningShown = false;
  let semanticActiveTasks = 0;
  const semanticTaskQueue = [];
  const semanticControllers = new WeakMap();
  const copyResetTimers = new WeakMap();

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

  async function writeClipboardText(text) {
    const value = String(text ?? "");
    let clipboardError = null;

    if (
      navigator.clipboard
      && typeof navigator.clipboard.writeText === "function"
    ) {
      try {
        await navigator.clipboard.writeText(value);
        return;
      } catch (error) {
        clipboardError = error;
      }
    }

    const textarea = document.createElement("textarea");
    const activeElement = document.activeElement;
    const selection = window.getSelection();
    const previousRanges = [];
    if (selection) {
      for (let index = 0; index < selection.rangeCount; index += 1) {
        previousRanges.push(selection.getRangeAt(index).cloneRange());
      }
    }

    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.setAttribute("aria-hidden", "true");
    textarea.tabIndex = -1;
    Object.assign(textarea.style, {
      position: "fixed",
      top: "0",
      left: "-9999px",
      width: "1px",
      height: "1px",
      opacity: "0",
      pointerEvents: "none",
      fontSize: "16px",
    });
    document.body.appendChild(textarea);

    let copied = false;
    try {
      try {
        textarea.focus({ preventScroll: true });
      } catch (_focusError) {
        textarea.focus();
      }
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      copied = Boolean(document.execCommand && document.execCommand("copy"));
    } catch (error) {
      clipboardError = clipboardError || error;
    } finally {
      textarea.remove();
      if (selection) {
        selection.removeAllRanges();
        previousRanges.forEach((range) => selection.addRange(range));
      }
      if (activeElement && typeof activeElement.focus === "function") {
        try {
          activeElement.focus({ preventScroll: true });
        } catch (_focusError) {
          activeElement.focus();
        }
      }
    }

    if (!copied) {
      throw clipboardError || new Error("clipboard-unavailable");
    }
  }

  function directCopyButton(frame) {
    return Array.from(frame.children).find((child) => (
      child.classList && child.classList.contains("numoj-code-copy")
    )) || null;
  }

  function setCopyButtonState(button, state) {
    const existingTimer = copyResetTimers.get(button);
    if (existingTimer) {
      window.clearTimeout(existingTimer);
      copyResetTimers.delete(button);
    }

    const copied = state === "copied";
    const failed = state === "error";
    const label = copied
      ? "代码已复制"
      : (failed ? "复制失败，请重试" : "复制代码");
    const icon = button.querySelector(".numoj-code-copy-icon");
    const announcement = button.querySelector(".numoj-code-copy-announcement");
    button.classList.toggle("is-copied", copied);
    button.classList.toggle("is-error", failed);
    button.setAttribute("aria-label", label);
    button.title = label;
    if (icon) icon.className = `numoj-code-copy-icon fas ${
      copied ? "fa-check" : "fa-copy"
    }`;
    if (announcement) announcement.textContent = state === "idle" ? "" : label;

    if (state !== "idle") {
      const timer = window.setTimeout(() => {
        copyResetTimers.delete(button);
        setCopyButtonState(button, "idle");
      }, CODE_COPY_RESET_DELAY_MS);
      copyResetTimers.set(button, timer);
    }
  }

  async function copyCodeBlock(button, code) {
    if (button.dataset.numojCopyBusy === "true") return;
    button.dataset.numojCopyBusy = "true";
    button.setAttribute("aria-busy", "true");
    try {
      await writeClipboardText(String(code.textContent || ""));
      setCopyButtonState(button, "copied");
    } catch (_error) {
      setCopyButtonState(button, "error");
    } finally {
      delete button.dataset.numojCopyBusy;
      button.removeAttribute("aria-busy");
    }
  }

  function ensureCodeCopyButtons(root) {
    const codeElements = [];
    if (root.matches && root.matches("pre code")) codeElements.push(root);
    root.querySelectorAll("pre code").forEach((code) => {
      codeElements.push(code);
    });

    codeElements.forEach((code) => {
      const frame = code.closest(".codehilite") || code.closest("pre");
      if (!frame) return;
      frame.classList.add("numoj-code-frame");
      if (directCopyButton(frame)) return;

      const button = document.createElement("button");
      const icon = document.createElement("i");
      const announcement = document.createElement("span");
      button.type = "button";
      button.className = "numoj-code-copy";
      button.setAttribute("aria-label", "复制代码");
      button.title = "复制代码";
      icon.className = "numoj-code-copy-icon fas fa-copy";
      icon.setAttribute("aria-hidden", "true");
      announcement.className = "numoj-code-copy-announcement";
      announcement.setAttribute("aria-live", "polite");
      announcement.setAttribute("aria-atomic", "true");
      button.append(icon, announcement);
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        copyCodeBlock(button, code);
      });
      frame.appendChild(button);
    });
  }

  function isBashCodeBlock(block) {
    return Array.from(block.classList).some((name) => (
      BASH_LANGUAGE_CLASSES.has(name.toLowerCase())
    ));
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

  function sourceByteLength(source) {
    if (typeof TextEncoder === "function") {
      return new TextEncoder().encode(source).byteLength;
    }
    return new Blob([source]).size;
  }

  function shikiColorClass(value) {
    const color = String(value || "").trim().replace(/^#/, "").toLowerCase();
    return SHIKI_DARK_PLUS_COLORS.has(color)
      ? `numoj-shiki-color-${color}`
      : "";
  }

  function bashTokenFragment(result) {
    if (!result || !Array.isArray(result.tokens)) return null;
    const fragment = document.createDocumentFragment();
    result.tokens.forEach((line, lineIndex) => {
      if (!Array.isArray(line)) return;
      line.forEach((token) => {
        const content = String(token && token.content || "");
        if (!content) return;
        const colorClass = shikiColorClass(token.color);
        const rawFontStyle = Number(token.fontStyle || 0);
        const fontStyle = Number.isInteger(rawFontStyle) && rawFontStyle > 0
          ? rawFontStyle
          : 0;
        if (!colorClass && fontStyle <= 0) {
          fragment.appendChild(document.createTextNode(content));
          return;
        }
        const span = document.createElement("span");
        span.className = "numoj-shiki-token";
        if (colorClass) span.classList.add(colorClass);
        if ((fontStyle & 1) !== 0) span.classList.add("is-italic");
        if ((fontStyle & 2) !== 0) span.classList.add("is-bold");
        if ((fontStyle & 4) !== 0) span.classList.add("is-underlined");
        span.textContent = content;
        fragment.appendChild(span);
      });
      if (lineIndex < result.tokens.length - 1) {
        fragment.appendChild(document.createTextNode("\n"));
      }
    });
    return fragment;
  }

  async function renderBashTextMateBlock(root, block) {
    if (block.dataset.numojBashState) return;
    const client = window.NumOJBashHighlighter;
    const code = block.querySelector("pre code");
    if (!client || typeof client.tokenize !== "function" || !code) return;

    const source = String(code.textContent || "");
    if (!source) {
      block.dataset.numojBashState = "empty";
      return;
    }
    if (sourceByteLength(source) > BASH_TEXTMATE_MAX_SOURCE_BYTES) {
      block.dataset.numojBashState = "skipped-size";
      return;
    }

    const generation = String(++bashRenderSequence);
    block.dataset.numojBashState = "rendering";
    block.dataset.numojBashGeneration = generation;
    try {
      const result = await client.tokenize(source);
      if (
        !root.isConnected
        || !root.contains(block)
        || !block.isConnected
        || !code.isConnected
        || block.dataset.numojBashGeneration !== generation
        || String(code.textContent || "") !== source
      ) return;

      const fragment = bashTokenFragment(result);
      if (!fragment || String(fragment.textContent || "") !== source) {
        throw new Error("bash-token-text-mismatch");
      }
      code.replaceChildren(fragment);
      block.dataset.numojBashState = "rendered";
      block.classList.add("has-bash-textmate-highlighting");
    } catch (error) {
      if (
        root.isConnected
        && root.contains(block)
        && block.dataset.numojBashGeneration === generation
      ) {
        block.dataset.numojBashState = "fallback";
        if (!bashWarningShown) {
          console.warn(
            "Bash TextMate 高亮失败，已保留 Pygments 着色。",
            error,
          );
          bashWarningShown = true;
        }
      }
    }
  }

  async function renderBashTextMateHighlights(root) {
    const client = window.NumOJBashHighlighter;
    if (!client || typeof client.tokenize !== "function") return;

    const blocks = Array.from(root.querySelectorAll(".codehilite"))
      .filter((block) => isBashCodeBlock(block) && !block.dataset.numojBashState);
    const candidates = blocks.slice(0, BASH_TEXTMATE_MAX_BLOCKS_PER_ROOT);
    blocks.slice(BASH_TEXTMATE_MAX_BLOCKS_PER_ROOT).forEach((block) => {
      block.dataset.numojBashState = "skipped";
    });

    const renderable = [];
    let totalSourceBytes = 0;
    candidates.forEach((block) => {
      const code = block.querySelector("pre code");
      const sourceBytes = code
        ? sourceByteLength(String(code.textContent || ""))
        : 0;
      if (sourceBytes > BASH_TEXTMATE_MAX_SOURCE_BYTES) {
        block.dataset.numojBashState = "skipped-size";
        return;
      }
      if (
        totalSourceBytes + sourceBytes
        > BASH_TEXTMATE_MAX_TOTAL_SOURCE_BYTES_PER_ROOT
      ) {
        block.dataset.numojBashState = "skipped-total-size";
        return;
      }
      totalSourceBytes += sourceBytes;
      renderable.push(block);
    });

    for (let index = 0; index < renderable.length; index += 1) {
      const block = renderable[index];
      if (!root.isConnected) break;
      if (!root.contains(block)) continue;
      await renderBashTextMateBlock(root, block);
      if (index + 1 < renderable.length) {
        // TextMate token 化在浏览器主线程运行；块间让出一次事件循环，
        // 避免包含大量 Bash 片段的讨论长时间阻塞交互和绘制。
        await new Promise((resolve) => window.setTimeout(resolve, 0));
      }
    }
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

  function sourceOffsetForPosition(source, offsets, position) {
    const line = Number(position && position.line);
    const character = Number(position && position.character);
    if (
      !Number.isInteger(line)
      || !Number.isInteger(character)
      || line < 0
      || character < 0
      || line >= offsets.length
    ) return null;

    const lineStart = offsets[line];
    let lineEnd = source.length;
    if (line + 1 < offsets.length) {
      const newlineOffset = offsets[line + 1] - 1;
      lineEnd = (
        newlineOffset > lineStart
        && source.charCodeAt(newlineOffset - 1) === 13
      ) ? newlineOffset - 1 : newlineOffset;
    }
    if (character > lineEnd - lineStart) return null;
    return lineStart + character;
  }

  function decodeInactiveRanges(source, regions) {
    if (!Array.isArray(regions)) return [];
    const offsets = lineStartOffsets(source);
    const ranges = [];
    regions.slice(0, CPP_INACTIVE_MAX_REGIONS_PER_BLOCK).forEach((region) => {
      const start = sourceOffsetForPosition(
        source,
        offsets,
        region && region.start,
      );
      const end = sourceOffsetForPosition(
        source,
        offsets,
        region && region.end,
      );
      if (start === null || end === null || start >= end) return;
      ranges.push({ start, end });
    });
    ranges.sort((left, right) => (
      left.start - right.start || left.end - right.end
    ));

    return ranges.reduce((merged, range) => {
      const previous = merged[merged.length - 1];
      if (!previous || range.start > previous.end) {
        merged.push({ start: range.start, end: range.end });
      } else {
        previous.end = Math.max(previous.end, range.end);
      }
      return merged;
    }, []);
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

  function applyInactiveRanges(code, ranges) {
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
        const start = Math.max(range.start, entry.start) - entry.start;
        const end = Math.min(range.end, entry.end) - entry.start;
        if (start < end) segments.push({ start, end });
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
        span.className = "numoj-clangd-inactive-code";
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
    if (sourceByteLength(source) > CPP_SEMANTIC_MAX_SOURCE_BYTES) {
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
      const inactiveRanges = decodeInactiveRanges(
        source,
        payload.inactive_regions,
      );
      applySemanticRanges(code, ranges);
      if (applyInactiveRanges(code, inactiveRanges) > 0) {
        block.classList.add("has-inactive-regions");
      }
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
    root.querySelectorAll(".numoj-code-copy").forEach((button) => {
      const timer = copyResetTimers.get(button);
      if (timer) window.clearTimeout(timer);
      copyResetTimers.delete(button);
    });
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
    ensureCodeCopyButtons(container);

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
    ensureCodeCopyButtons(root);
    renderCppSemanticHighlights(root).catch((error) => {
      if (!semanticWarningShown) {
        console.warn("C++ 代码块 clangd 高亮任务失败。", error);
        semanticWarningShown = true;
      }
    });
    await Promise.all([
      renderBashTextMateHighlights(root),
      renderMermaidDiagrams(root),
    ]);
    // Mermaid 会重组容器并移动源码节点，因此绘制完成后幂等补回复制按钮。
    ensureCodeCopyButtons(root);
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
    copyText: writeClipboardText,
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
