(function () {
  "use strict";

  if (window.NumericalOJMarkdownRenderer) return;

  const MERMAID_MAX_TEXT_SIZE = 50_000;
  const MERMAID_MAX_EDGES = 500;
  const MERMAID_MAX_DIAGRAMS_PER_ROOT = 64;

  let mermaidRenderer = null;
  let mermaidRenderSequence = 0;

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
    const mathJax = window.MathJax;
    if (!root || !mathJax || typeof mathJax.typesetClear !== "function") return;
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
