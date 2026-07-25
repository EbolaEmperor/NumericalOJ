(function () {
  "use strict";

  const MERMAID_MAX_TEXT_SIZE = 50_000;
  const MERMAID_MAX_EDGES = 500;
  const MERMAID_MAX_DIAGRAMS_PER_ROOT = 64;

  let mermaidRenderer = null;
  let mermaidRenderSequence = 0;

  try {
    if (window.mermaid && typeof window.mermaid.initialize === "function") {
      mermaidRenderer = window.mermaid;
      mermaidRenderer.initialize({
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
    }
  } catch (_error) {
    mermaidRenderer = null;
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

  function typesetMath(root) {
    if (!window.MathJax || typeof window.MathJax.typesetPromise !== "function") {
      return Promise.resolve();
    }
    return window.MathJax.typesetPromise([root]).catch(() => {
      // 公式错误只影响该段展示，不反转正文加载结果。
    });
  }

  function mermaidStatus(message) {
    const status = document.createElement("div");
    status.className = "forum-mermaid-status";
    status.setAttribute("role", "status");
    status.textContent = message;
    return status;
  }

  function markMermaidSourceError(container, message) {
    if (container.dataset.mermaidState) return;
    container.dataset.mermaidState = "error";
    container.classList.add("forum-mermaid-source", "is-error");
    container.prepend(mermaidStatus(message));
  }

  async function renderMermaidBlock(container) {
    if (container.dataset.mermaidState) return;
    const code = container.querySelector("pre code");
    const sourcePre = code && code.closest("pre");
    if (!code || !sourcePre) return;

    const source = String(code.textContent || "");
    const generation = String(++mermaidRenderSequence);
    container.dataset.mermaidState = "rendering";
    container.dataset.mermaidGeneration = generation;
    container.classList.add("forum-mermaid-source");
    container.setAttribute("aria-busy", "true");

    const status = mermaidStatus("正在安全绘制 Mermaid 图…");
    const diagram = document.createElement("div");
    diagram.className = "forum-mermaid-diagram mermaid";
    diagram.textContent = source;

    const sourceDetails = document.createElement("details");
    const sourceSummary = document.createElement("summary");
    sourceSummary.textContent = "查看 Mermaid 源码";
    sourceDetails.append(sourceSummary, sourcePre);
    container.replaceChildren(status, diagram, sourceDetails);

    try {
      if (!mermaidRenderer) throw new Error("renderer-unavailable");
      if (source.length > MERMAID_MAX_TEXT_SIZE) throw new Error("source-too-large");
      const parsed = await mermaidRenderer.parse(source, { suppressErrors: true });
      if (!parsed) throw new Error("invalid-diagram");
      if (
        !container.isConnected
        || container.dataset.mermaidGeneration !== generation
      ) return;

      await mermaidRenderer.run({ nodes: [diagram] });
      if (
        !container.isConnected
        || container.dataset.mermaidGeneration !== generation
      ) return;

      status.remove();
      container.dataset.mermaidState = "rendered";
    } catch (_error) {
      if (
        !container.isConnected
        || container.dataset.mermaidGeneration !== generation
      ) return;
      diagram.remove();
      status.textContent = "Mermaid 语法无效或图表过于复杂，已保留源码。";
      sourceDetails.open = true;
      container.dataset.mermaidState = "error";
      container.classList.add("is-error");
    } finally {
      if (container.dataset.mermaidGeneration === generation) {
        container.removeAttribute("aria-busy");
      }
    }
  }

  async function renderMermaidDiagrams(root) {
    const blocks = Array.from(
      root.querySelectorAll(
        ".codehilite.language-mermaid, .codehilite.language-mmd",
      ),
    ).filter((block) => !block.dataset.mermaidState);

    const renderable = blocks.slice(0, MERMAID_MAX_DIAGRAMS_PER_ROOT);
    blocks.slice(MERMAID_MAX_DIAGRAMS_PER_ROOT).forEach((block) => {
      markMermaidSourceError(block, "本次页面中的图表数量过多，已保留源码。");
    });
    for (const block of renderable) {
      await renderMermaidBlock(block);
    }
  }

  async function enhance(root) {
    enhanceRenderedLinks(root);
    await renderMermaidDiagrams(root);
    if (root.isConnected) await typesetMath(root);
  }

  window.NumericalOJForumMarkdown = Object.freeze({ enhance });
}());
