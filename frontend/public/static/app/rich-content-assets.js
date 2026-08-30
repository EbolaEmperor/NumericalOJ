(function (global) {
  "use strict";

  if (global.NumOJRichContentAssets) return;

  const loaderScript = document.currentScript;
  const assetUrls = {
    highlighter: loaderScript?.dataset.highlighterSrc || "",
    mathjax: loaderScript?.dataset.mathjaxSrc || "",
    mermaid: loaderScript?.dataset.mermaidSrc || "",
    semanticTokens: loaderScript?.dataset.semanticTokensSrc || "",
  };
  const assetPromises = Object.create(null);
  const STRUCTURED_CODE_SELECTOR = [
    ".codehilite.language-bash",
    ".codehilite.language-sh",
    ".codehilite.language-shell",
    ".codehilite.language-shellscript",
    ".codehilite.language-zsh",
    ".codehilite.language-ksh",
    ".codehilite.language-openrc",
    ".codehilite.language-c",
    ".codehilite.language-cpp",
    ".codehilite.language-c\\+\\+",
    ".codehilite.language-cc",
    ".codehilite.language-cxx",
    ".codehilite.language-py",
    ".codehilite.language-py3",
    ".codehilite.language-python",
    ".codehilite.language-python3",
    ".codehilite.language-m",
    ".codehilite.language-matlab",
    ".codehilite.language-octave",
    ".codehilite.language-lean",
    ".codehilite.language-lean4",
  ].join(",");
  const MERMAID_SELECTOR = (
    ".codehilite.language-mermaid, .codehilite.language-mmd"
  );
  const MATH_DELIMITER_PATTERN = (
    /\\\([\s\S]+?\\\)|\\\[[\s\S]+?\\\]|\$\$[\s\S]+?\$\$|(?:^|[^$])\$[^$\n]+\$(?!\$)/m
  );

  function assetReady(name) {
    if (name === "mathjax") {
      return Boolean(global.MathJax && global.MathJax.typesetPromise);
    }
    if (name === "mermaid") {
      return Boolean(global.mermaid && global.mermaid.initialize);
    }
    if (name === "highlighter") {
      return Boolean(global.NumOJMarkdownCodeHighlighter);
    }
    if (name === "semanticTokens") {
      return Boolean(global.NumOJSemanticTokens);
    }
    return false;
  }

  function loadAsset(name) {
    if (assetReady(name)) return Promise.resolve(true);
    if (assetPromises[name]) return assetPromises[name];
    const url = assetUrls[name];
    if (!url) return Promise.resolve(false);

    assetPromises[name] = new Promise((resolve) => {
      const script = document.createElement("script");
      script.src = url;
      script.async = true;
      script.dataset.numojRichAsset = name;
      script.addEventListener("load", () => resolve(assetReady(name)), { once: true });
      script.addEventListener("error", () => resolve(false), { once: true });
      document.head.appendChild(script);
    });
    return assetPromises[name];
  }

  function rootMatches(root, selector) {
    if (!root) return false;
    if (root.matches && root.matches(selector)) return true;
    return Boolean(root.querySelector && root.querySelector(selector));
  }

  function needsStructuredCode(root) {
    return rootMatches(root, STRUCTURED_CODE_SELECTOR);
  }

  function needsMermaid(root) {
    return rootMatches(root, MERMAID_SELECTOR);
  }

  function needsMath(root) {
    if (!root) return false;
    const scanRoot = root.nodeType === Node.TEXT_NODE ? root.parentElement : root;
    if (!scanRoot) return false;
    const walker = document.createTreeWalker(scanRoot, NodeFilter.SHOW_TEXT);
    let node = walker.nextNode();
    while (node) {
      const parent = node.parentElement;
      if (
        parent
        && !parent.closest("pre, code, script, style, textarea, [data-no-mathjax]")
        && MATH_DELIMITER_PATTERN.test(node.data || "")
      ) {
        return true;
      }
      node = walker.nextNode();
    }
    return false;
  }

  function ensureCodeAssets(root) {
    if (!needsStructuredCode(root)) return Promise.resolve(false);
    return Promise.all([
      loadAsset("highlighter"),
      loadAsset("semanticTokens"),
    ]).then((results) => results.some(Boolean));
  }

  function ensureMermaid(root) {
    return needsMermaid(root) ? loadAsset("mermaid") : Promise.resolve(false);
  }

  function ensureMathJax(root) {
    return needsMath(root) ? loadAsset("mathjax") : Promise.resolve(false);
  }

  global.NumOJRichContentAssets = Object.freeze({
    ensureCodeAssets,
    ensureMathJax,
    ensureMermaid,
    needsMath,
    needsMermaid,
    needsStructuredCode,
  });
}(window));
