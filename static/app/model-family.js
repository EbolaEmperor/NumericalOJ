(function (global) {
  "use strict";

  const BASE_CLASS = "model-family-logo";
  const CLASS_PREFIX = `${BASE_CLASS}--`;
  const MARKER_SELECTOR = "[data-model-family-logo]";

  // Rules are deliberately ordered. A distilled model can mention several
  // families (for example DeepSeek-R1-Distill-Qwen), and the model's primary
  // family should win over the architecture it was distilled into.
  const RULES = Object.freeze([
    { key: "deepseek", includes: ["deepseek"] },
    {
      key: "openai",
      includes: ["openai", "chatgpt", "codex"],
      patterns: [
        /(?:^|[^a-z0-9])gpt(?:[-_.]?\d|[^a-z0-9]|$)/,
        /(?:^|[^a-z0-9])o(?:1|3|4)(?:[^a-z0-9]|$)/,
      ],
    },
    {
      key: "claude",
      includes: ["claude", "anthropic", "opus", "sonnet", "haiku"],
    },
    { key: "gemini", includes: ["gemini"] },
    {
      key: "grok",
      includes: ["grok", "x-ai", "x.ai"],
      patterns: [/(?:^|[^a-z0-9])xai(?:[^a-z0-9]|$)/],
    },
    { key: "qwen", includes: ["qwen", "tongyi", "qwq", "qvq"] },
    {
      key: "doubao",
      includes: ["doubao", "seed", "bytedance", "volcengine"],
    },
    { key: "minimax", includes: ["minimax", "abab"] },
    {
      key: "glm",
      includes: ["chatglm", "glm", "zhipu", "z-ai", "z.ai"],
      patterns: [/(?:^|[^a-z0-9])zai(?:[^a-z0-9]|$)/],
    },
    { key: "kimi", includes: ["kimi", "moonshot"] },
    { key: "gemma", includes: ["gemma"] },
    { key: "nvidia", includes: ["nvidia", "nemotron"] },
    {
      key: "llama",
      patterns: [
        /(?:^|[^a-z0-9])llama(?:[^a-z0-9]|$)/,
        /(?:^|[^a-z0-9])meta(?:[^a-z0-9]|$)/,
      ],
    },
    {
      key: "mistral",
      includes: [
        "mistral",
        "mixtral",
        "codestral",
        "ministral",
        "pixtral",
        "magistral",
        "devstral",
      ],
    },
    {
      key: "cohere",
      includes: ["cohere"],
      patterns: [
        /(?:^|[^a-z0-9])command(?:[^a-z0-9]|$)/,
        /(?:^|[^a-z0-9])aya(?:[^a-z0-9]|$)/,
      ],
    },
    {
      key: "microsoft",
      includes: ["microsoft"],
      patterns: [/(?:^|[^a-z0-9])phi(?:[-_.]?\d|[^a-z0-9]|$)/],
    },
    {
      key: "amazon",
      includes: ["amazon", "bedrock"],
      patterns: [
        /(?:^|[^a-z0-9])aws(?:[^a-z0-9]|$)/,
        /(?:^|[^a-z0-9])nova(?:[^a-z0-9]|$)/,
        /(?:^|[^a-z0-9])titan(?:[^a-z0-9]|$)/,
      ],
    },
    { key: "baidu", includes: ["baidu", "ernie", "wenxin"] },
    { key: "hunyuan", includes: ["hunyuan", "tencent"] },
    { key: "baichuan", includes: ["baichuan"] },
    {
      key: "yi",
      includes: ["zeroone", "01-ai", "01.ai"],
      patterns: [/(?:^|[^a-z0-9])yi(?:[^a-z0-9]|$)/],
    },
    { key: "ai21", includes: ["ai21", "jamba"] },
    { key: "perplexity", includes: ["perplexity", "sonar"] },
    {
      key: "stepfun",
      includes: ["stepfun"],
      patterns: [/(?:^|[^a-z0-9])step[-_.]?\d/],
    },
    { key: "internlm", includes: ["internlm"] },
    {
      key: "baai",
      includes: ["baai"],
      patterns: [/(?:^|[^a-z0-9])bge(?:[-_.]?\d|[^a-z0-9]|$)/],
    },
    { key: "jina", includes: ["jina"] },
    { key: "voyage", includes: ["voyage"] },
    { key: "tii", includes: ["tii", "falcon"] },
  ]);

  function detect(name) {
    const normalized = String(name == null ? "" : name).trim().toLowerCase();
    if (!normalized) {
      return null;
    }

    for (const rule of RULES) {
      if (
        (rule.includes || []).some((keyword) => normalized.includes(keyword)) ||
        (rule.patterns || []).some((pattern) => pattern.test(normalized))
      ) {
        return rule.key;
      }
    }
    return null;
  }

  function iconClass(name) {
    const family = detect(name);
    return family ? `${BASE_CLASS} ${CLASS_PREFIX}${family}` : "fas fa-microchip";
  }

  function modelNameForElement(element, explicitName) {
    if (explicitName !== undefined) {
      return explicitName;
    }
    return (
      element.getAttribute("data-model-name") ||
      element.getAttribute("data-model-family-logo") ||
      ""
    );
  }

  function clearFamilyClasses(element) {
    for (const className of Array.from(element.classList)) {
      if (className === BASE_CLASS || className.startsWith(CLASS_PREFIX)) {
        element.classList.remove(className);
      }
    }
  }

  function paint(element, name) {
    if (!element || !element.classList) {
      return null;
    }

    const family = detect(modelNameForElement(element, name));
    clearFamilyClasses(element);

    if (!family) {
      element.classList.add("fas", "fa-microchip");
      element.removeAttribute("data-model-family");
      return null;
    }

    element.classList.remove("fas", "fa-microchip");
    element.classList.add(BASE_CLASS, `${CLASS_PREFIX}${family}`);
    element.setAttribute("data-model-family", family);
    return family;
  }

  function paintAll(scope) {
    const root = scope || global.document;
    if (!root) {
      return 0;
    }

    const elements = [];
    if (typeof root.matches === "function" && root.matches(MARKER_SELECTOR)) {
      elements.push(root);
    }
    if (typeof root.querySelectorAll === "function") {
      elements.push(...root.querySelectorAll(MARKER_SELECTOR));
    }

    for (const element of elements) {
      paint(element);
    }
    return elements.length;
  }

  const api = Object.freeze({ detect, iconClass, paint, paintAll });
  global.NumojModelFamily = api;

  function startAutomaticPainting() {
    paintAll(global.document);
    if (!global.MutationObserver || !global.document.documentElement) {
      return;
    }

    const observer = new global.MutationObserver((records) => {
      for (const record of records) {
        if (record.type === "attributes") {
          if (
            typeof record.target.matches === "function" &&
            record.target.matches(MARKER_SELECTOR)
          ) {
            paint(record.target);
          }
          continue;
        }
        for (const node of record.addedNodes) {
          if (node.nodeType === 1) {
            paintAll(node);
          }
        }
      }
    });
    observer.observe(global.document.documentElement, {
      attributes: true,
      attributeFilter: ["data-model-family-logo", "data-model-name"],
      childList: true,
      subtree: true,
    });
  }

  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", startAutomaticPainting, {
        once: true,
      });
    } else {
      startAutomaticPainting();
    }
  }
})(typeof window === "undefined" ? globalThis : window);
