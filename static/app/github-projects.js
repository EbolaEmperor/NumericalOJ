(() => {
  "use strict";

  const projects = [
    "openai/codex",
    "badlogic/pi-mono",
    "anomalyco/opencode",
    "deepseek-ai/deepseek-harness",
    "OpenHands/OpenHands",
    "Aider-AI/aider",
    "aaif-goose/goose",
    "SWE-agent/mini-swe-agent",
    "NousResearch/hermes-agent",
    "QwenLM/qwen-code",
    "cline/cline",
    "RooCodeInc/Roo-Code",
    "continuedev/continue",
    "SWE-agent/SWE-agent",
    "huggingface/smolagents",
    "NVIDIA/Megatron-LM",
    "deepspeedai/DeepSpeed",
    "huggingface/trl",
    "verl-project/verl",
    "axolotl-ai-cloud/axolotl",
    "unslothai/unsloth",
    "hiyouga/LlamaFactory",
    "modelscope/ms-swift",
    "OpenRLHF/OpenRLHF",
    "NVIDIA-NeMo/RL",
    "THUDM/slime",
    "areal-project/AReaL",
    "agentica-project/rllm",
    "allenai/open-instruct",
    "huggingface/open-r1",
    "Lightning-AI/litgpt",
    "vllm-project/vllm",
    "sgl-project/sglang",
    "ggml-org/llama.cpp",
    "NVIDIA/TensorRT-LLM",
    "InternLM/lmdeploy",
    "mlc-ai/mlc-llm",
    "llm-d/llm-d",
    "kvcache-ai/Mooncake",
    "flashinfer-ai/flashinfer",
    "LMCache/LMCache",
    "deepseek-ai/FlashMLA",
    "deepseek-ai/DeepGEMM",
    "jingyaogong/minimind",
    "karpathy/nanoGPT",
    "rasbt/LLMs-from-scratch",
    "karpathy/nn-zero-to-hero",
    "karpathy/micrograd",
    "karpathy/makemore",
    "karpathy/nanochat",
    "karpathy/llama2.c",
    "karpathy/llm.c",
    "microsoft/AI-For-Beginners",
    "microsoft/ML-For-Beginners",
    "microsoft/generative-ai-for-beginners",
    "microsoft/ai-agents-for-beginners",
    "huggingface/agents-course",
    "huggingface/course",
    "DatawhaleChina/happy-llm",
    "DatawhaleChina/llm-universe",
    "DatawhaleChina/self-llm",
    "d2l-ai/d2l-zh",
    "labmlai/annotated_deep_learning_paper_implementations",
    "leanprover/lean4",
    "leanprover-community/mathlib4",
    "leanprover-community/mathematics_in_lean",
    "leanprover-community/aesop",
    "lean-dojo/LeanDojo-v2",
    "lean-dojo/LeanCopilot",
    "deepseek-ai/DeepSeek-Prover-V2",
    "project-numina/numina-lean-agent",
    "project-numina/kimina-lean-server",
    "krahets/hello-algo",
    "algorithm-visualizer/algorithm-visualizer",
    "OpenDSA/OpenDSA",
  ];

  function renderProjects(selectedProjects) {
    document.querySelectorAll("[data-numoj-projects]").forEach((list) => {
      list.replaceChildren();
      selectedProjects.forEach((repository) => {
        const item = document.createElement("li");
        const link = document.createElement("a");
        const copy = document.createElement("span");
        const arrow = document.createElement("b");

        link.href = `https://github.com/${repository}`;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        copy.textContent = repository;
        arrow.textContent = "↗";

        link.append(copy, arrow);
        item.appendChild(link);
        list.appendChild(item);
      });
    });
  }

  function selectRandomProjects(count) {
    const shuffled = [...projects];
    for (let index = shuffled.length - 1; index > 0; index -= 1) {
      const target = Math.floor(Math.random() * (index + 1));
      [shuffled[index], shuffled[target]] = [shuffled[target], shuffled[index]];
    }
    return shuffled.slice(0, count);
  }

  function refreshProjects() {
    renderProjects(selectRandomProjects(3));
  }

  refreshProjects();
  document.querySelectorAll("[data-numoj-projects-refresh]").forEach((button) => {
    button.addEventListener("click", refreshProjects);
  });
})();
