const BASE_CLASS = 'model-family-logo'
const CLASS_PREFIX = `${BASE_CLASS}--`

type Rule = {key: string; includes?: string[]; patterns?: RegExp[]}

const RULES: readonly Rule[] = [
  {key: 'deepseek', includes: ['deepseek']},
  {key: 'openai', includes: ['openai', 'chatgpt', 'codex'], patterns: [/(?:^|[^a-z0-9])gpt(?:[-_.]?\d|[^a-z0-9]|$)/, /(?:^|[^a-z0-9])o(?:1|3|4)(?:[^a-z0-9]|$)/]},
  {key: 'claude', includes: ['claude', 'anthropic', 'opus', 'sonnet', 'haiku']},
  {key: 'gemini', includes: ['gemini']},
  {key: 'grok', includes: ['grok', 'x-ai', 'x.ai'], patterns: [/(?:^|[^a-z0-9])xai(?:[^a-z0-9]|$)/]},
  {key: 'qwen', includes: ['qwen', 'tongyi', 'qwq', 'qvq']},
  {key: 'doubao', includes: ['doubao', 'seed', 'bytedance', 'volcengine']},
  {key: 'minimax', includes: ['minimax', 'abab']},
  {key: 'glm', includes: ['chatglm', 'glm', 'zhipu', 'z-ai', 'z.ai'], patterns: [/(?:^|[^a-z0-9])zai(?:[^a-z0-9]|$)/]},
  {key: 'kimi', includes: ['kimi', 'moonshot']},
  {key: 'gemma', includes: ['gemma']},
  {key: 'nvidia', includes: ['nvidia', 'nemotron']},
  {key: 'llama', patterns: [/(?:^|[^a-z0-9])llama(?:[^a-z0-9]|$)/, /(?:^|[^a-z0-9])meta(?:[^a-z0-9]|$)/]},
  {key: 'mistral', includes: ['mistral', 'mixtral', 'codestral', 'ministral', 'pixtral', 'magistral', 'devstral']},
  {key: 'cohere', includes: ['cohere'], patterns: [/(?:^|[^a-z0-9])command(?:[^a-z0-9]|$)/, /(?:^|[^a-z0-9])aya(?:[^a-z0-9]|$)/]},
  {key: 'microsoft', includes: ['microsoft'], patterns: [/(?:^|[^a-z0-9])phi(?:[-_.]?\d|[^a-z0-9]|$)/]},
  {key: 'amazon', includes: ['amazon', 'bedrock'], patterns: [/(?:^|[^a-z0-9])aws(?:[^a-z0-9]|$)/, /(?:^|[^a-z0-9])nova(?:[^a-z0-9]|$)/, /(?:^|[^a-z0-9])titan(?:[^a-z0-9]|$)/]},
  {key: 'baidu', includes: ['baidu', 'ernie', 'wenxin']},
  {key: 'hunyuan', includes: ['hunyuan', 'tencent']},
  {key: 'baichuan', includes: ['baichuan']},
  {key: 'yi', includes: ['zeroone', '01-ai', '01.ai'], patterns: [/(?:^|[^a-z0-9])yi(?:[^a-z0-9]|$)/]},
  {key: 'ai21', includes: ['ai21', 'jamba']},
  {key: 'perplexity', includes: ['perplexity', 'sonar']},
  {key: 'stepfun', includes: ['stepfun'], patterns: [/(?:^|[^a-z0-9])step[-_.]?\d/]},
  {key: 'internlm', includes: ['internlm']},
  {key: 'baai', includes: ['baai'], patterns: [/(?:^|[^a-z0-9])bge(?:[-_.]?\d|[^a-z0-9]|$)/]},
  {key: 'jina', includes: ['jina']},
  {key: 'voyage', includes: ['voyage']},
  {key: 'tii', includes: ['tii', 'falcon']},
]

export function detectModelFamily(name: unknown) {
  const normalized = String(name ?? '').trim().toLowerCase()
  if (!normalized) return null
  return RULES.find((rule) => rule.includes?.some((keyword) => normalized.includes(keyword)) || rule.patterns?.some((pattern) => pattern.test(normalized)))?.key || null
}

export function modelFamilyIconClass(name: unknown) {
  const family = detectModelFamily(name)
  return family ? `${BASE_CLASS} ${CLASS_PREFIX}${family}` : 'fas fa-microchip'
}
