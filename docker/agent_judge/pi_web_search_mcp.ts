/**
 * Pi 没有原生 MCP 配置入口。这个镜像内受信任扩展把站点 Web Search MCP
 * 暴露为单一 web_search 工具；URL 与凭证只从任务进程环境读取。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PROTOCOL_VERSION = "2024-11-05";
const PREFERRED_TOOL_NAME = "bailian_web_search";

type JsonObject = Record<string, unknown>;

function requiredEnv(name: string): string {
	const value = (process.env[name] || "").trim();
	if (!value) throw new Error(`${name} is required`);
	return value;
}

function timeoutMs(): number {
	const raw = Number.parseInt(process.env.AJ_WEB_SEARCH_MCP_TIMEOUT_SECONDS || "90", 10);
	const seconds = Number.isFinite(raw) ? Math.max(10, Math.min(240, raw)) : 90;
	return seconds * 1000;
}

function decodeResponseBody(contentType: string, body: string): JsonObject {
	const trimmed = body.trim();
	if (!trimmed) return {};
	if (contentType.toLowerCase().includes("text/event-stream")) {
		for (const line of trimmed.split(/\r?\n/)) {
			if (!line.startsWith("data:")) continue;
			const data = line.slice(5).trim();
			if (!data || data === "[DONE]") continue;
			const parsed = JSON.parse(data);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				return parsed as JsonObject;
			}
		}
		throw new Error("Web Search MCP returned an empty event stream");
	}
	const parsed = JSON.parse(trimmed);
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("Web Search MCP returned an invalid JSON-RPC response");
	}
	return parsed as JsonObject;
}

async function postJsonRpc(
	payload: JsonObject,
	sessionId: string,
	signal?: AbortSignal,
): Promise<{ message: JsonObject; sessionId: string }> {
	const timeoutController = new AbortController();
	const timer = setTimeout(() => timeoutController.abort(), timeoutMs());
	const combinedSignal = signal
		? AbortSignal.any([signal, timeoutController.signal])
		: timeoutController.signal;
	try {
		const headers: Record<string, string> = {
			Authorization: requiredEnv("AJ_WEB_SEARCH_MCP_AUTHORIZATION"),
			"Content-Type": "application/json",
			Accept: "application/json, text/event-stream",
			"MCP-Protocol-Version": PROTOCOL_VERSION,
		};
		if (sessionId) {
			headers["Mcp-Session-Id"] = sessionId;
		}
		const response = await fetch(requiredEnv("AJ_WEB_SEARCH_MCP_URL"), {
			method: "POST",
			headers,
			body: JSON.stringify(payload),
			signal: combinedSignal,
			redirect: "error",
		});
		const body = await response.text();
		if (!response.ok) {
			throw new Error(`Web Search MCP HTTP ${response.status}: ${body.slice(0, 400)}`);
		}
		const message = decodeResponseBody(response.headers.get("content-type") || "", body);
		if (message.error) {
			throw new Error(`Web Search MCP JSON-RPC error: ${JSON.stringify(message.error)}`);
		}
		return {
			message,
			sessionId: response.headers.get("mcp-session-id") || sessionId,
		};
	} finally {
		clearTimeout(timer);
	}
}

function resultObject(message: JsonObject): JsonObject {
	const result = message.result;
	return result && typeof result === "object" && !Array.isArray(result)
		? result as JsonObject
		: {};
}

async function search(query: string, count: number, signal?: AbortSignal) {
	let sessionId = "";
	let response = await postJsonRpc({
		jsonrpc: "2.0",
		id: 1,
		method: "initialize",
		params: {
			protocolVersion: PROTOCOL_VERSION,
			capabilities: {},
			clientInfo: { name: "numericaloj-pi", version: "1.0.0" },
		},
	}, sessionId, signal);
	sessionId = response.sessionId;
	if (!response.message.result) throw new Error("Web Search MCP initialize failed");

	response = await postJsonRpc({
		jsonrpc: "2.0",
		method: "notifications/initialized",
		params: {},
	}, sessionId, signal);
	sessionId = response.sessionId;

	response = await postJsonRpc({
		jsonrpc: "2.0",
		id: 2,
		method: "tools/list",
		params: {},
	}, sessionId, signal);
	sessionId = response.sessionId;
	const tools = resultObject(response.message).tools;
	const names = Array.isArray(tools)
		? tools.map((tool) => (
			tool && typeof tool === "object" ? String((tool as JsonObject).name || "") : ""
		)).filter(Boolean)
		: [];
	const toolName = names.includes(PREFERRED_TOOL_NAME)
		? PREFERRED_TOOL_NAME
		: names.find((name) => name.toLowerCase().includes("search")) || names[0];
	if (!toolName) throw new Error("Web Search MCP did not expose a search tool");

	response = await postJsonRpc({
		jsonrpc: "2.0",
		id: 3,
		method: "tools/call",
		params: { name: toolName, arguments: { query, count } },
	}, sessionId, signal);
	const result = resultObject(response.message);
	const content = Array.isArray(result.content) ? result.content : [];
	const text = content.map((item) => {
		if (item && typeof item === "object" && (item as JsonObject).type === "text") {
			return String((item as JsonObject).text || "");
		}
		return JSON.stringify(item);
	}).filter(Boolean).join("\n");
	return {
		text: text || JSON.stringify(result),
		details: { toolName, isError: Boolean(result.isError) },
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "web_search",
		label: "Web Search",
		description: "Search the web through the site-configured Web Search MCP server.",
		parameters: Type.Object({
			query: Type.String({ description: "Search query" }),
			count: Type.Optional(Type.Integer({ minimum: 1, maximum: 50, description: "Maximum result count" })),
		}),
		async execute(_toolCallId, params, signal) {
			const query = params.query.trim();
			if (!query) throw new Error("query cannot be empty");
			const count = Math.max(1, Math.min(50, params.count || 5));
			const result = await search(query, count, signal);
			return {
				content: [{ type: "text", text: result.text }],
				details: result.details,
			};
		},
	});
}
