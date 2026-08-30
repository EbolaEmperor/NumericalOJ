(function () {
  "use strict";

  const app = document.getElementById("forumApp");
  if (!app) return;

  const identicon = window.NumojIdenticon;
  if (!identicon) throw new Error("Identicon renderer is unavailable");
  const avatarCellsForName = identicon.cellsForSeed;
  const paintAvatar = identicon.paint;

  const API_ROOT = "/api/forum";
  const THREAD_PAGE_SIZE = 30;
  const REPLY_PAGE_SIZE = 50;
  const RETRY_DELAYS_MS = [350, 900, 1800];
  const MOBILE_BREAKPOINT = 940;

  class ApiError extends Error {
    constructor(message, status, payload) {
      super(message || "请求失败");
      this.name = "ApiError";
      this.status = Number(status || 0);
      this.payload = payload || {};
    }
  }

  const elements = {
    identityControl: document.getElementById("identityControl"),
    currentIdentityAvatar: document.getElementById("currentIdentityAvatar"),
    currentIdentityName: document.getElementById("currentIdentityName"),
    anonymousToggle: document.getElementById("anonymousToggle"),
    refreshIdentityButton: document.getElementById("refreshIdentityButton"),
    openComposeButton: document.getElementById("openComposeButton"),
    searchInput: document.getElementById("threadSearchInput"),
    filterStrip: document.querySelector(".forum-filter-strip"),
    threadList: document.getElementById("threadList"),
    loadMoreThreadsButton: document.getElementById("loadMoreThreadsButton"),
    detailKicker: document.getElementById("detailKicker"),
    detailTitle: document.getElementById("detailTitle"),
    editThreadButton: document.getElementById("editThreadButton"),
    copyThreadLinkButton: document.getElementById("copyThreadLinkButton"),
    mobileBackButton: document.getElementById("mobileBackButton"),
    detailPane: document.getElementById("detailPane"),
    conversation: document.getElementById("conversation"),
    replyForm: document.getElementById("replyForm"),
    replyInput: document.getElementById("replyInput"),
    replyError: document.getElementById("replyError"),
    submitReplyButton: document.getElementById("submitReplyButton"),
    editorDialog: document.getElementById("editorDialog"),
    editorForm: document.getElementById("editorForm"),
    editorEyebrow: document.getElementById("editorEyebrow"),
    editorDialogTitle: document.getElementById("editorDialogTitle"),
    editorIdentityRow: document.getElementById("editorIdentityRow"),
    editorIdentityHint: document.getElementById("editorIdentityHint"),
    editorTitleField: document.getElementById("editorTitleField"),
    editorTitleInput: document.getElementById("editorTitleInput"),
    editorContentInput: document.getElementById("editorContentInput"),
    editorWritePanel: document.getElementById("editorWritePanel"),
    editorPreviewPanel: document.getElementById("editorPreviewPanel"),
    editorError: document.getElementById("editorError"),
    editorDraftStatus: document.getElementById("editorDraftStatus"),
    rebaseEditorDraftButton: document.getElementById("rebaseEditorDraftButton"),
    submitEditorButton: document.getElementById("submitEditorButton"),
    closeEditorButton: document.getElementById("closeEditorButton"),
    cancelEditorButton: document.getElementById("cancelEditorButton"),
    editorTabs: document.querySelector(".forum-editor-tabs"),
    identityDialog: document.getElementById("identityDialog"),
    identityForm: document.getElementById("identityForm"),
    identityDialogTitle: document.getElementById("identityDialogTitle"),
    aliasInput: document.getElementById("aliasInput"),
    aliasCount: document.getElementById("aliasCount"),
    aliasError: document.getElementById("aliasError"),
    aliasPreviewAvatar: document.getElementById("aliasPreviewAvatar"),
    aliasPreviewName: document.getElementById("aliasPreviewName"),
    identityCooldownNote: document.getElementById("identityCooldownNote"),
    saveIdentityButton: document.getElementById("saveIdentityButton"),
    closeIdentityButton: document.getElementById("closeIdentityButton"),
    cancelIdentityButton: document.getElementById("cancelIdentityButton"),
    toast: document.getElementById("forumToast"),
    toastEyebrow: document.getElementById("forumToastEyebrow"),
    toastMessage: document.getElementById("forumToastMessage"),
  };

  const state = {
    identity: null,
    storageNamespace: null,
    storageAvailable: false,
    threads: [],
    page: 1,
    totalPages: 0,
    scope: "all",
    query: "",
    selectedId: null,
    thread: null,
    replies: [],
    hasEarlierReplies: false,
    beforeReplyId: null,
    editorMode: "new",
    editorTarget: null,
    editorDraftIsStale: false,
    identityMode: "first",
    listRequestSequence: 0,
    detailRequestSequence: 0,
    previewRequestSequence: 0,
    conversationRenderSequence: 0,
    toastTimer: null,
    searchTimer: null,
    identityRefreshTimer: null,
    replyComposerFrame: null,
    replyComposerObserver: null,
  };

  function sleep(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  function isRetriable(error) {
    if (!(error instanceof ApiError)) return true;
    return error.status === 0 || error.status >= 500;
  }

  async function requestJson(path, options) {
    const config = Object.assign(
      { method: "GET", body: undefined, retries: 0 },
      options || {},
    );
    let lastError = null;

    for (let attempt = 0; attempt <= config.retries; attempt += 1) {
      try {
        const fetchOptions = {
          method: config.method,
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "X-Requested-With": "XMLHttpRequest",
          },
        };
        if (config.signal) fetchOptions.signal = config.signal;
        if (config.body !== undefined) {
          fetchOptions.headers["Content-Type"] = "application/json";
          fetchOptions.body = JSON.stringify(config.body);
        }

        const response = await fetch(path, fetchOptions);
        let payload = {};
        try {
          payload = await response.json();
        } catch (_error) {
          payload = {};
        }

        if (response.status === 401) {
          const next = `${window.location.pathname}${window.location.search}${window.location.hash}`;
          window.location.assign(`/login?next=${encodeURIComponent(next)}`);
          throw new ApiError("登录状态已失效", 401, payload);
        }
        if (!response.ok || payload.success === false) {
          throw new ApiError(payload.message || `请求失败（${response.status}）`, response.status, payload);
        }
        return payload;
      } catch (error) {
        if (error && error.name === "AbortError") throw error;
        lastError = error instanceof ApiError
          ? error
          : new ApiError("网络连接失败，草稿已保留", 0, {});
        if (attempt >= config.retries || !isRetriable(lastError)) throw lastError;
        await sleep(RETRY_DELAYS_MS[Math.min(attempt, RETRY_DELAYS_MS.length - 1)]);
      }
    }
    throw lastError || new ApiError("请求失败", 0, {});
  }

  function setLoading(button, loading, loadingLabel) {
    if (!button) return;
    if (loading) {
      if (!button.classList.contains("is-loading")) {
        button.dataset.originalHtml = button.innerHTML;
      }
      button.disabled = true;
      button.classList.add("is-loading");
      if (loadingLabel) {
        button.innerHTML = `<i class="fas fa-rotate" aria-hidden="true"></i>${escapeHtml(loadingLabel)}`;
      }
    } else {
      if (button.dataset.originalHtml) button.innerHTML = button.dataset.originalHtml;
      delete button.dataset.originalHtml;
      button.disabled = false;
      button.classList.remove("is-loading");
    }
  }

  function showToast(message, kind) {
    if (!elements.toast) return;
    window.clearTimeout(state.toastTimer);
    const isError = kind === "error";
    const isShare = kind === "share";
    if (elements.toastMessage) {
      elements.toastMessage.textContent = String(message || "");
    }
    if (elements.toastEyebrow) {
      elements.toastEyebrow.textContent = isError
        ? "FORUM · ERROR"
        : (isShare ? "SHARE · READY" : "FORUM · NOTICE");
    }
    elements.toast.setAttribute("role", isError ? "alert" : "status");
    elements.toast.classList.toggle("is-error", isError);
    elements.toast.classList.toggle("is-share", isShare);
    elements.toast.classList.add("is-visible");
    state.toastTimer = window.setTimeout(() => {
      elements.toast.classList.remove("is-visible");
    }, isError ? 5200 : (isShare ? 4200 : 3000));
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function normalizeIdentity(payload) {
    const source = (payload && payload.identity) || payload || {};
    const realName = source.real_name || source.username || "";
    const anonymousName = source.anonymous_name || source.anonymous_display_name || null;
    const useAnonymous = Boolean(source.use_anonymous && anonymousName);
    return {
      real_name: realName,
      real_avatar: source.real_avatar || avatarCellsForName(realName),
      anonymous_name: anonymousName,
      anonymous_avatar: source.anonymous_avatar || (anonymousName ? avatarCellsForName(anonymousName) : { cells: [] }),
      use_anonymous: useAnonymous,
      posting_name: source.posting_name || (useAnonymous ? anonymousName : realName),
      posting_avatar: source.posting_avatar || (useAnonymous
        ? (source.anonymous_avatar || avatarCellsForName(anonymousName))
        : (source.real_avatar || avatarCellsForName(realName))),
      posting_token: String(source.posting_token || ""),
      draft_namespace: String(source.draft_namespace || ""),
      can_change_at: source.can_change_at || null,
      cooldown_remaining_seconds: Math.max(0, Number(source.cooldown_remaining_seconds || 0)),
    };
  }

  function postingName() {
    return state.identity ? state.identity.posting_name : "";
  }

  function postingAvatar() {
    return state.identity ? state.identity.posting_avatar : { cells: [] };
  }

  function updatePostingIdentityElements() {
    const name = postingName();
    document.querySelectorAll("[data-posting-name]").forEach((element) => {
      if (element.closest(".has-pending-attempt")) return;
      element.textContent = name || "当前身份";
    });
    document.querySelectorAll("[data-posting-avatar]").forEach((element) => {
      if (element.closest(".has-pending-attempt")) return;
      paintAvatar(element, postingAvatar(), name);
    });
  }

  function applyIdentity(payload) {
    state.identity = normalizeIdentity(payload);
    state.storageNamespace = state.identity.draft_namespace
      ? `numoj.forum.v2.${encodeURIComponent(state.identity.draft_namespace)}`
      : null;
    if (!state.storageNamespace) state.storageAvailable = false;

    elements.currentIdentityName.textContent = state.identity.posting_name || "当前用户";
    paintAvatar(
      elements.currentIdentityAvatar,
      state.identity.posting_avatar,
      state.identity.posting_name,
    );
    elements.anonymousToggle.checked = state.identity.use_anonymous;
    elements.anonymousToggle.disabled = false;
    elements.openComposeButton.disabled = false;
    elements.identityControl.setAttribute("aria-busy", "false");

    const canRefresh = Boolean(state.identity.anonymous_name)
      && state.identity.cooldown_remaining_seconds <= 0;
    elements.refreshIdentityButton.disabled = !canRefresh;
    if (state.identity.cooldown_remaining_seconds > 0) {
      elements.refreshIdentityButton.title = formatCooldown(state.identity.cooldown_remaining_seconds);
    } else {
      elements.refreshIdentityButton.title = state.identity.anonymous_name
        ? "更换匿名身份"
        : "首次打开匿名开关后设置身份";
    }
    window.clearTimeout(state.identityRefreshTimer);
    state.identityRefreshTimer = null;
    if (
      state.identity.anonymous_name
      && state.identity.cooldown_remaining_seconds > 0
    ) {
      state.identityRefreshTimer = window.setTimeout(() => {
        loadIdentity().catch(() => {
          // loadIdentity 已向用户报告错误；下次身份操作仍会由服务端校验时间。
        });
      }, state.identity.cooldown_remaining_seconds * 1000 + 250);
    }
    updatePostingIdentityElements();
  }

  async function loadIdentity() {
    elements.identityControl.setAttribute("aria-busy", "true");
    try {
      const payload = await requestJson(`${API_ROOT}/identity`);
      applyIdentity(payload);
      reconcileStoredIdentityAttempt();
      if (pendingAttempt(readDraft(identityAttemptDraftKey()))) {
        elements.refreshIdentityButton.disabled = false;
        elements.refreshIdentityButton.title = "确认上次匿名身份更换";
      }
    } catch (error) {
      elements.currentIdentityName.textContent = "身份读取失败";
      elements.identityControl.setAttribute("aria-busy", "false");
      elements.anonymousToggle.disabled = true;
      elements.refreshIdentityButton.disabled = true;
      showToast(error.message, "error");
      throw error;
    }
  }

  function formatCooldown(seconds) {
    const total = Math.max(0, Math.ceil(Number(seconds || 0)));
    const hours = Math.floor(total / 3600);
    const minutes = Math.ceil((total % 3600) / 60);
    if (hours > 0) return `约 ${hours} 小时 ${minutes} 分钟后可更换`;
    if (minutes > 0) return `约 ${minutes} 分钟后可更换`;
    return "即将可以更换";
  }

  function identityAttemptDraftKey() {
    return storageKey("identity.rotate");
  }

  function reconcileStoredIdentityAttempt() {
    if (!state.identity || !state.storageAvailable || !state.storageNamespace) return false;
    const draft = readDraft(identityAttemptDraftKey());
    const pending = pendingAttempt(draft);
    const attemptedName = String(pending && pending.body.display_name || "");
    const previousName = typeof draft?.previous_anonymous_name === "string"
      ? draft.previous_anonymous_name
      : null;
    if (
      !pending
      || previousName === null
      || attemptedName === previousName
      || attemptedName !== String(state.identity.anonymous_name || "")
    ) return false;
    clearDraft(identityAttemptDraftKey());
    return true;
  }

  function testSessionStorage() {
    try {
      const key = "__numoj_forum_storage_test__";
      window.sessionStorage.setItem(key, "1");
      window.sessionStorage.removeItem(key);
      state.storageAvailable = true;
    } catch (_error) {
      state.storageAvailable = false;
    }
  }

  function storageKey(kind, id) {
    const suffix = id == null ? kind : `${kind}.${id}`;
    return `${state.storageNamespace || "numoj.forum.v2.unknown"}.${suffix}`;
  }

  function readDraft(key) {
    if (!state.storageAvailable) return null;
    try {
      const value = JSON.parse(window.sessionStorage.getItem(key) || "null");
      return value && typeof value === "object" ? value : null;
    } catch (_error) {
      return null;
    }
  }

  function writeDraft(key, value) {
    if (!state.storageAvailable) return false;
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (_error) {
      state.storageAvailable = false;
      showToast("无法使用标签页存储，已暂停提交以免丢失草稿", "error");
      return false;
    }
  }

  function clearDraft(key) {
    if (!state.storageAvailable) return;
    try {
      window.sessionStorage.removeItem(key);
    } catch (_error) {
      // 清理失败不会把已经确认成功的请求重新发送。
    }
  }

  function pendingAttempt(draft) {
    const attempt = draft && draft.pending_attempt;
    if (
      !attempt
      || typeof attempt !== "object"
      || !attempt.body
      || typeof attempt.body !== "object"
      || typeof attempt.body.client_request_id !== "string"
    ) return null;
    return attempt;
  }

  function reliableAttempt(body, postingIdentity) {
    const attempt = {
      body: Object.assign({}, body),
      submitted_at: new Date().toISOString(),
    };
    if (postingIdentity) {
      attempt.posting_identity = {
        name: String(postingIdentity.name || ""),
        avatar: postingIdentity.avatar || { cells: [] },
      };
    }
    return attempt;
  }

  function randomUuid() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function ensureReliableStorage(errorElement) {
    if (state.storageAvailable) return true;
    const message = "当前浏览器禁止标签页存储，无法启用可靠提交；请允许站点存储后刷新页面。";
    if (errorElement) errorElement.textContent = message;
    showToast(message, "error");
    return false;
  }

  function postingToken() {
    return state.identity ? state.identity.posting_token : "";
  }

  function parseDate(value) {
    if (!value) return null;
    if (value instanceof Date) return value;
    const text = String(value);
    const date = new Date(text.includes("T") ? text : text.replace(" ", "T"));
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatRelativeTime(value) {
    const date = parseDate(value);
    if (!date) return String(value || "未知时间");
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 45) return "刚刚";
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)} 天前`;
    return new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  function formatAbsoluteTime(value) {
    const date = parseDate(value);
    if (!date) return String(value || "未知时间");
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  function threadCode(id) {
    return `F${String(id || 0).padStart(4, "0")}`;
  }

  function threadUrl(id) {
    return `/forum/thread/${Number(id)}`;
  }

  function currentPathThreadId() {
    const match = window.location.pathname.match(/^\/forum\/thread\/(\d+)\/?$/);
    return match ? Number(match[1]) : null;
  }

  function isMobile() {
    return window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT}px)`).matches;
  }

  function showMobileDetail(show) {
    app.classList.toggle("is-mobile-detail-open", Boolean(show));
    document.body.classList.toggle("forum-mobile-locked", Boolean(show));
  }

  function setThreadListLoading() {
    elements.threadList.innerHTML = `
      <div class="forum-list-skeleton" aria-hidden="true">
        <span></span><span></span><span></span><span></span><span></span>
      </div>
    `;
  }

  function normalizeThread(item) {
    return Object.assign({}, item, {
      id: Number(item.id),
      reply_count: Number(item.reply_count || 0),
      display_name: item.display_name || item.username || "未知用户",
      avatar: item.avatar || item.avatar_cells || { cells: [] },
      excerpt: item.excerpt || item.preview || "",
      is_owner: Boolean(item.is_owner),
      is_anonymous: Boolean(item.is_anonymous),
      edit_version: Number(item.edit_version || 1),
    });
  }

  function normalizeReply(item) {
    return Object.assign({}, item, {
      id: Number(item.id),
      display_name: item.display_name || item.username || "未知用户",
      avatar: item.avatar || item.avatar_cells || { cells: [] },
      is_owner: Boolean(item.is_owner),
      is_anonymous: Boolean(item.is_anonymous),
      edit_version: Number(item.edit_version || 1),
    });
  }

  function renderThreadList() {
    if (!state.threads.length) {
      elements.threadList.innerHTML = `
        <div class="forum-list-empty">
          <span class="forum-empty-mark"><i class="fas fa-magnifying-glass" aria-hidden="true"></i></span>
          <strong>${state.query ? "没有匹配的讨论" : "讨论区还是空的"}</strong>
          <p>${state.query ? "换个关键词，或切换讨论范围后再试。" : "从一个具体问题开始，会更容易得到有用的回应。"}</p>
        </div>
      `;
      elements.loadMoreThreadsButton.hidden = true;
      return;
    }

    const fragment = document.createDocumentFragment();
    state.threads.forEach((thread) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = `forum-thread-row${thread.id === state.selectedId ? " is-selected" : ""}`;
      row.dataset.threadId = String(thread.id);
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", thread.id === state.selectedId ? "true" : "false");

      const title = document.createElement("h3");
      title.className = "forum-thread-title";
      title.textContent = thread.title;

      const meta = document.createElement("span");
      meta.className = "forum-thread-meta";
      const identity = document.createElement("span");
      identity.className = "forum-thread-identity";
      const avatar = document.createElement("span");
      avatar.className = "forum-identicon forum-identicon-xs";
      avatar.setAttribute("aria-hidden", "true");
      paintAvatar(avatar, thread.avatar, thread.display_name);
      const author = document.createElement("span");
      author.className = "forum-thread-author";
      author.textContent = thread.display_name;
      identity.append(avatar, author);
      if (thread.is_anonymous) {
        const anonymous = document.createElement("span");
        anonymous.className = "forum-anonymous-mark";
        anonymous.textContent = "匿名";
        identity.append(anonymous);
      }
      const active = document.createElement("span");
      active.className = "forum-thread-active-time";
      active.textContent = formatRelativeTime(thread.last_activity_at || thread.updated_at || thread.created_at);
      active.title = formatAbsoluteTime(thread.last_activity_at || thread.updated_at || thread.created_at);
      const replyCount = document.createElement("span");
      replyCount.className = "forum-reply-count";
      replyCount.innerHTML = `<i class="far fa-comment" aria-hidden="true"></i>${thread.reply_count}`;
      meta.append(identity, active, replyCount);

      row.append(title, meta);
      fragment.appendChild(row);
    });
    elements.threadList.replaceChildren(fragment);
    elements.loadMoreThreadsButton.hidden = state.page >= state.totalPages;
  }

  async function loadThreads(options) {
    const config = Object.assign({ append: false, autoSelect: false }, options || {});
    const requestSequence = ++state.listRequestSequence;
    const page = config.append ? state.page + 1 : 1;
    if (!config.append) setThreadListLoading();

    const params = new URLSearchParams({
      scope: state.scope,
      page: String(page),
      limit: String(THREAD_PAGE_SIZE),
    });
    if (state.query) params.set("q", state.query);

    try {
      const payload = await requestJson(`${API_ROOT}?${params.toString()}`);
      if (requestSequence !== state.listRequestSequence) return;
      const incoming = (payload.threads || []).map(normalizeThread);
      state.threads = config.append ? state.threads.concat(incoming) : incoming;
      state.page = Number(payload.page || page);
      state.totalPages = Number(payload.total_pages || (incoming.length === THREAD_PAGE_SIZE ? page + 1 : page));
      renderThreadList();

      if (config.autoSelect && !state.selectedId && state.threads.length) {
        await selectThread(state.threads[0].id, {
          historyMode: isMobile() ? "none" : "replace",
          revealMobile: false,
        });
      }
    } catch (error) {
      if (error.name === "AbortError") return;
      elements.threadList.innerHTML = `
        <div class="forum-list-empty">
          <span class="forum-empty-mark"><i class="fas fa-triangle-exclamation" aria-hidden="true"></i></span>
          <strong>讨论列表加载失败</strong>
          <p>${escapeHtml(error.message)}。请稍后重试。</p>
        </div>
      `;
      showToast(error.message, "error");
    }
  }

  function enhanceRenderedMarkdown(root) {
    return window.NumericalOJMarkdownRenderer.enhance(root);
  }

  function clearRenderedMarkdown(root) {
    window.NumericalOJMarkdownRenderer.clear(root);
  }

  function buildPost(item, kind) {
    const article = document.createElement("article");
    article.className = "forum-post";
    article.dataset.postKind = kind;
    article.dataset.postId = String(item.id);

    const avatar = document.createElement("span");
    avatar.className = "forum-identicon";
    avatar.setAttribute("aria-hidden", "true");
    paintAvatar(avatar, item.avatar, item.display_name);

    const content = document.createElement("div");
    content.className = "forum-post-content";
    const header = document.createElement("header");
    header.className = "forum-post-head";
    const name = document.createElement("strong");
    name.textContent = item.display_name;
    header.appendChild(name);

    if (item.is_anonymous) {
      const anonymous = document.createElement("span");
      anonymous.className = "forum-anonymous-mark";
      anonymous.textContent = "ANON";
      header.appendChild(anonymous);
    }
    if (item.edit_version > 1) {
      const edited = document.createElement("span");
      edited.className = "forum-edited-mark";
      edited.textContent = "已编辑";
      edited.title = item.updated_at ? `最后编辑：${formatAbsoluteTime(item.updated_at)}` : "内容已编辑";
      header.appendChild(edited);
    }

    const time = document.createElement("time");
    time.className = "forum-post-time";
    time.textContent = formatRelativeTime(item.created_at);
    time.dateTime = String(item.created_at || "");
    time.title = formatAbsoluteTime(item.created_at);
    header.appendChild(time);

    if (item.is_owner && kind === "reply") {
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "forum-icon-button forum-post-edit";
      edit.dataset.editKind = "reply";
      edit.dataset.editId = String(item.id);
      edit.setAttribute("aria-label", "编辑回复");
      edit.title = "编辑回复";
      edit.innerHTML = '<i class="fas fa-pen" aria-hidden="true"></i>';
      header.appendChild(edit);
    }

    const body = document.createElement("div");
    body.className = "forum-markdown numoj-markdown";
    body.innerHTML = String(item.rendered_content || "");

    content.append(header, body);
    article.append(avatar, content);
    return article;
  }

  function renderConversation(options) {
    const config = Object.assign({ preserveScroll: false, scrollToBottom: false }, options || {});
    if (!state.thread) return;
    const renderSequence = ++state.conversationRenderSequence;
    const previousHeight = elements.conversation.scrollHeight;
    const previousTop = elements.conversation.scrollTop;
    const fragment = document.createDocumentFragment();

    fragment.appendChild(buildPost(state.thread, "thread"));

    const divider = document.createElement("div");
    divider.className = "forum-reply-divider";
    divider.textContent = `${state.thread.reply_count || state.replies.length} REPLIES`;
    fragment.appendChild(divider);

    if (state.hasEarlierReplies) {
      const earlier = document.createElement("button");
      earlier.type = "button";
      earlier.className = "forum-load-earlier";
      earlier.id = "loadEarlierRepliesButton";
      earlier.innerHTML = '<i class="fas fa-arrow-up" aria-hidden="true"></i>加载更早回复';
      fragment.appendChild(earlier);
    }

    if (!state.replies.length) {
      const empty = document.createElement("div");
      empty.className = "forum-detail-empty";
      empty.innerHTML = `
        <span class="forum-empty-mark"><i class="far fa-message" aria-hidden="true"></i></span>
        <strong>还没有回复</strong>
        <p>把你想到的关键线索写下来，成为第一个回应的人。</p>
      `;
      fragment.appendChild(empty);
    } else {
      state.replies.forEach((reply) => fragment.appendChild(buildPost(reply, "reply")));
    }

    clearRenderedMarkdown(elements.conversation);
    elements.conversation.replaceChildren(fragment);

    function settleScrollPosition() {
      if (renderSequence !== state.conversationRenderSequence) return;
      if (config.preserveScroll) {
        const addedHeight = elements.conversation.scrollHeight - previousHeight;
        elements.conversation.scrollTop = previousTop + addedHeight;
      } else if (config.scrollToBottom) {
        elements.conversation.scrollTop = elements.conversation.scrollHeight;
      } else {
        elements.conversation.scrollTop = 0;
      }
    }

    settleScrollPosition();
    enhanceRenderedMarkdown(elements.conversation)
      .then(settleScrollPosition)
      .catch(settleScrollPosition);
  }

  function setDetailLoading(id) {
    state.conversationRenderSequence += 1;
    elements.detailKicker.textContent = `THREAD · ${threadCode(id)}`;
    elements.detailTitle.textContent = "正在读取讨论…";
    elements.editThreadButton.hidden = true;
    elements.copyThreadLinkButton.disabled = true;
    setReplyComposerVisible(false);
    clearRenderedMarkdown(elements.conversation);
    elements.conversation.innerHTML = `
      <div class="forum-list-skeleton" aria-hidden="true">
        <span></span><span></span><span></span><span></span>
      </div>
    `;
  }

  function setDetailError(error) {
    state.conversationRenderSequence += 1;
    elements.detailTitle.textContent = "这条讨论暂时无法显示";
    clearRenderedMarkdown(elements.conversation);
    elements.conversation.innerHTML = `
      <div class="forum-conversation-error">
        <span class="forum-empty-mark"><i class="fas fa-triangle-exclamation" aria-hidden="true"></i></span>
        <strong>正文加载失败</strong>
        <p>${escapeHtml(error.message)}。重新选择该讨论即可重试。</p>
      </div>
    `;
    setReplyComposerVisible(false);
  }

  function applyThreadPayload(payload) {
    state.thread = normalizeThread(payload.thread || {});
    state.thread.rendered_content = (payload.thread || {}).rendered_content || "";
    state.thread.content = (payload.thread || {}).content || "";
    state.replies = (payload.replies || []).map(normalizeReply);
    state.hasEarlierReplies = Boolean(payload.has_earlier_replies);
    state.beforeReplyId = payload.before_reply_id != null
      ? Number(payload.before_reply_id)
      : (state.replies.length ? state.replies[0].id : null);
    state.thread.reply_count = Number(
      payload.reply_count != null ? payload.reply_count : state.thread.reply_count,
    );

    elements.detailKicker.textContent = `THREAD · ${threadCode(state.thread.id)} · ${state.thread.reply_count} REPLIES`;
    elements.detailTitle.textContent = state.thread.title;
    elements.editThreadButton.hidden = !state.thread.is_owner;
    elements.copyThreadLinkButton.disabled = false;
    setReplyComposerVisible(true);
    restoreReplyDraft();
    renderConversation();
  }

  function updateSelectedRow() {
    elements.threadList.querySelectorAll("[data-thread-id]").forEach((row) => {
      const selected = Number(row.dataset.threadId) === state.selectedId;
      row.classList.toggle("is-selected", selected);
      row.setAttribute("aria-selected", selected ? "true" : "false");
    });
  }

  async function selectThread(id, options) {
    const numericId = Number(id);
    if (!Number.isInteger(numericId) || numericId <= 0) return;
    const config = Object.assign(
      { historyMode: "push", revealMobile: true, force: false },
      options || {},
    );
    if (state.selectedId === numericId && state.thread && !config.force) {
      if (config.historyMode === "push" && currentPathThreadId() !== numericId) {
        const fromForumList = /^\/forum\/?$/.test(window.location.pathname);
        window.history.pushState({ forumThread: numericId, fromForumList }, "", threadUrl(numericId));
      }
      if (config.revealMobile && isMobile()) showMobileDetail(true);
      return;
    }

    state.selectedId = numericId;
    updateSelectedRow();
    setDetailLoading(numericId);
    const requestSequence = ++state.detailRequestSequence;

    if (config.historyMode === "push") {
      const fromForumList = /^\/forum\/?$/.test(window.location.pathname);
      window.history.pushState({ forumThread: numericId, fromForumList }, "", threadUrl(numericId));
    } else if (config.historyMode === "replace") {
      window.history.replaceState({ forumThread: numericId }, "", threadUrl(numericId));
    }
    if (config.revealMobile && isMobile()) showMobileDetail(true);

    try {
      const payload = await requestJson(`${API_ROOT}/threads/${numericId}`);
      if (requestSequence !== state.detailRequestSequence) return;
      applyThreadPayload(payload);
      updateSelectedRow();
    } catch (error) {
      if (requestSequence !== state.detailRequestSequence) return;
      state.thread = null;
      state.replies = [];
      setDetailError(error);
      showToast(error.message, "error");
    }
  }

  async function loadEarlierReplies() {
    if (!state.thread || !state.hasEarlierReplies || !state.beforeReplyId) return;
    const targetThreadId = state.thread.id;
    const targetDetailSequence = state.detailRequestSequence;
    const button = document.getElementById("loadEarlierRepliesButton");
    setLoading(button, true, "正在加载");
    const params = new URLSearchParams({
      before: String(state.beforeReplyId),
      limit: String(REPLY_PAGE_SIZE),
    });
    try {
      const payload = await requestJson(
        `${API_ROOT}/threads/${targetThreadId}/replies?${params.toString()}`,
      );
      if (
        targetDetailSequence !== state.detailRequestSequence
        || !state.thread
        || state.thread.id !== targetThreadId
      ) return;
      const earlier = (payload.replies || []).map(normalizeReply);
      const known = new Set(state.replies.map((reply) => reply.id));
      state.replies = earlier.filter((reply) => !known.has(reply.id)).concat(state.replies);
      state.hasEarlierReplies = Boolean(payload.has_earlier_replies);
      state.beforeReplyId = payload.before_reply_id != null
        ? Number(payload.before_reply_id)
        : (state.replies.length ? state.replies[0].id : null);
      renderConversation({ preserveScroll: true });
    } catch (error) {
      if (
        targetDetailSequence === state.detailRequestSequence
        && state.thread
        && state.thread.id === targetThreadId
      ) {
        showToast(error.message, "error");
        setLoading(button, false);
      }
    }
  }

  function replyDraftKey() {
    return storageKey("reply", state.selectedId);
  }

  function currentReplyDraft() {
    const existing = readDraft(replyDraftKey()) || {};
    const pending = pendingAttempt(existing);
    if (pending) return existing;
    return {
      content: elements.replyInput.value,
      client_request_id: existing.client_request_id || randomUuid(),
      pending_attempt: null,
    };
  }

  function resizeReplyInput() {
    elements.replyInput.style.height = "auto";
    elements.replyInput.style.height = `${Math.min(180, Math.max(48, elements.replyInput.scrollHeight))}px`;
    scheduleReplyComposerClearance();
  }

  function syncReplyComposerClearance() {
    state.replyComposerFrame = null;
    const height = elements.replyForm.hidden
      ? 0
      : Math.ceil(elements.replyForm.getBoundingClientRect().height);
    elements.detailPane.style.setProperty(
      "--forum-reply-overlay-height",
      `${height}px`,
    );
  }

  function scheduleReplyComposerClearance() {
    if (state.replyComposerFrame !== null) {
      window.cancelAnimationFrame(state.replyComposerFrame);
    }
    state.replyComposerFrame = window.requestAnimationFrame(
      syncReplyComposerClearance,
    );
  }

  function setReplyComposerVisible(visible) {
    elements.replyForm.hidden = !visible;
    scheduleReplyComposerClearance();
  }

  function observeReplyComposerSize() {
    if (typeof window.ResizeObserver === "function") {
      state.replyComposerObserver = new window.ResizeObserver(
        scheduleReplyComposerClearance,
      );
      state.replyComposerObserver.observe(elements.replyForm);
    }
    window.addEventListener("resize", scheduleReplyComposerClearance);
    scheduleReplyComposerClearance();
  }

  function setReplyAttemptPending(isPending) {
    elements.replyInput.readOnly = Boolean(isPending);
    elements.replyForm.classList.toggle("has-pending-attempt", Boolean(isPending));
  }

  function saveReplyDraft() {
    if (!state.selectedId || !state.storageAvailable) return;
    const existing = readDraft(replyDraftKey()) || {};
    if (pendingAttempt(existing)) return;
    const content = elements.replyInput.value;
    if (!content && !Object.keys(existing).length) return;
    writeDraft(replyDraftKey(), currentReplyDraft());
  }

  function restoreReplyDraft() {
    // 回复提交可以在用户切换讨论后继续完成；按钮本身由所有讨论复用，
    // 因此每次恢复当前讨论时先清理旧讨论留下的 loading 外观。
    setLoading(elements.submitReplyButton, false);
    elements.replyError.textContent = "";
    const draft = readDraft(replyDraftKey());
    const pending = pendingAttempt(draft);
    const restoredContent = pending ? pending.body.content : (draft && draft.content);
    elements.replyInput.value = typeof restoredContent === "string" ? restoredContent : "";
    resizeReplyInput();
    setReplyAttemptPending(Boolean(pending));
    if (pending) {
      elements.replyError.textContent = "上次提交结果尚未确认。内容已冻结，只会使用同一请求标识原样重试。";
    }
  }

  async function submitReply(event) {
    event.preventDefault();
    if (!state.thread || !ensureReliableStorage(elements.replyError)) return;
    const submittedThreadId = state.thread.id;
    const submittedDraftKey = replyDraftKey();
    const storedDraft = readDraft(submittedDraftKey) || {};
    const storedAttempt = pendingAttempt(storedDraft);
    const content = storedAttempt
      ? String(storedAttempt.body.content || "")
      : elements.replyInput.value.trim();
    if (!content) {
      elements.replyError.textContent = "回复内容不能为空。";
      elements.replyInput.focus();
      return;
    }
    if (content.length > 100000) {
      elements.replyError.textContent = "回复内容不能超过 100000 个字符。";
      elements.replyInput.focus();
      return;
    }
    if (!storedAttempt && !postingToken()) {
      elements.replyError.textContent = "发布身份尚未就绪，请刷新页面后重试。";
      return;
    }

    const body = storedAttempt
      ? storedAttempt.body
      : {
        content,
        client_request_id: storedDraft.client_request_id || randomUuid(),
        expected_identity_token: postingToken(),
      };
    const draft = Object.assign({}, storedDraft, {
      content: body.content,
      client_request_id: body.client_request_id,
      pending_attempt: storedAttempt || reliableAttempt(body, {
        name: postingName(),
        avatar: postingAvatar(),
      }),
    });
    if (!writeDraft(submittedDraftKey, draft)) return;
    setReplyAttemptPending(true);
    elements.replyError.textContent = "";
    setLoading(elements.submitReplyButton, true);
    elements.submitReplyButton.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>';

    try {
      const payload = await requestJson(`${API_ROOT}/threads/${submittedThreadId}/replies`, {
        method: "POST",
        body,
        retries: RETRY_DELAYS_MS.length,
      });
      clearDraft(submittedDraftKey);

      if (state.thread && state.thread.id === submittedThreadId) {
        setReplyAttemptPending(false);
        elements.replyInput.value = "";
        resizeReplyInput();
      }

      if (
        payload.reply
        && payload.created !== false
        && state.thread
        && state.thread.id === submittedThreadId
      ) {
        const reply = normalizeReply(payload.reply);
        const existingIndex = state.replies.findIndex((item) => item.id === reply.id);
        if (existingIndex >= 0) state.replies[existingIndex] = reply;
        else state.replies.push(reply);
        state.thread.reply_count = Number(payload.reply_count || state.thread.reply_count + 1);
        renderConversation({ scrollToBottom: true });
      } else if (state.thread && state.thread.id === submittedThreadId) {
        await selectThread(submittedThreadId, { historyMode: "none", revealMobile: false, force: true });
        if (state.thread && state.thread.id === submittedThreadId) {
          elements.conversation.scrollTop = elements.conversation.scrollHeight;
        }
      }
      showToast("回复已可靠提交");
      loadThreads({ append: false });
    } catch (error) {
      if (error.payload && error.payload.code === "posting_identity_changed") {
        clearDraft(submittedDraftKey);
        try {
          await loadIdentity();
        } catch (_identityError) {
          // loadIdentity 已显示错误，正文仍在输入框中。
        }
        writeDraft(submittedDraftKey, {
          content,
          client_request_id: randomUuid(),
          pending_attempt: null,
        });
        if (state.thread && state.thread.id === submittedThreadId) {
          setReplyAttemptPending(false);
          elements.replyError.textContent = "发布身份已在其他页面更改。请确认当前身份后再次提交。";
        }
        showToast("发布身份已变化，请重新确认", "error");
        return;
      }
      if (state.thread && state.thread.id === submittedThreadId) {
        elements.replyError.textContent = `${error.message}。草稿和请求标识仍在本标签页，可直接重试。`;
      }
      showToast("回复未获服务端确认，草稿已保留", "error");
    } finally {
      if (state.thread && state.thread.id === submittedThreadId) {
        setLoading(elements.submitReplyButton, false);
        const latestDraft = readDraft(submittedDraftKey);
        setReplyAttemptPending(Boolean(pendingAttempt(latestDraft)));
      }
    }
  }

  async function previewMarkdown(content, target, button) {
    const requestSequence = ++state.previewRequestSequence;
    const text = String(content || "").trim();
    if (!text) {
      clearRenderedMarkdown(target);
      target.innerHTML = '<p class="forum-preview-placeholder">先输入一些内容再预览。</p>';
      target.hidden = false;
      return;
    }
    setLoading(button, true, "预览中");
    try {
      const payload = await requestJson(`${API_ROOT}/preview`, {
        method: "POST",
        body: { content: text },
      });
      if (requestSequence !== state.previewRequestSequence) return;
      clearRenderedMarkdown(target);
      target.innerHTML = String(payload.rendered_content || "");
      target.classList.add("forum-markdown", "numoj-markdown");
      target.hidden = false;
      await enhanceRenderedMarkdown(target);
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setLoading(button, false);
    }
  }

  function newThreadDraftKey() {
    return storageKey("thread.new");
  }

  function editDraftKey() {
    const target = state.editorTarget;
    return storageKey(`edit.${state.editorMode}`, target && target.id);
  }

  function editorDraftKey() {
    return state.editorMode === "new" ? newThreadDraftKey() : editDraftKey();
  }

  function editorContextMatches(mode, targetId, draftKey) {
    const currentTargetId = state.editorMode === "new"
      ? null
      : Number(state.editorTarget && state.editorTarget.id);
    return (
      elements.editorDialog.open
      && state.editorMode === mode
      && currentTargetId === targetId
      && editorDraftKey() === draftKey
    );
  }

  function saveEditorDraft() {
    if (!state.storageAvailable) return;
    const existing = readDraft(editorDraftKey()) || {};
    if (pendingAttempt(existing)) return;
    const isEdit = state.editorMode !== "new";
    const value = {
      title: elements.editorTitleInput.value,
      content: elements.editorContentInput.value,
      client_request_id: existing.client_request_id || randomUuid(),
      base_version: isEdit
        ? Number(existing.base_version || state.editorTarget.edit_version)
        : null,
      pending_attempt: null,
    };
    writeDraft(editorDraftKey(), value);
    elements.editorDraftStatus.textContent = state.editorDraftIsStale
      ? `旧草稿仍基于版本 ${value.base_version}`
      : "";
  }

  function setEditorDraftControls({ pending, stale }) {
    const isPending = Boolean(pending);
    const isStale = Boolean(stale);
    state.editorDraftIsStale = isStale;
    elements.editorTitleInput.readOnly = isPending;
    elements.editorContentInput.readOnly = isPending;
    elements.editorForm.classList.toggle("has-pending-attempt", isPending);
    elements.rebaseEditorDraftButton.hidden = !isStale || isPending;
    elements.submitEditorButton.disabled = isStale && !isPending;
  }

  function rebaseEditorDraft() {
    if (!state.editorTarget || state.editorMode === "new") return;
    const key = editorDraftKey();
    const draft = readDraft(key);
    if (!draft || pendingAttempt(draft)) return;
    const rebased = {
      title: state.editorMode === "edit-thread"
        ? elements.editorTitleInput.value
        : "",
      content: elements.editorContentInput.value,
      client_request_id: randomUuid(),
      base_version: state.editorTarget.edit_version,
      pending_attempt: null,
    };
    if (!writeDraft(key, rebased)) return;
    setEditorDraftControls({ pending: false, stale: false });
    elements.editorError.textContent = "已明确将此草稿重建到最新版本，请检查差异后再保存。";
    elements.editorDraftStatus.textContent = `已重建到版本 ${state.editorTarget.edit_version}`;
  }

  function setEditorTab(tab) {
    const preview = tab === "preview";
    elements.editorTabs.querySelectorAll("[data-editor-tab]").forEach((button) => {
      const active = button.dataset.editorTab === tab;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
    elements.editorWritePanel.hidden = preview;
    elements.editorPreviewPanel.hidden = !preview;
    if (preview) {
      previewMarkdown(
        elements.editorContentInput.value,
        elements.editorPreviewPanel,
        elements.editorTabs.querySelector('[data-editor-tab="preview"]'),
      );
    }
  }

  function setEditorIdentity(name, avatar, hint) {
    const nameElement = elements.editorIdentityRow.querySelector("[data-posting-name]");
    const avatarElement = elements.editorIdentityRow.querySelector("[data-posting-avatar]");
    nameElement.textContent = name || "当前身份";
    paintAvatar(avatarElement, avatar, name);
    elements.editorIdentityHint.textContent = hint;
  }

  function openEditor(mode, target) {
    state.previewRequestSequence += 1;
    // 提交请求可以在编辑器关闭后继续完成。打开另一个编辑上下文时，先清掉
    // 复用按钮上属于旧上下文的 loading 外观；旧请求完成后也不会再改写新上下文。
    setLoading(elements.submitEditorButton, false);
    state.editorMode = mode;
    state.editorTarget = target || null;
    elements.editorError.textContent = "";
    clearRenderedMarkdown(elements.editorPreviewPanel);
    elements.editorPreviewPanel.innerHTML = "";
    elements.rebaseEditorDraftButton.hidden = true;
    setEditorTab("write");

    if (mode === "new") {
      elements.editorEyebrow.textContent = "NEW THREAD";
      elements.editorDialogTitle.textContent = "发起讨论";
      elements.submitEditorButton.textContent = "发布讨论";
      elements.editorTitleField.hidden = false;
      elements.editorTitleInput.required = true;
      const draft = readDraft(newThreadDraftKey()) || {};
      const pending = pendingAttempt(draft);
      const restored = pending ? pending.body : draft;
      elements.editorTitleInput.value = restored.title || "";
      elements.editorContentInput.value = restored.content || "";
      elements.editorDraftStatus.textContent = restored.content || restored.title
        ? "已恢复当前标签页中的草稿"
        : "";
      const attemptedIdentity = pending && pending.posting_identity;
      setEditorIdentity(
        attemptedIdentity ? attemptedIdentity.name : postingName(),
        attemptedIdentity ? attemptedIdentity.avatar : postingAvatar(),
        pending ? "正在确认这次发布所锁定的身份" : "讨论将以当前身份发布",
      );
      setEditorDraftControls({ pending: Boolean(pending), stale: false });
      if (pending) {
        elements.editorError.textContent = "上次发布结果尚未确认。内容已冻结，只会使用同一请求标识原样重试。";
      }
    } else if (mode === "edit-thread") {
      elements.editorEyebrow.textContent = `EDIT · ${threadCode(target.id)}`;
      elements.editorDialogTitle.textContent = "编辑主题";
      elements.submitEditorButton.textContent = "保存修改";
      elements.editorTitleField.hidden = false;
      elements.editorTitleInput.required = true;
      const draft = readDraft(editDraftKey());
      const pending = pendingAttempt(draft);
      const restored = pending ? pending.body : draft;
      const baseVersion = Number(
        (draft && draft.base_version)
        || (pending && pending.body.edit_version)
        || target.edit_version,
      );
      const stale = Boolean(draft) && baseVersion !== Number(target.edit_version);
      elements.editorTitleInput.value = restored ? restored.title : target.title;
      elements.editorContentInput.value = restored ? restored.content : target.content;
      elements.editorDraftStatus.textContent = draft
        ? `已恢复基于版本 ${baseVersion} 的编辑`
        : `基于版本 ${target.edit_version}`;
      setEditorIdentity(target.display_name, target.avatar, "身份按首次发布时锁定");
      setEditorDraftControls({ pending: Boolean(pending), stale });
      if (pending) {
        elements.editorError.textContent = "上次编辑结果尚未确认。内容已冻结，请原样重试完成对账。";
      } else if (stale) {
        elements.editorError.textContent = `草稿基于版本 ${baseVersion}，当前已是版本 ${target.edit_version}。请检查后明确重建，不能直接覆盖。`;
      }
    } else {
      elements.editorEyebrow.textContent = `EDIT REPLY · #${target.id}`;
      elements.editorDialogTitle.textContent = "编辑回复";
      elements.submitEditorButton.textContent = "保存修改";
      elements.editorTitleField.hidden = true;
      elements.editorTitleInput.required = false;
      const draft = readDraft(editDraftKey());
      const pending = pendingAttempt(draft);
      const restored = pending ? pending.body : draft;
      const baseVersion = Number(
        (draft && draft.base_version)
        || (pending && pending.body.edit_version)
        || target.edit_version,
      );
      const stale = Boolean(draft) && baseVersion !== Number(target.edit_version);
      elements.editorTitleInput.value = "";
      elements.editorContentInput.value = restored ? restored.content : target.content;
      elements.editorDraftStatus.textContent = draft
        ? `已恢复基于版本 ${baseVersion} 的编辑`
        : `基于版本 ${target.edit_version}`;
      setEditorIdentity(target.display_name, target.avatar, "身份按首次发布时锁定");
      setEditorDraftControls({ pending: Boolean(pending), stale });
      if (pending) {
        elements.editorError.textContent = "上次编辑结果尚未确认。内容已冻结，请原样重试完成对账。";
      } else if (stale) {
        elements.editorError.textContent = `草稿基于版本 ${baseVersion}，当前已是版本 ${target.edit_version}。请检查后明确重建，不能直接覆盖。`;
      }
    }
    elements.editorDialog.showModal();
    window.setTimeout(() => {
      if (mode === "new" || mode === "edit-thread") elements.editorTitleInput.focus();
      else elements.editorContentInput.focus();
    }, 30);
  }

  function closeEditor() {
    state.previewRequestSequence += 1;
    if (elements.editorDialog.open) elements.editorDialog.close();
  }

  async function submitEditor(event) {
    event.preventDefault();
    if (!ensureReliableStorage(elements.editorError)) return;
    const submittedMode = state.editorMode;
    const submittedTarget = state.editorTarget
      ? Object.assign({}, state.editorTarget)
      : null;
    const submittedTargetId = submittedMode === "new"
      ? null
      : Number(submittedTarget && submittedTarget.id);
    const affectedThreadId = submittedMode === "edit-thread"
      ? submittedTargetId
      : (
        submittedMode === "edit-reply"
          ? Number(submittedTarget && submittedTarget.thread_id)
          : null
      );
    const draftKey = editorDraftKey();
    const storedDraft = readDraft(draftKey) || {};
    const storedAttempt = pendingAttempt(storedDraft);
    if (state.editorDraftIsStale && !storedAttempt) {
      elements.editorError.textContent = "这份草稿基于旧版本，必须先明确重建后才能保存。";
      return;
    }

    const title = storedAttempt
      ? String(storedAttempt.body.title || "")
      : elements.editorTitleInput.value.trim();
    const content = storedAttempt
      ? String(storedAttempt.body.content || "")
      : elements.editorContentInput.value.trim();
    if (
      !storedAttempt
      && (state.editorMode === "new" || state.editorMode === "edit-thread")
      && !title
    ) {
      elements.editorError.textContent = "标题不能为空。";
      elements.editorTitleInput.focus();
      return;
    }
    if (!storedAttempt && !content) {
      elements.editorError.textContent = "正文不能为空。";
      elements.editorContentInput.focus();
      return;
    }
    if (!storedAttempt && title.length > 255) {
      elements.editorError.textContent = "标题长度不能超过 255 个字符。";
      elements.editorTitleInput.focus();
      return;
    }
    if (!storedAttempt && content.length > 100000) {
      elements.editorError.textContent = "正文不能超过 100000 个字符。";
      elements.editorContentInput.focus();
      return;
    }
    if (state.editorMode === "new" && !storedAttempt && !postingToken()) {
      elements.editorError.textContent = "发布身份尚未就绪，请刷新页面后重试。";
      return;
    }

    if (!storedAttempt) saveEditorDraft();
    const persistedDraft = readDraft(draftKey) || storedDraft;
    let body;
    if (storedAttempt) {
      body = storedAttempt.body;
    } else if (state.editorMode === "new") {
      body = {
        title,
        content,
        client_request_id: persistedDraft.client_request_id || randomUuid(),
        expected_identity_token: postingToken(),
      };
    } else if (state.editorMode === "edit-thread") {
      body = {
        title,
        content,
        edit_version: Number(
          persistedDraft.base_version || state.editorTarget.edit_version,
        ),
        client_request_id: persistedDraft.client_request_id || randomUuid(),
      };
    } else {
      body = {
        content,
        edit_version: Number(
          persistedDraft.base_version || state.editorTarget.edit_version,
        ),
        client_request_id: persistedDraft.client_request_id || randomUuid(),
      };
    }
    const pendingDraft = Object.assign({}, persistedDraft, {
      title,
      content,
      client_request_id: body.client_request_id,
      base_version: state.editorMode === "new" ? null : body.edit_version,
      pending_attempt: storedAttempt || reliableAttempt(
        body,
        state.editorMode === "new"
          ? { name: postingName(), avatar: postingAvatar() }
          : null,
      ),
    });
    if (!writeDraft(draftKey, pendingDraft)) return;
    setEditorDraftControls({
      pending: true,
      stale: state.editorDraftIsStale,
    });
    elements.editorError.textContent = "";
    setLoading(
      elements.submitEditorButton,
      true,
      state.editorMode === "new" ? "发布中" : "保存中",
    );

    try {
      let payload;
      if (submittedMode === "new") {
        payload = await requestJson(`${API_ROOT}/threads`, {
          method: "POST",
          body,
          retries: RETRY_DELAYS_MS.length,
        });
      } else if (submittedMode === "edit-thread") {
        payload = await requestJson(`${API_ROOT}/threads/${submittedTargetId}`, {
          method: "PATCH",
          body,
          retries: RETRY_DELAYS_MS.length,
        });
      } else {
        payload = await requestJson(`${API_ROOT}/replies/${submittedTargetId}`, {
          method: "PATCH",
          body,
          retries: RETRY_DELAYS_MS.length,
        });
      }

      clearDraft(draftKey);
      const contextStillOpen = editorContextMatches(
        submittedMode,
        submittedTargetId,
        draftKey,
      );
      if (contextStillOpen) {
        setLoading(elements.submitEditorButton, false);
        setEditorDraftControls({ pending: false, stale: false });
        closeEditor();
      }
      if (submittedMode === "new") {
        const newId = Number(
          (payload.thread && payload.thread.id) || payload.thread_id,
        );
        await loadThreads({ append: false });
        if (newId && (contextStillOpen || !elements.editorDialog.open)) {
          await selectThread(newId, { historyMode: "push", revealMobile: true, force: true });
        }
        showToast("讨论已可靠发布");
      } else {
        if (affectedThreadId && state.selectedId === affectedThreadId) {
          await selectThread(affectedThreadId, {
            historyMode: "none",
            revealMobile: false,
            force: true,
          });
        }
        await loadThreads({ append: false });
        showToast("修改已保存");
      }
    } catch (error) {
      if (
        submittedMode === "new"
        && error.payload
        && error.payload.code === "posting_identity_changed"
      ) {
        clearDraft(draftKey);
        try {
          await loadIdentity();
        } catch (_identityError) {
          // loadIdentity 已显示错误；草稿正文仍保留在编辑器内。
        }
        writeDraft(draftKey, {
          title,
          content,
          client_request_id: randomUuid(),
          base_version: null,
          pending_attempt: null,
        });
        if (editorContextMatches(submittedMode, submittedTargetId, draftKey)) {
          setEditorDraftControls({ pending: false, stale: false });
          setEditorIdentity(postingName(), postingAvatar(), "讨论将以当前身份发布");
          elements.editorError.textContent = "发布身份已在其他页面更改。请确认当前身份后再次发布。";
        }
      } else if (
        error.status === 409
        && submittedMode !== "new"
        && error.payload
        && error.payload.current_version != null
      ) {
        const baseVersion = Number(body.edit_version);
        writeDraft(draftKey, {
          title,
          content,
          client_request_id: randomUuid(),
          base_version: baseVersion,
          pending_attempt: null,
        });
        if (affectedThreadId && state.selectedId === affectedThreadId) {
          await selectThread(affectedThreadId, {
            historyMode: "none",
            revealMobile: false,
            force: true,
          });
        }
        if (editorContextMatches(submittedMode, submittedTargetId, draftKey)) {
          const refreshedTarget = submittedMode === "edit-thread"
            ? state.thread
            : findReply(submittedTargetId);
          if (refreshedTarget) state.editorTarget = refreshedTarget;
          setEditorDraftControls({ pending: false, stale: true });
          elements.editorError.textContent = `内容已更新到版本 ${error.payload.current_version}。旧草稿已保留，请检查后明确重建，不能直接覆盖。`;
        }
      } else {
        if (editorContextMatches(submittedMode, submittedTargetId, draftKey)) {
          elements.editorError.textContent = `${error.message}。请求内容和标识已冻结，可原样重试确认结果。`;
        }
      }
      showToast(error.message, "error");
    } finally {
      if (editorContextMatches(submittedMode, submittedTargetId, draftKey)) {
        setLoading(elements.submitEditorButton, false);
        const latestDraft = readDraft(draftKey);
        setEditorDraftControls({
          pending: Boolean(pendingAttempt(latestDraft)),
          stale: state.editorDraftIsStale,
        });
      }
    }
  }

  const HAN_CODEPOINT_RANGES = [
    [0x3400, 0x4dbf],
    [0x4e00, 0x9fff],
    [0xf900, 0xfaff],
    [0x20000, 0x2a6df],
    [0x2a700, 0x2b73f],
    [0x2b740, 0x2b81f],
    [0x2b820, 0x2ceaf],
    [0x2ceb0, 0x2ebef],
    [0x2f800, 0x2fa1f],
    [0x30000, 0x3134f],
    [0x31350, 0x323af],
  ];

  function isAllowedHanCharacter(char) {
    const codepoint = char.codePointAt(0);
    return HAN_CODEPOINT_RANGES.some(
      ([start, end]) => codepoint >= start && codepoint <= end,
    );
  }

  function weightedAliasLength(value) {
    return Array.from(value).reduce((total, char) => (
      total + (isAllowedHanCharacter(char) ? 2 : 1)
    ), 0);
  }

  function validateAliasClient(value) {
    const cleaned = String(value || "").normalize("NFKC").trim();
    if (!cleaned) return { ok: false, cleaned, length: 0, message: "请输入匿名用户名。" };
    const length = weightedAliasLength(cleaned);
    if (length > 10) {
      return { ok: false, cleaned, length, message: "匿名用户名的加权长度不能超过 10。" };
    }
    for (const char of cleaned) {
      if (!(isAllowedHanCharacter(char) || /^[A-Za-z0-9_-]$/.test(char))) {
        return {
          ok: false,
          cleaned,
          length,
          message: "只能使用中文、英文字母、数字、下划线和连字符。",
        };
      }
    }
    return { ok: true, cleaned, length, message: "" };
  }

  function updateAliasPreview() {
    const validation = validateAliasClient(elements.aliasInput.value);
    const hasPendingAttempt = elements.identityForm.classList.contains("has-pending-attempt");
    const isCoolingDown = (
      state.identityMode === "refresh"
      && state.identity.cooldown_remaining_seconds > 0
      && !hasPendingAttempt
    );
    elements.aliasCount.textContent = `${validation.length} / 10`;
    elements.aliasCount.classList.toggle("is-invalid", validation.length > 10);
    elements.aliasPreviewName.textContent = validation.cleaned || "等待输入";
    paintAvatar(
      elements.aliasPreviewAvatar,
      avatarCellsForName(validation.cleaned || "anonymous-preview"),
      validation.cleaned || "匿名头像预览",
    );
    elements.aliasError.textContent = validation.message;
    elements.saveIdentityButton.disabled = (
      isCoolingDown
      || (!hasPendingAttempt && !validation.ok)
    );
    return validation;
  }

  function setIdentityAttemptPending(isPending) {
    elements.aliasInput.readOnly = Boolean(isPending);
    elements.identityForm.classList.toggle("has-pending-attempt", Boolean(isPending));
  }

  function openIdentityDialog(mode) {
    const storedDraft = readDraft(identityAttemptDraftKey());
    const storedAttempt = pendingAttempt(storedDraft);
    state.identityMode = storedAttempt
      ? (storedDraft.mode || mode)
      : mode;
    elements.identityDialogTitle.textContent = storedAttempt
      ? "确认上次身份更换"
      : (mode === "first" ? "设置匿名身份" : "更换匿名身份");
    elements.aliasInput.value = storedAttempt
      ? String(storedAttempt.body.display_name || "")
      : "";
    elements.aliasError.textContent = "";
    setIdentityAttemptPending(Boolean(storedAttempt));
    if (storedAttempt) {
      elements.identityCooldownNote.textContent = "请求结果尚未确认，用户名已冻结并将原样重试";
      elements.saveIdentityButton.disabled = false;
    } else if (mode === "refresh" && state.identity.cooldown_remaining_seconds > 0) {
      elements.identityCooldownNote.textContent = formatCooldown(state.identity.cooldown_remaining_seconds);
      elements.saveIdentityButton.disabled = true;
    } else {
      elements.identityCooldownNote.textContent = mode === "first"
        ? "首次设置不受冷却限制"
        : "成功更换后 24 小时内不能再次更换";
      elements.saveIdentityButton.disabled = false;
    }
    updateAliasPreview();
    elements.identityDialog.showModal();
    window.setTimeout(() => elements.aliasInput.focus(), 30);
  }

  function closeIdentityDialog() {
    if (elements.identityDialog.open) elements.identityDialog.close();
    elements.anonymousToggle.checked = Boolean(state.identity && state.identity.use_anonymous);
  }

  async function saveAnonymousIdentity(event) {
    event.preventDefault();
    const draftKey = identityAttemptDraftKey();
    const storedDraft = readDraft(draftKey) || {};
    const storedAttempt = pendingAttempt(storedDraft);
    const validation = updateAliasPreview();
    if (!storedAttempt && !validation.ok) {
      elements.aliasInput.focus();
      return;
    }
    const body = storedAttempt
      ? storedAttempt.body
      : {
        display_name: validation.cleaned,
        enable: state.identityMode === "first" ? true : state.identity.use_anonymous,
        client_request_id: randomUuid(),
      };
    const persistedDraft = {
      mode: state.identityMode,
      display_name: body.display_name,
      client_request_id: body.client_request_id,
      previous_anonymous_name: storedAttempt
        ? storedDraft.previous_anonymous_name
        : String(state.identity.anonymous_name || ""),
      pending_attempt: storedAttempt || reliableAttempt(body),
    };
    if (!writeDraft(draftKey, persistedDraft)) return;
    setIdentityAttemptPending(true);
    setLoading(elements.saveIdentityButton, true, "保存中");
    try {
      const payload = await requestJson(`${API_ROOT}/identity/anonymous`, {
        method: "POST",
        body,
        retries: RETRY_DELAYS_MS.length,
      });
      clearDraft(draftKey);
      applyIdentity(payload);
      closeIdentityDialog();
      showToast(
        state.identityMode === "first"
          ? `已启用匿名身份：${state.identity.anonymous_name}`
          : `匿名身份已更换为：${state.identity.anonymous_name}`,
      );
    } catch (error) {
      let reconciled = false;
      try {
        const identityPayload = await requestJson(`${API_ROOT}/identity`);
        applyIdentity(identityPayload);
        const previousName = typeof persistedDraft.previous_anonymous_name === "string"
          ? persistedDraft.previous_anonymous_name
          : null;
        reconciled = (
          previousName !== null
          && String(body.display_name || "") !== previousName
          &&
          String(state.identity.anonymous_name || "")
          === String(body.display_name || "")
        );
      } catch (_identityError) {
        // 无法对账时保留冻结请求，绝不生成新标识再次更换。
      }
      if (reconciled) {
        clearDraft(draftKey);
        closeIdentityDialog();
        showToast(`匿名身份已确认：${state.identity.anonymous_name}`);
        return;
      }

      const rejectionCode = error.payload && error.payload.code;
      const definitelyRejected = error.status === 400 || [
        "invalid_anonymous_name",
        "reserved_identity_name",
        "identity_name_conflict",
        "anonymous_identity_cooldown",
        "identity_operation_conflict",
      ].includes(rejectionCode);
      if (definitelyRejected) {
        clearDraft(draftKey);
        setIdentityAttemptPending(false);
      }
      elements.aliasError.textContent = definitelyRejected
        ? `${error.message}。请求未写入，可以修改后重试。`
        : `${error.message}。结果尚未确认，用户名与请求标识已冻结。`;
      showToast(error.message, "error");
    } finally {
      setLoading(elements.saveIdentityButton, false);
      const latestDraft = readDraft(draftKey);
      setIdentityAttemptPending(Boolean(pendingAttempt(latestDraft)));
      updateAliasPreview();
    }
  }

  async function toggleAnonymousIdentity(event) {
    const enabled = event.target.checked;
    if (enabled && !state.identity.anonymous_name) {
      event.target.checked = false;
      openIdentityDialog("first");
      return;
    }
    elements.anonymousToggle.disabled = true;
    try {
      const payload = await requestJson(`${API_ROOT}/identity/mode`, {
        method: "PUT",
        body: { use_anonymous: enabled },
        retries: RETRY_DELAYS_MS.length,
      });
      applyIdentity(payload);
      showToast(enabled
        ? `已切换为匿名身份：${state.identity.posting_name}`
        : `已恢复原始身份：${state.identity.posting_name}`);
    } catch (error) {
      let reconciled = false;
      try {
        const identityPayload = await requestJson(`${API_ROOT}/identity`);
        applyIdentity(identityPayload);
        reconciled = state.identity.use_anonymous === enabled;
      } catch (_identityError) {
        // 无法对账时恢复本地显示，下一次操作仍由服务端绝对状态接口校正。
      }
      if (reconciled) {
        showToast(enabled
          ? `已确认匿名身份：${state.identity.posting_name}`
          : `已确认原始身份：${state.identity.posting_name}`);
      } else {
        elements.anonymousToggle.checked = !enabled;
        elements.anonymousToggle.disabled = false;
        showToast(error.message, "error");
      }
    }
  }

  async function writeClipboardText(text) {
    const renderer = window.NumericalOJMarkdownRenderer;
    if (!renderer || typeof renderer.copyText !== "function") {
      throw new Error("clipboard-unavailable");
    }
    await renderer.copyText(text);
  }

  async function copyThreadLink() {
    if (!state.selectedId) return;
    const url = new URL(threadUrl(state.selectedId), window.location.origin).href;
    try {
      await writeClipboardText(url);
      showToast("链接已复制到剪贴板，快去分享吧！", "share");
    } catch (_error) {
      showToast("链接复制失败，请允许浏览器访问剪贴板后重试。", "error");
    }
  }

  function findReply(id) {
    return state.replies.find((reply) => reply.id === Number(id)) || null;
  }

  function handleConversationClick(event) {
    const earlier = event.target.closest("#loadEarlierRepliesButton");
    if (earlier) {
      loadEarlierReplies();
      return;
    }
    const edit = event.target.closest("[data-edit-kind]");
    if (!edit) return;
    if (edit.dataset.editKind === "thread" && state.thread) {
      openEditor("edit-thread", state.thread);
      return;
    }
    const reply = findReply(edit.dataset.editId);
    if (reply) openEditor("edit-reply", reply);
  }

  function handleMobileBack() {
    if (window.history.state && window.history.state.fromForumList) {
      window.history.back();
      return;
    }
    window.history.pushState({ forumView: "list" }, "", "/forum");
    showMobileDetail(false);
  }

  function bindEvents() {
    elements.threadList.addEventListener("click", (event) => {
      const row = event.target.closest("[data-thread-id]");
      if (!row) return;
      selectThread(Number(row.dataset.threadId), {
        historyMode: "push",
        revealMobile: true,
      });
    });

    elements.filterStrip.addEventListener("click", (event) => {
      const chip = event.target.closest("[data-scope]");
      if (!chip || chip.dataset.scope === state.scope) return;
      state.scope = chip.dataset.scope;
      elements.filterStrip.querySelectorAll("[data-scope]").forEach((item) => {
        const active = item === chip;
        item.classList.toggle("is-active", active);
        item.setAttribute("aria-selected", active ? "true" : "false");
      });
      loadThreads({ append: false });
    });

    elements.searchInput.addEventListener("input", () => {
      window.clearTimeout(state.searchTimer);
      state.searchTimer = window.setTimeout(() => {
        state.query = elements.searchInput.value.trim();
        loadThreads({ append: false });
      }, 280);
    });

    elements.loadMoreThreadsButton.addEventListener("click", () => loadThreads({ append: true }));
    elements.openComposeButton.addEventListener("click", () => openEditor("new"));
    elements.editThreadButton.addEventListener("click", () => {
      if (state.thread) openEditor("edit-thread", state.thread);
    });
    elements.copyThreadLinkButton.addEventListener("click", copyThreadLink);
    elements.mobileBackButton.addEventListener("click", handleMobileBack);
    elements.conversation.addEventListener("click", handleConversationClick);

    elements.replyInput.addEventListener("input", () => {
      elements.replyError.textContent = "";
      resizeReplyInput();
      saveReplyDraft();
    });
    elements.replyForm.addEventListener("submit", submitReply);

    elements.editorForm.addEventListener("submit", submitEditor);
    elements.editorContentInput.addEventListener("input", saveEditorDraft);
    elements.editorTitleInput.addEventListener("input", saveEditorDraft);
    elements.editorTabs.addEventListener("click", (event) => {
      const tab = event.target.closest("[data-editor-tab]");
      if (tab) setEditorTab(tab.dataset.editorTab);
    });
    elements.closeEditorButton.addEventListener("click", closeEditor);
    elements.cancelEditorButton.addEventListener("click", closeEditor);
    elements.rebaseEditorDraftButton.addEventListener("click", rebaseEditorDraft);
    elements.editorDialog.addEventListener("click", (event) => {
      if (event.target === elements.editorDialog) closeEditor();
    });

    elements.anonymousToggle.addEventListener("change", toggleAnonymousIdentity);
    elements.refreshIdentityButton.addEventListener("click", () => openIdentityDialog("refresh"));
    elements.aliasInput.addEventListener("input", updateAliasPreview);
    elements.identityForm.addEventListener("submit", saveAnonymousIdentity);
    elements.closeIdentityButton.addEventListener("click", closeIdentityDialog);
    elements.cancelIdentityButton.addEventListener("click", closeIdentityDialog);
    elements.identityDialog.addEventListener("click", (event) => {
      if (event.target === elements.identityDialog) closeIdentityDialog();
    });

    window.addEventListener("popstate", () => {
      const id = currentPathThreadId();
      if (id) {
        selectThread(id, { historyMode: "none", revealMobile: true, force: true });
      } else {
        showMobileDetail(false);
        if (!isMobile() && state.threads.length) {
          selectThread(state.threads[0].id, {
            historyMode: "none",
            revealMobile: false,
            force: state.selectedId !== state.threads[0].id,
          });
        }
      }
    });
  }

  async function initialize() {
    testSessionStorage();
    observeReplyComposerSize();
    bindEvents();

    const requestedThreadId = Number(app.dataset.initialThreadId || currentPathThreadId() || 0);
    try {
      await Promise.all([
        loadIdentity(),
        loadThreads({ append: false, autoSelect: false }),
      ]);
    } catch (_error) {
      return;
    }

    if (!state.storageAvailable) {
      showToast("标签页存储不可用：发帖和回复已暂停，以避免无法恢复的提交", "error");
    }

    if (requestedThreadId > 0) {
      await selectThread(requestedThreadId, {
        historyMode: "none",
        revealMobile: isMobile(),
      });
    } else if (state.threads.length) {
      await selectThread(state.threads[0].id, {
        historyMode: isMobile() ? "none" : "replace",
        revealMobile: false,
      });
    }

    if (app.dataset.openComposer === "true") {
      openEditor("new");
    }
  }

  initialize();
}());
