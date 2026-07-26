(function () {
  'use strict';

  var root = document.getElementById('repositoryWorkbench');
  if (!root) return;

  var MAX_FILE_BYTES = 2 * 1024 * 1024;
  var MAX_REPOSITORY_BYTES = 32 * 1024 * 1024;
  var ACTIVE_INDEX_STORAGE_KEY = 'repositoryIndexJobId';
  var textEncoder = new TextEncoder();
  var pathCollator = new Intl.Collator('zh-CN', {
    numeric: true,
    sensitivity: 'variant',
  });

  var endpoints = {
    tree: root.dataset.treeUrl,
    legacyFiles: root.dataset.filesUrl,
    file: root.dataset.fileUrl,
    directory: root.dataset.directoryUrl,
    entry: root.dataset.entryUrl,
    uploadSession: root.dataset.uploadSessionUrl,
    indexBuild: root.dataset.indexBuildUrl,
    indexCancel: root.dataset.indexCancelUrl,
    indexActive: root.dataset.indexActiveUrl,
    indexStatus: root.dataset.indexStatusUrl,
    indexSearch: root.dataset.indexSearchUrl,
  };

  var elements = {
    tree: document.getElementById('repositoryTree'),
    filesPane: document.getElementById('repositoryFilesPane'),
    fileFilter: document.getElementById('repositoryFileFilter'),
    fileCount: document.getElementById('repositoryFileCount'),
    quota: document.getElementById('repositoryQuota'),
    meta: document.getElementById('repositoryMeta'),
    mobileFiles: document.getElementById('repositoryMobileFiles'),
    drawerBackdrop: document.getElementById('repositoryDrawerBackdrop'),
    newFile: document.getElementById('repositoryNewFile'),
    newDirectory: document.getElementById('repositoryNewDirectory'),
    upload: document.getElementById('repositoryUpload'),
    dropTarget: document.getElementById('repositoryDropTarget'),
    editorTextarea: document.getElementById('repositoryCodeEditor'),
    editorStage: document.getElementById('repositoryEditorStage'),
    monacoHost: document.getElementById('repositoryMonacoContainer'),
    codeMirrorHost: document.getElementById('repositoryCodeMirrorContainer'),
    emptyEditor: document.getElementById('repositoryEmptyEditor'),
    editorLoading: document.getElementById('repositoryEditorLoading'),
    tabExt: document.getElementById('repositoryTabExt'),
    tabName: document.getElementById('repositoryTabName'),
    modified: document.getElementById('repositoryModified'),
    save: document.getElementById('repositorySave'),
    manageCurrent: document.getElementById('repositoryManageCurrent'),
    deleteCurrent: document.getElementById('repositoryDeleteCurrent'),
    breadcrumbs: document.getElementById('repositoryBreadcrumbs'),
    language: document.getElementById('repositoryLanguage'),
    cursor: document.getElementById('repositoryCursor'),
    saveState: document.getElementById('repositorySaveState'),
    outlineList: document.getElementById('repositoryOutlineList'),
    semanticForm: document.getElementById('repositorySemanticForm'),
    semanticQuery: document.getElementById('repositorySemanticQuery'),
    semanticMeta: document.getElementById('repositorySemanticMeta'),
    semanticList: document.getElementById('repositorySemanticList'),
    contextMenu: document.getElementById('repositoryContextMenu'),
    uploadDialog: document.getElementById('repositoryUploadDialog'),
    uploadForm: document.getElementById('repositoryUploadForm'),
    uploadDestination: document.getElementById('repositoryUploadDestination'),
    uploadDropzone: document.getElementById('repositoryUploadDropzone'),
    uploadFiles: document.getElementById('repositoryUploadFiles'),
    uploadFolder: document.getElementById('repositoryUploadFolder'),
    chooseFiles: document.getElementById('repositoryChooseFiles'),
    chooseFolder: document.getElementById('repositoryChooseFolder'),
    uploadQueue: document.getElementById('repositoryUploadQueue'),
    uploadQueueTitle: document.getElementById('repositoryUploadQueueTitle'),
    uploadFileList: document.getElementById('repositoryUploadFileList'),
    uploadSummary: document.getElementById('repositoryUploadSummary'),
    uploadConfirm: document.getElementById('repositoryUploadConfirm'),
    clearUploads: document.getElementById('repositoryClearUploads'),
    moveDialog: document.getElementById('repositoryMoveDialog'),
    moveForm: document.getElementById('repositoryMoveForm'),
    moveTitle: document.getElementById('repositoryMoveTitle'),
    moveName: document.getElementById('repositoryMoveName'),
    moveDestination: document.getElementById('repositoryMoveDestination'),
    moveMergeWrap: document.getElementById('repositoryMoveMergeWrap'),
    moveMerge: document.getElementById('repositoryMoveMerge'),
    deleteDialog: document.getElementById('repositoryDeleteDialog'),
    deleteTitle: document.getElementById('repositoryDeleteTitle'),
    deleteCopy: document.getElementById('repositoryDeleteCopy'),
    deleteConfirm: document.getElementById('repositoryDeleteConfirm'),
    saveConflictDialog: document.getElementById('repositorySaveConflictDialog'),
    saveConflictCopy: document.getElementById('repositorySaveConflictCopy'),
    conflictCopy: document.getElementById('repositoryConflictCopy'),
    conflictDownload: document.getElementById('repositoryConflictDownload'),
    conflictReloadCheck: document.getElementById('repositoryConflictReloadCheck'),
    conflictReloadLabel: document.getElementById('repositoryConflictReloadLabel'),
    conflictReload: document.getElementById('repositoryConflictReload'),
    toast: document.getElementById('repositoryToast'),
    toastTitle: document.getElementById('repositoryToastTitle'),
    toastCopy: document.getElementById('repositoryToastCopy'),
    indexButton: document.getElementById('repositoryIndexButton'),
    indexCancel: document.getElementById('repositoryIndexCancel'),
    indexProgress: document.getElementById('repositoryIndexProgress'),
    indexTitle: document.getElementById('repositoryIndexTitle'),
    indexSubtitle: document.getElementById('repositoryIndexSubtitle'),
    indexDetail: document.getElementById('repositoryIndexDetail'),
    progressBar: document.getElementById('repositoryProgressBar'),
  };

  var state = {
    entries: [],
    entryById: new Map(),
    structureVersion: null,
    quota: {
      maxFileBytes: MAX_FILE_BYTES,
      maxRawFileBytes: MAX_FILE_BYTES * 4 + 4,
      maxRepositoryBytes: MAX_REPOSITORY_BYTES,
      usedBytes: 0,
      maxEntries: 2048,
      maxDepth: 32,
      maxPathBytes: 1024,
    },
    expanded: new Set(),
    focusedDirectoryId: null,
    current: null,
    codeEditor: null,
    editorInitializing: true,
    suppressEditorChanges: false,
    savePromise: null,
    openSequence: 0,
    contextEntryId: null,
    inlineCreate: null,
    moveEntryId: null,
    deleteEntryId: null,
    deletePreview: null,
    draggedEntryId: null,
    treeDropTargetId: undefined,
    externalDragDepth: 0,
    dialogDragDepth: 0,
    saveConflict: null,
    upload: {
      parentId: null,
      items: [],
      sessionId: null,
      previewStructureVersion: null,
      previewing: false,
      previewSequence: 0,
      phase: 'idle',
      progressBytes: 0,
      totalBytes: 0,
      errorMessage: '',
    },
    indexJobId: null,
    indexTimer: null,
    indexHideTimer: null,
    toastTimer: null,
  };

  var indexStageLabels = {
    prepare: '准备文件',
    file_prepare: '文件预处理',
    clang_ast: '解析 clang AST',
    syntax_parse: '解析语法树',
    class_structuring: '整理类声明',
    function_structuring: '整理函数',
    embedding: '生成向量索引',
    persist: '写入工作区',
    file_done: '完成当前文件',
    completed: '整理完成',
    canceling: '正在安全停止',
    canceled: '整理已取消',
    failed: '整理失败',
  };

  function HttpError(message, status, payload) {
    this.name = 'HttpError';
    this.message = message || '请求失败';
    this.status = status || 0;
    this.payload = payload || {};
  }
  HttpError.prototype = Object.create(Error.prototype);

  function requestJson(url, options) {
    var requestOptions = Object.assign({
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    }, options || {});
    if (requestOptions.body && typeof requestOptions.body === 'string') {
      requestOptions.headers = Object.assign(
        { 'Content-Type': 'application/json' },
        requestOptions.headers || {}
      );
    }
    return fetch(url, requestOptions).then(function (response) {
      return response.text().then(function (body) {
        var payload = {};
        if (body) {
          try {
            payload = JSON.parse(body);
          } catch (_error) {
            payload = { message: body };
          }
        }
        if (!response.ok || payload.success === false) {
          throw new HttpError(
            payload.message || ('请求失败（HTTP ' + response.status + '）'),
            response.status,
            payload
          );
        }
        return payload;
      });
    });
  }

  function postJson(url, payload) {
    return requestJson(url, {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (character) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[character];
    });
  }

  function normalizeNfc(value) {
    var text = String(value == null ? '' : value);
    return typeof text.normalize === 'function' ? text.normalize('NFC') : text;
  }

  function normalizeId(value) {
    if (value === null || value === undefined || value === '') return null;
    var number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : null;
  }

  function basename(path) {
    var pieces = String(path || '').split('/');
    return pieces.length ? pieces[pieces.length - 1] : '';
  }

  function dirname(path) {
    var pieces = String(path || '').split('/');
    pieces.pop();
    return pieces.join('/');
  }

  function formatBytes(bytes) {
    var value = Math.max(0, Number(bytes) || 0);
    if (value < 1024) return value + ' B';
    if (value < 1024 * 1024) {
      return (value / 1024).toFixed(value < 10 * 1024 ? 1 : 0) + ' KiB';
    }
    return (value / (1024 * 1024)).toFixed(value < 10 * 1024 * 1024 ? 1 : 0) + ' MiB';
  }

  function byteLength(value) {
    return textEncoder.encode(normalizeNfc(value)).length;
  }

  function validateEntryName(value) {
    var name = normalizeNfc(value);
    if (!name) return { valid: false, name: '', message: '名称不能为空' };
    if (name === '.' || name === '..') {
      return { valid: false, name: name, message: '不能使用 “.” 或 “..” 作为名称' };
    }
    if (/[/\\\0]/.test(name)) {
      return { valid: false, name: name, message: '名称不能包含斜杠、反斜杠或空字符' };
    }
    if (name.endsWith(' ') || name.endsWith('.')) {
      return { valid: false, name: name, message: '名称不能以空格或点结尾' };
    }
    if (/\p{C}/u.test(name)) {
      return { valid: false, name: name, message: '名称不能包含控制字符或格式控制符' };
    }
    var reservedBase = name.split('.', 1)[0].toLocaleUpperCase();
    if (/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(reservedBase)) {
      return { valid: false, name: name, message: '不能使用系统保留名称' };
    }
    var bytes = byteLength(name);
    if (bytes > 255) {
      return { valid: false, name: name, bytes: bytes, message: '名称超过 255 UTF-8 字节' };
    }
    return { valid: true, name: name, bytes: bytes, message: bytes + ' / 255 UTF-8 字节' };
  }

  function validateRelativePath(value, options) {
    var settings = options || {};
    var raw = normalizeNfc(value);
    if (!raw) {
      return settings.allowEmpty
        ? { valid: true, path: '' }
        : { valid: false, path: '', message: '路径不能为空' };
    }
    if (raw.indexOf('\\') >= 0) {
      return { valid: false, path: raw, message: '路径不能包含反斜杠，只接受 POSIX “/”' };
    }
    if (raw.charAt(0) === '/') {
      return { valid: false, path: raw, message: '路径必须是相对路径' };
    }
    var parts = raw.split('/');
    if (parts.some(function (part) { return !part || part === '.' || part === '..'; })) {
      return { valid: false, path: raw, message: '路径不能包含空段、“.” 或 “..”' };
    }
    for (var index = 0; index < parts.length; index += 1) {
      var nameResult = validateEntryName(parts[index]);
      if (!nameResult.valid) {
        return {
          valid: false,
          path: raw,
          message: '路径片段“' + parts[index] + '”无效：' + nameResult.message,
        };
      }
      parts[index] = nameResult.name;
    }
    var normalized = parts.join('/');
    var maxDepth = Number(state && state.quota && state.quota.maxDepth) || 32;
    var maxPathBytes = Number(state && state.quota && state.quota.maxPathBytes) || 1024;
    if (parts.length > maxDepth) {
      return { valid: false, path: normalized, message: '目录深度不能超过 ' + maxDepth + ' 层' };
    }
    if (byteLength(normalized) > maxPathBytes) {
      return {
        valid: false,
        path: normalized,
        message: '仓库路径不能超过 ' + maxPathBytes + ' UTF-8 字节',
      };
    }
    return { valid: true, path: normalized };
  }

  function normalizeRelativePath(path) {
    var result = validateRelativePath(path);
    return result.valid ? result.path : '';
  }

  function showToast(title, message, type) {
    elements.toastTitle.textContent = title;
    elements.toastCopy.textContent = message || '';
    elements.toast.classList.toggle('is-error', type === 'error');
    elements.toast.classList.add('is-visible');
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(function () {
      elements.toast.classList.remove('is-visible');
    }, type === 'error' ? 5200 : 3000);
  }

  function normalizeEntry(raw) {
    var path = normalizeRelativePath(raw.relative_path || raw.path || raw.filename || '');
    var entryId = normalizeId(raw.id != null ? raw.id : raw.entry_id);
    var kind = raw.kind === 'directory' ? 'directory' : 'file';
    var name = normalizeNfc(raw.name || basename(path));
    if (!path) path = name;
    return {
      id: entryId,
      parentId: normalizeId(raw.parent_id),
      name: name,
      path: path,
      kind: kind,
      fileSize: Math.max(0, Number(raw.file_size != null ? raw.file_size : raw.size) || 0),
      version: raw.file_version != null ? raw.file_version : raw.version,
      createdAt: raw.created_at || '',
      updatedAt: raw.updated_at || '',
    };
  }

  function normalizeEntries(payload) {
    var rows = Array.isArray(payload.entries) ? payload.entries : payload.files;
    return (rows || []).map(function (row) {
      var normalized = normalizeEntry(Object.assign({ kind: 'file' }, row));
      if (normalized.parentId == null && !row.parent_id && normalized.path.indexOf('/') >= 0) {
        normalized._legacyPath = true;
      }
      return normalized;
    }).filter(function (entry) {
      return entry.id != null && entry.name;
    });
  }

  function entryForId(entryId) {
    return state.entryById.get(Number(entryId)) || null;
  }

  function directoryLabel(parentId) {
    var entry = entryForId(parentId);
    return entry && entry.kind === 'directory'
      ? 'repository / ' + entry.path
      : 'repository /';
  }

  function actionDirectoryId() {
    var focused = entryForId(state.focusedDirectoryId);
    if (focused && focused.kind === 'directory') return focused.id;
    if (state.current) return state.current.parentId;
    return null;
  }

  function updateRepositorySummary() {
    var files = state.entries.filter(function (entry) { return entry.kind === 'file'; });
    var directories = state.entries.length - files.length;
    var usedBytes = Number(state.quota.usedBytes);
    if (!Number.isFinite(usedBytes) || usedBytes < 0) {
      usedBytes = files.reduce(function (sum, entry) { return sum + entry.fileSize; }, 0);
    }
    elements.fileCount.textContent = files.length + ' FILES';
    elements.meta.textContent =
      files.length + ' FILES · ' + directories + ' DIRS · ' + formatBytes(usedBytes);
    elements.quota.textContent =
      formatBytes(usedBytes) + ' / ' + formatBytes(state.quota.maxRepositoryBytes) +
      ' · ' + formatBytes(state.quota.maxFileBytes) + ' EACH';
  }

  function applyTreePayload(payload) {
    state.entries = normalizeEntries(payload);
    state.entryById = new Map();
    state.entries.forEach(function (entry) {
      state.entryById.set(entry.id, entry);
    });
    if (payload.structure_version !== undefined) {
      state.structureVersion = payload.structure_version;
    }
    var quota = payload.quota || {};
    var maxFileBytes = Number(
      quota.file_bytes || quota.max_file_size_bytes || quota.max_file_bytes || MAX_FILE_BYTES
    );
    state.quota = {
      maxFileBytes: maxFileBytes,
      maxRawFileBytes: Number(
        quota.raw_file_bytes || quota.max_raw_file_bytes || (maxFileBytes * 4 + 4)
      ),
      maxRepositoryBytes: Number(
        quota.total_bytes || quota.max_repository_size_bytes ||
          quota.max_total_bytes || MAX_REPOSITORY_BYTES
      ),
      usedBytes: Number(
        quota.used_bytes != null
          ? quota.used_bytes
          : payload.total_size != null
            ? payload.total_size
            : 0
      ),
      maxEntries: Number(quota.entries || quota.max_entries || 2048),
      maxDepth: Number(quota.depth || quota.max_depth || 32),
      maxPathBytes: Number(quota.path_bytes || quota.max_path_bytes || 1024),
    };
    if (!Number.isFinite(state.quota.usedBytes)) {
      state.quota.usedBytes = state.entries.reduce(function (sum, entry) {
        return sum + (entry.kind === 'file' ? entry.fileSize : 0);
      }, 0);
    }
    if (state.focusedDirectoryId != null && !entryForId(state.focusedDirectoryId)) {
      state.focusedDirectoryId = null;
    }
    if (
      state.inlineCreate &&
      state.inlineCreate.parentId != null &&
      !entryForId(state.inlineCreate.parentId)
    ) {
      state.inlineCreate.parentId = null;
      state.inlineCreate.saving = false;
      state.inlineCreate.error = '原目标目录已不存在，已改为在仓库根目录创建';
    }
    if (state.current) {
      var currentEntry = entryForId(state.current.id);
      if (currentEntry) {
        state.current.name = currentEntry.name;
        state.current.path = currentEntry.path;
        state.current.parentId = currentEntry.parentId;
      }
    }
    updateRepositorySummary();
    renderTree();
    updateEditorChrome();
  }

  function loadTree(options) {
    var settings = options || {};
    return requestJson(endpoints.tree).catch(function (error) {
      if (error.status !== 404 && error.status !== 405) throw error;
      return requestJson(endpoints.legacyFiles).then(function (legacy) {
        return {
          success: true,
          structure_version: null,
          files: legacy.files || [],
          quota: {
            max_file_size_bytes: MAX_FILE_BYTES,
            max_total_bytes: MAX_REPOSITORY_BYTES,
          },
        };
      });
    }).then(function (payload) {
      applyTreePayload(payload);
      if (settings.focusEntryId != null) {
        var focused = entryForId(settings.focusEntryId);
        if (focused && focused.kind === 'directory') {
          state.focusedDirectoryId = focused.id;
          state.expanded.add(String(focused.id));
          renderTree();
        }
      }
      return payload;
    }).catch(function (error) {
      elements.tree.innerHTML =
        '<div class="repository-tree-empty">仓库加载失败。<br>' +
        escapeHtml(error.message) + '</div>';
      showToast('仓库加载失败', error.message, 'error');
      throw error;
    });
  }

  function refreshTreeBestEffort() {
    return loadTree().catch(function () {
      // loadTree 已呈现具体错误，这里只避免产生未处理的 Promise rejection。
      return null;
    });
  }

  function childrenMap() {
    var byParent = new Map();
    state.entries.forEach(function (entry) {
      var key = entry.parentId == null ? 'root' : String(entry.parentId);
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(entry);
    });
    byParent.forEach(function (children) {
      children.sort(function (left, right) {
        if (left.kind !== right.kind) return left.kind === 'directory' ? -1 : 1;
        return pathCollator.compare(left.name, right.name);
      });
    });
    return byParent;
  }

  function matchingEntryIds(query) {
    if (!query) return null;
    var matches = new Set();
    state.entries.forEach(function (entry) {
      if (entry.path.toLocaleLowerCase().indexOf(query) >= 0) {
        matches.add(entry.id);
        var parentId = entry.parentId;
        while (parentId != null) {
          matches.add(parentId);
          var parent = entryForId(parentId);
          parentId = parent ? parent.parentId : null;
        }
      }
    });
    return matches;
  }

  function markedName(name, query) {
    var safeName = String(name);
    if (!query) return escapeHtml(safeName);
    var lower = safeName.toLocaleLowerCase();
    var index = lower.indexOf(query);
    if (index < 0) return escapeHtml(safeName);
    return escapeHtml(safeName.slice(0, index)) +
      '<mark>' + escapeHtml(safeName.slice(index, index + query.length)) + '</mark>' +
      escapeHtml(safeName.slice(index + query.length));
  }

  function treeRow(entry, depth, hasChildren, query) {
    var isDirectory = entry.kind === 'directory';
    var expanded = isDirectory && state.expanded.has(String(entry.id));
    var active = state.current && state.current.id === entry.id;
    var selected = isDirectory && state.focusedDirectoryId === entry.id;
    var directSearchHit = !!query &&
      entry.path.toLocaleLowerCase().indexOf(query) >= 0;
    var visibleLabel = directSearchHit ? entry.path : entry.name;
    var classes = [
      'repository-tree-row',
      expanded ? 'is-expanded' : '',
      active || selected ? 'is-active' : '',
      directSearchHit ? 'is-search-hit' : '',
    ].filter(Boolean).join(' ');
    var ariaExpanded = isDirectory ? ' aria-expanded="' + (expanded ? 'true' : 'false') + '"' : '';
    return (
      '<div class="' + classes + '" style="--tree-depth:' + depth +
        ';--tree-indent:' + (Math.min(depth, 8) * 13) + 'px"' +
        ' data-entry-id="' + entry.id + '" data-entry-kind="' + entry.kind + '"' +
        ' role="treeitem" aria-level="' + (depth + 1) + '"' + ariaExpanded +
        ' draggable="true" title="' + escapeHtml(entry.path) + '">' +
        '<button class="repository-tree-toggle' + (!isDirectory || !hasChildren ? ' is-placeholder' : '') + '"' +
          ' type="button" data-tree-toggle="' + entry.id + '" tabindex="' + (isDirectory && hasChildren ? '0' : '-1') + '"' +
          ' aria-label="' + (expanded ? '折叠目录' : '展开目录') + '">' +
          '<svg class="repository-icon"><use href="#repo-icon-chevron"></use></svg>' +
        '</button>' +
        '<span class="repository-tree-glyph ' + (isDirectory ? '' : 'file') + '">' +
          '<svg class="repository-icon"><use href="#repo-icon-' + (isDirectory ? 'folder' : 'file') + '"></use></svg>' +
        '</span>' +
        '<button class="repository-tree-main" type="button" data-tree-open="' + entry.id + '">' +
          '<span class="repository-tree-name' + (directSearchHit ? ' is-path' : '') + '">' +
            markedName(visibleLabel, query) +
          '</span>' +
        '</button>' +
        '<button class="repository-tree-menu" type="button" data-tree-menu="' + entry.id + '"' +
          ' aria-label="' + escapeHtml(entry.name) + ' 的操作菜单">' +
          '<svg class="repository-icon"><use href="#repo-icon-more"></use></svg>' +
        '</button>' +
      '</div>'
    );
  }

  function inlineCreateRow(depth) {
    var draft = state.inlineCreate;
    if (!draft) return '';
    var isDirectory = draft.kind === 'directory';
    return (
      '<div class="repository-tree-row repository-tree-inline' +
        (draft.error ? ' is-invalid' : '') +
        '" style="--tree-depth:' + depth +
        ';--tree-indent:' + (Math.min(depth, 8) * 13) +
        'px" role="treeitem" aria-level="' + (depth + 1) + '">' +
        '<span class="repository-tree-toggle is-placeholder"></span>' +
        '<span class="repository-tree-glyph ' + (isDirectory ? '' : 'file') + '">' +
          '<svg class="repository-icon"><use href="#repo-icon-' +
            (isDirectory ? 'folder' : 'file') + '"></use></svg>' +
        '</span>' +
        '<span class="repository-tree-inline-field">' +
          '<input data-tree-inline-create type="text" maxlength="255" autocomplete="off"' +
            ' aria-label="' + (isDirectory ? '新目录名称' : '新文件名称') + '"' +
            ' aria-invalid="' + (draft.error ? 'true' : 'false') + '"' +
            ' placeholder="' + (isDirectory ? '新建目录' : 'untitled.txt') + '"' +
            ' value="' + escapeHtml(draft.value || '') + '"' +
            (draft.saving ? ' disabled' : '') + '>' +
          (draft.error
            ? '<small role="alert">' + escapeHtml(draft.error) + '</small>'
            : '<small>Enter 创建 · Esc 取消</small>') +
        '</span>' +
        '<span class="repository-tree-inline-status">' +
          (draft.saving ? '…' : '') +
        '</span>' +
      '</div>'
    );
  }

  function renderTree() {
    var query = normalizeNfc(elements.fileFilter.value).trim().toLocaleLowerCase();
    var visibleIds = matchingEntryIds(query);
    var byParent = childrenMap();
    var rows = [];

    function walk(parentId, depth) {
      var key = parentId == null ? 'root' : String(parentId);
      var children = byParent.get(key) || [];
      if (
        !query &&
        state.inlineCreate &&
        state.inlineCreate.parentId === parentId
      ) {
        rows.push(inlineCreateRow(depth));
      }
      children.forEach(function (entry) {
        if (visibleIds && !visibleIds.has(entry.id)) return;
        var nested = byParent.get(String(entry.id)) || [];
        rows.push(treeRow(entry, depth, nested.length > 0, query));
        if (
          entry.kind === 'directory' &&
          (query || state.expanded.has(String(entry.id)))
        ) {
          walk(entry.id, depth + 1);
        }
      });
    }

    walk(null, 0);
    elements.tree.innerHTML = rows.length
      ? rows.join('')
      : '<div class="repository-tree-empty">' +
          (query ? '没有匹配的文件或目录。' : '仓库还是空的。<br>新建文件、目录，或拖入本地文件夹。') +
        '</div>';
    var inlineInput = elements.tree.querySelector('[data-tree-inline-create]');
    if (inlineInput && !state.inlineCreate.saving) {
      window.requestAnimationFrame(function () {
        inlineInput.focus();
        inlineInput.setSelectionRange(inlineInput.value.length, inlineInput.value.length);
      });
    }
  }

  function fallbackLanguageForFilename(filename) {
    var extension = String(filename || '').split('.').pop().toLocaleLowerCase();
    var modes = {
      c: {
        language: 'c',
        monacoLanguage: 'c',
        codeMirrorMode: 'text/x-csrc',
        label: 'C Source',
      },
      h: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Header',
      },
      cc: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Source',
      },
      cpp: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Source',
      },
      cxx: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Source',
      },
      hpp: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Header',
      },
      hxx: {
        language: 'cpp',
        monacoLanguage: 'cpp',
        codeMirrorMode: 'text/x-c++src',
        label: 'C++ Header',
      },
      py: {
        language: 'python',
        monacoLanguage: 'python',
        codeMirrorMode: 'python',
        label: 'Python',
      },
      m: {
        language: 'matlab',
        monacoLanguage: 'matlab',
        codeMirrorMode: 'octave',
        label: 'MATLAB / Octave',
      },
    };
    return modes[extension] || {
      language: null,
      monacoLanguage: 'plaintext',
      codeMirrorMode: null,
      label: 'Plain Text',
    };
  }

  function languageForFilename(filename) {
    var runtime = window.NumOJCodeEditorRuntime;
    return runtime
      ? runtime.forFilename(filename)
      : fallbackLanguageForFilename(filename);
  }

  async function createMonacoEditor() {
    var monaco = window.NumericalOJMonaco;
    var runtime = window.NumOJCodeEditorRuntime;
    if (!monaco || !monaco.editor || !runtime || !elements.monacoHost) {
      return null;
    }

    var theme = await runtime.prepareMonaco(monaco);
    elements.monacoHost.hidden = false;
    var initialModel = monaco.editor.createModel(
      '',
      'plaintext',
      monaco.Uri.parse('inmemory://repository/workspace')
    );
    var instance = monaco.editor.create(
      elements.monacoHost,
      runtime.monacoOptions({
        model: initialModel,
        theme: theme,
        ariaLabel: '代码仓库编辑器输入区',
        wordWrap: 'off',
      })
    );
    var semanticProviders = Object.create(null);
    var locatedDecorations = new Map();

    instance.addCommand(
      monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS,
      function () { void saveCurrentFile(); }
    );
    runtime.protectEditorInput(
      instance.getDomNode() &&
        instance.getDomNode().querySelector('textarea.inputarea'),
      'repository_editor_input',
      '代码仓库编辑器输入区'
    );

    function ensureSemanticProvider(spec) {
      if (
        !spec.language ||
        semanticProviders[spec.language] ||
        !window.NumOJSemanticTokens
      ) {
        return;
      }
      semanticProviders[spec.language] = true;
      window.NumOJSemanticTokens.register(monaco, {
        context: 'repository',
        documentId: function (model) {
          var pieces = String(model && model.uri && model.uri.path || '')
            .split('/')
            .filter(Boolean);
          return pieces.pop() || 'workspace';
        },
        language: spec.language,
        monacoLanguage: spec.monacoLanguage,
      }).then(function (disposable) {
        semanticProviders[spec.language] = disposable || true;
      }).catch(function (error) {
        delete semanticProviders[spec.language];
        console.warn('仓库语言服务初始化失败，已保留 TextMate 着色。', error);
      });
    }

    return {
      kind: 'monaco',
      getValue: function () { return instance.getValue(); },
      setValue: function (value) { instance.setValue(String(value || '')); },
      clearHistory: function () {},
      getWrapperElement: function () { return elements.monacoHost; },
      getInputField: function () {
        return instance.getDomNode() &&
          instance.getDomNode().querySelector('textarea.inputarea');
      },
      setSize: function () { instance.layout(); },
      refresh: function () { instance.layout(); },
      focus: function () { instance.focus(); },
      on: function (eventName, handler) {
        if (eventName === 'change') {
          return instance.onDidChangeModelContent(handler);
        }
        if (eventName === 'cursorActivity') {
          return instance.onDidChangeCursorPosition(handler);
        }
        return { dispose: function () {} };
      },
      setLanguage: function (spec, documentId) {
        ensureSemanticProvider(spec);
        var model = instance.getModel();
        var safeDocumentId = String(documentId || 'workspace');
        var targetUri = monaco.Uri.parse(
          'inmemory://repository/' + safeDocumentId
        );
        if (model && model.uri.toString() !== targetUri.toString()) {
          var previousModel = model;
          model = monaco.editor.createModel(
            '',
            spec.monacoLanguage,
            targetUri
          );
          instance.setModel(model);
          previousModel.dispose();
          return;
        }
        if (model) monaco.editor.setModelLanguage(model, spec.monacoLanguage);
      },
      getCursor: function () {
        var position = instance.getPosition() || { lineNumber: 1, column: 1 };
        return { line: position.lineNumber - 1, ch: position.column - 1 };
      },
      lineCount: function () {
        var model = instance.getModel();
        return model ? model.getLineCount() : 1;
      },
      setCursor: function (position) {
        instance.setPosition({
          lineNumber: Number(position.line || 0) + 1,
          column: Number(position.ch || 0) + 1,
        });
      },
      scrollIntoView: function (position) {
        instance.revealLineInCenterIfOutsideViewport(
          Number(position.line || 0) + 1
        );
      },
      addLineClass: function (line, _where, className) {
        var existing = locatedDecorations.get(line);
        if (existing) existing.clear();
        var collection = instance.createDecorationsCollection([{
          range: new monaco.Range(line + 1, 1, line + 1, 1),
          options: {
            isWholeLine: true,
            className: className,
          },
        }]);
        locatedDecorations.set(line, collection);
      },
      removeLineClass: function (line) {
        var collection = locatedDecorations.get(line);
        if (collection) collection.clear();
        locatedDecorations.delete(line);
      },
    };
  }

  function createCodeMirrorEditor() {
    var runtime = window.NumOJCodeEditorRuntime;
    if (!window.CodeMirror || !elements.codeMirrorHost) return null;
    elements.codeMirrorHost.hidden = false;
    var instance = window.CodeMirror(elements.codeMirrorHost, {
      value: '',
      mode: null,
      theme: 'eclipse',
      lineNumbers: true,
      lineWrapping: false,
      indentUnit: 4,
      tabSize: 4,
      autofocus: false,
      extraKeys: {
        Tab: function (editor) {
          if (editor.somethingSelected()) {
            editor.indentSelection('add');
          } else {
            editor.replaceSelection('    ', 'end');
          }
        },
        'Shift-Tab': 'indentLess',
        'Ctrl-S': function () { void saveCurrentFile(); },
        'Cmd-S': function () { void saveCurrentFile(); },
      },
    });
    if (runtime) {
      runtime.protectEditorInput(
        instance.getInputField(),
        'repository_editor_input',
        '代码仓库编辑器输入区'
      );
    }
    instance.setSize(null, '100%');
    return {
      kind: 'codemirror',
      getValue: function () { return instance.getValue(); },
      setValue: function (value) { instance.setValue(String(value || '')); },
      clearHistory: function () { instance.clearHistory(); },
      getWrapperElement: function () { return elements.codeMirrorHost; },
      getInputField: function () { return instance.getInputField(); },
      setSize: function () { instance.setSize(null, '100%'); },
      refresh: function () { instance.refresh(); },
      focus: function () { instance.focus(); },
      on: function (eventName, handler) { instance.on(eventName, handler); },
      setLanguage: function (spec) {
        instance.setOption('mode', spec.codeMirrorMode);
      },
      getCursor: function () { return instance.getCursor(); },
      lineCount: function () { return instance.lineCount(); },
      setCursor: function (position) { instance.setCursor(position); },
      scrollIntoView: function (position, margin) {
        instance.scrollIntoView(position, margin);
      },
      addLineClass: function (line, where, className) {
        instance.addLineClass(line, where, className);
      },
      removeLineClass: function (line, where, className) {
        instance.removeLineClass(line, where, className);
      },
    };
  }

  function createTextareaEditor() {
    var textarea = elements.editorTextarea;
    var runtime = window.NumOJCodeEditorRuntime;
    textarea.style.display = 'block';
    if (runtime) {
      runtime.protectEditorInput(
        textarea,
        'repository_editor_input',
        '代码仓库编辑器输入区'
      );
    }
    textarea.addEventListener('keydown', function (event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
        event.preventDefault();
        void saveCurrentFile();
      }
    });
    return {
      kind: 'textarea',
      getValue: function () { return textarea.value; },
      setValue: function (value) { textarea.value = String(value || ''); },
      clearHistory: function () {},
      getWrapperElement: function () { return textarea; },
      getInputField: function () { return textarea; },
      setSize: function () {},
      refresh: function () {},
      focus: function () { textarea.focus(); },
      on: function (eventName, handler) {
        if (eventName === 'change') textarea.addEventListener('input', handler);
        if (eventName === 'cursorActivity') {
          ['input', 'keyup', 'click'].forEach(function (name) {
            textarea.addEventListener(name, handler);
          });
        }
      },
      setLanguage: function () {},
      getCursor: function () {
        var before = textarea.value.slice(0, textarea.selectionStart || 0);
        var lines = before.split('\n');
        return {
          line: lines.length - 1,
          ch: lines[lines.length - 1].length,
        };
      },
      lineCount: function () { return textarea.value.split('\n').length; },
      setCursor: function (position) {
        var lines = textarea.value.split('\n');
        var line = Math.max(0, Math.min(Number(position.line) || 0, lines.length - 1));
        var offset = 0;
        for (var index = 0; index < line; index += 1) {
          offset += lines[index].length + 1;
        }
        offset += Math.min(Number(position.ch) || 0, lines[line].length);
        textarea.setSelectionRange(offset, offset);
      },
      scrollIntoView: function () {},
      addLineClass: function () {},
      removeLineClass: function () {},
    };
  }

  async function initializeEditor() {
    var desktop = window.matchMedia('(min-width: 992px)').matches;
    var editor = null;
    if (desktop && window.NumOJMonacoReady) {
      try {
        await window.NumOJMonacoReady;
        editor = await createMonacoEditor();
      } catch (error) {
        console.warn('仓库 Monaco 编辑器初始化失败，准备降级。', error);
      }
    } else if (!desktop && window.NumOJCodeMirrorReady) {
      try {
        await window.NumOJCodeMirrorReady;
        editor = createCodeMirrorEditor();
      } catch (error) {
        console.warn('仓库移动端编辑器初始化失败，准备降级。', error);
      }
    }
    if (!editor) {
      editor = createTextareaEditor();
      showToast(
        '编辑器已降级',
        '高级编辑器资源不可用，仍可使用基础文本编辑器。',
        'error'
      );
    }

    state.codeEditor = editor;
    state.editorInitializing = false;
    editor.getWrapperElement().hidden = true;
    editor.on('change', function () {
      if (state.suppressEditorChanges || !state.current) return;
      state.current.editRevision += 1;
      state.current.content = editor.getValue();
      state.current.dirty = state.current.content !== state.current.savedContent;
      updateEditorChrome();
      renderOutline();
    });
    editor.on('cursorActivity', updateCursorStatus);
    if (state.current) {
      setEditorContent(state.current.content, state.current.name);
    }
    updateEditorChrome();
  }

  function extensionLabel(filename) {
    var pieces = String(filename || '').split('.');
    if (pieces.length <= 1) return 'TXT';
    var extension = pieces.pop().toLocaleUpperCase();
    return extension.length <= 5 ? extension : 'TEXT';
  }

  function updateBreadcrumbs() {
    if (!state.current) {
      elements.breadcrumbs.innerHTML =
        '<span>repository</span><span>›</span><b>选择一个文件开始编辑</b>';
      return;
    }
    var pieces = state.current.path.split('/').filter(Boolean);
    var html = ['<span>repository</span>'];
    pieces.forEach(function (piece, index) {
      html.push('<span>›</span>');
      html.push(index === pieces.length - 1
        ? '<b>' + escapeHtml(piece) + '</b>'
        : '<span>' + escapeHtml(piece) + '</span>');
    });
    elements.breadcrumbs.innerHTML = html.join('');
  }

  function updateEditorChrome() {
    var current = state.current;
    var hasFile = !!current;
    elements.emptyEditor.hidden = hasFile;
    elements.editorLoading.hidden =
      !hasFile || !state.editorInitializing;
    elements.tabExt.textContent = hasFile ? extensionLabel(current.name) : '—';
    elements.tabName.textContent = hasFile ? current.path : '尚未打开文件';
    elements.modified.hidden = !hasFile || !current.dirty;
    elements.save.disabled = !hasFile || !!state.savePromise;
    elements.manageCurrent.disabled = !hasFile || !!state.savePromise;
    elements.deleteCurrent.disabled = !hasFile || !!state.savePromise;
    elements.language.textContent = hasFile
      ? languageForFilename(current.name).label.toUpperCase()
      : 'NO FILE';
    elements.saveState.textContent = !hasFile
      ? 'IDLE'
      : state.savePromise
        ? 'SAVING'
        : current.dirty
          ? 'UNSAVED'
          : 'SAVED';
    updateBreadcrumbs();
    updateCursorStatus();
  }

  function updateCursorStatus() {
    if (!state.current || !state.codeEditor) {
      elements.cursor.textContent = 'Ln —, Col —';
      return;
    }
    var cursor = state.codeEditor.getCursor();
    elements.cursor.textContent = 'Ln ' + (cursor.line + 1) + ', Col ' + (cursor.ch + 1);
  }

  function setEditorContent(content, filename) {
    if (!state.codeEditor) return;
    state.suppressEditorChanges = true;
    state.codeEditor.setLanguage(
      languageForFilename(filename),
      state.current ? 'entry-' + state.current.id : 'workspace'
    );
    state.codeEditor.setValue(content || '');
    state.codeEditor.clearHistory();
    state.codeEditor.getWrapperElement().hidden = false;
    state.suppressEditorChanges = false;
    window.requestAnimationFrame(function () {
      state.codeEditor.refresh();
      state.codeEditor.setCursor({ line: 0, ch: 0 });
    });
  }

  function clearEditor() {
    state.current = null;
    if (state.codeEditor) {
      state.suppressEditorChanges = true;
      state.codeEditor.setValue('');
      state.codeEditor.clearHistory();
      state.codeEditor.getWrapperElement().hidden = true;
      state.suppressEditorChanges = false;
    }
    updateEditorChrome();
    renderOutline();
    renderTree();
  }

  function openSaveConflictDialog(snapshot, error) {
    if (!state.current || state.current.id !== snapshot.id) return;
    state.saveConflict = {
      snapshot: snapshot,
      message: error.message,
      missing: error.status === 404 ||
        (error.payload && error.payload.code === 'not_found'),
    };
    elements.saveConflictCopy.innerHTML = state.saveConflict.missing
      ? '文件 <strong>' + escapeHtml(snapshot.path) +
        '</strong> 已在其他位置被删除。当前本地修改仍保留在编辑器中；' +
        '请先复制或下载本地内容，或明确放弃后关闭该文件。'
      : '文件 <strong>' + escapeHtml(snapshot.path) +
        '</strong> 的服务端版本已变化。当前本地修改仍保留在编辑器中；' +
        '请先复制或下载本地内容，或明确放弃后重新载入服务端版本。';
    elements.conflictReloadCheck.checked = false;
    elements.conflictReload.disabled = true;
    elements.conflictReloadLabel.textContent = state.saveConflict.missing
      ? '我确认丢弃当前本地修改，并关闭已被删除的文件'
      : '我确认丢弃当前本地修改，并重新载入服务端版本';
    elements.conflictReload.textContent = state.saveConflict.missing
      ? '丢弃本地修改并关闭'
      : '丢弃本地修改并重新载入';
    showDialog(elements.saveConflictDialog);
  }

  function resolveSaveConflictByBackup(mode) {
    var conflict = state.saveConflict;
    if (!conflict) return;
    var snapshot = conflict.snapshot;
    var finish = function () {
      if (state.current && state.current.id === snapshot.id) clearEditor();
      state.saveConflict = null;
      closeDialog(elements.saveConflictDialog);
      void refreshTreeBestEffort();
      showToast(
        mode === 'copy' ? '本地内容已复制' : '本地副本已下载',
        '当前冲突文件已关闭，服务端内容未被覆盖。'
      );
    };
    if (mode === 'copy') {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        showToast('无法访问剪贴板', '请使用“下载本地副本”。', 'error');
        return;
      }
      navigator.clipboard.writeText(snapshot.content).then(finish).catch(function () {
        showToast('复制失败', '浏览器拒绝了剪贴板权限，请改用下载。', 'error');
      });
      return;
    }
    var blob = new Blob([snapshot.content], { type: 'text/plain;charset=utf-8' });
    var objectUrl = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = objectUrl;
    link.download = basename(snapshot.path) + '.local-conflict';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(objectUrl); }, 0);
    finish();
  }

  function reloadServerAfterConflict() {
    var conflict = state.saveConflict;
    if (!conflict || !elements.conflictReloadCheck.checked) return;
    var snapshot = conflict.snapshot;
    elements.conflictReload.disabled = true;
    elements.conflictReload.textContent = conflict.missing ? '正在关闭…' : '正在重新载入…';
    if (conflict.missing) {
      clearEditor();
      state.saveConflict = null;
      closeDialog(elements.saveConflictDialog);
      void refreshTreeBestEffort();
      showToast('本地修改已丢弃', '服务端文件已不存在，编辑器已关闭。');
      return;
    }
    requestJson(endpoints.file + '/' + encodeURIComponent(snapshot.id)).then(function (payload) {
      if (!state.current || state.current.id !== snapshot.id) return;
      var latest = entryForId(snapshot.id) || {};
      var rawPath = payload.relative_path || payload.path || payload.filename || latest.path;
      state.current = {
        id: snapshot.id,
        parentId: normalizeId(payload.parent_id != null ? payload.parent_id : latest.parentId),
        name: normalizeNfc(payload.name || latest.name || basename(rawPath)),
        path: normalizeRelativePath(rawPath),
        content: String(payload.content == null ? '' : payload.content),
        savedContent: String(payload.content == null ? '' : payload.content),
        dirty: false,
        editRevision: 0,
        version: payload.file_version != null ? payload.file_version : latest.version,
      };
      state.focusedDirectoryId = state.current.parentId;
      state.saveConflict = null;
      setEditorContent(state.current.content, state.current.name);
      updateEditorChrome();
      renderTree();
      renderOutline();
      closeDialog(elements.saveConflictDialog);
      showToast('已重新载入', state.current.path);
      void loadTree().then(function () {
        expandAncestors(entryForId(snapshot.id));
        renderTree();
      }).catch(function () {
        // loadTree 已在页面内呈现错误；冲突本身已经解除。
      });
    }).catch(function (error) {
      if (
        error.status === 404 ||
        (error.payload && error.payload.code === 'not_found')
      ) {
        clearEditor();
        state.saveConflict = null;
        closeDialog(elements.saveConflictDialog);
        void refreshTreeBestEffort();
        showToast('文件已被删除', '本地修改已丢弃，编辑器已关闭。');
        return;
      }
      showToast('重新载入失败', error.message, 'error');
    }).finally(function () {
      if (state.saveConflict) {
        elements.conflictReload.textContent = '丢弃本地修改并重新载入';
        elements.conflictReload.disabled = !elements.conflictReloadCheck.checked;
      }
    });
  }

  function saveCurrentFile(options) {
    var settings = options || {};
    if (!state.current || !state.current.dirty) return Promise.resolve(true);
    if (state.savePromise) {
      return state.savePromise.then(function (saved) {
        if (!saved || !state.current || !state.current.dirty) return saved;
        return saveCurrentFile(Object.assign({}, settings, { drain: true }));
      });
    }

    var snapshot = {
      id: state.current.id,
      name: state.current.name,
      path: state.current.path,
      parentId: state.current.parentId,
      content: state.codeEditor
        ? state.codeEditor.getValue()
        : state.current.content,
      version: state.current.version,
      editRevision: state.current.editRevision,
    };
    var snapshotBytes = textEncoder.encode(snapshot.content).length;
    if (snapshotBytes > state.quota.maxFileBytes) {
      showToast(
        '文件无法保存',
        '规范化 UTF-8 内容为 ' + formatBytes(snapshotBytes) +
          '，超过单文件 ' + formatBytes(state.quota.maxFileBytes) + ' 限制。',
        'error'
      );
      return Promise.resolve(false);
    }
    state.savePromise = postJson(endpoints.file, {
      file_id: snapshot.id,
      parent_id: snapshot.parentId,
      name: snapshot.name,
      filename: snapshot.path,
      content: snapshot.content,
      expected_structure_version: state.structureVersion,
      expected_file_version: snapshot.version,
    }).then(function (payload) {
      if (!state.current || state.current.id !== snapshot.id) return true;
      var savedEntry = payload.entry || {};
      var previousStructureVersion = state.structureVersion;
      var savedPath = normalizeRelativePath(
        savedEntry.relative_path || savedEntry.path || snapshot.path
      ) || snapshot.path;
      var savedName = normalizeNfc(savedEntry.name || basename(savedPath) || snapshot.name);
      var savedParentId = savedEntry.parent_id !== undefined
        ? normalizeId(savedEntry.parent_id)
        : snapshot.parentId;
      var requiresTreeRefresh =
        savedPath !== snapshot.path ||
        savedName !== snapshot.name ||
        savedParentId !== snapshot.parentId ||
        (
          payload.structure_version != null &&
          previousStructureVersion != null &&
          Number(payload.structure_version) !== Number(previousStructureVersion)
        );
      var latestContent = state.codeEditor
        ? state.codeEditor.getValue()
        : state.current.content;
      state.current.savedContent = snapshot.content;
      state.current.content = latestContent;
      state.current.dirty =
        state.current.editRevision !== snapshot.editRevision ||
        latestContent !== snapshot.content;
      state.current.path = savedPath;
      state.current.name = savedName;
      state.current.parentId = savedParentId;
      if (state.focusedDirectoryId === snapshot.parentId) {
        state.focusedDirectoryId = savedParentId;
      }
      if (savedEntry.file_version != null) state.current.version = savedEntry.file_version;
      else if (payload.file_version != null) state.current.version = payload.file_version;
      else if (payload.version != null) state.current.version = payload.version;
      if (payload.structure_version != null) state.structureVersion = payload.structure_version;
      var entry = entryForId(snapshot.id);
      if (entry) {
        var previousSize = entry.fileSize;
        entry.path = savedPath;
        entry.name = savedName;
        entry.parentId = savedParentId;
        entry.fileSize = Number(savedEntry.file_size != null
          ? savedEntry.file_size
          : textEncoder.encode(snapshot.content).length);
        state.quota.usedBytes += entry.fileSize - previousSize;
        if (state.current.version != null) entry.version = state.current.version;
      }
      updateRepositorySummary();
      renderTree();
      if (state.codeEditor) {
        state.codeEditor.setLanguage(
          languageForFilename(savedName),
          state.current ? 'entry-' + state.current.id : 'workspace'
        );
      }
      var refreshed = requiresTreeRefresh
        ? loadTree().catch(function () { return null; })
        : Promise.resolve();
      return refreshed.then(function () {
        if (requiresTreeRefresh) {
          expandAncestors(entryForId(snapshot.id));
          renderTree();
        }
        if (!settings.silent) showToast('文件已保存', savedPath);
        return true;
      });
    }).catch(function (error) {
      if (
        error.status === 409 ||
        error.status === 404 ||
        (error.payload && error.payload.code === 'not_found')
      ) {
        var latestSnapshot = snapshot;
        if (state.current && state.current.id === snapshot.id) {
          latestSnapshot = Object.assign({}, snapshot, {
            name: state.current.name,
            path: state.current.path,
            parentId: state.current.parentId,
            content: state.codeEditor
              ? state.codeEditor.getValue()
              : state.current.content,
            editRevision: state.current.editRevision,
          });
        }
        openSaveConflictDialog(latestSnapshot, error);
      } else {
        showToast('保存失败', error.message, 'error');
      }
      return false;
    }).finally(function () {
      state.savePromise = null;
      updateEditorChrome();
    });
    updateEditorChrome();
    return state.savePromise.then(function (saved) {
      if (
        !saved ||
        !settings.drain ||
        !state.current ||
        !state.current.dirty
      ) {
        return saved;
      }
      return saveCurrentFile(settings);
    });
  }

  function persistBeforeTransition() {
    if (state.saveConflict) {
      showDialog(elements.saveConflictDialog);
      return Promise.resolve(false);
    }
    if (!state.current || !state.current.dirty) return Promise.resolve(true);
    return saveCurrentFile({ silent: true, drain: true });
  }

  function openFile(entryId, options) {
    var settings = options || {};
    var entry = entryForId(entryId);
    if (!entry || entry.kind !== 'file') return Promise.resolve(false);
    if (state.current && state.current.id === entry.id) {
      if (settings.line) revealLine(settings.line);
      closeFilesDrawer();
      return Promise.resolve(true);
    }
    var sequence = ++state.openSequence;
    return persistBeforeTransition().then(function (saved) {
      if (!saved || sequence !== state.openSequence) return false;
      elements.saveState.textContent = 'LOADING';
      return requestJson(endpoints.file + '/' + encodeURIComponent(entry.id)).then(function (payload) {
        if (sequence !== state.openSequence) return false;
        var latest = entryForId(entry.id) || entry;
        state.current = {
          id: entry.id,
          parentId: normalizeId(payload.parent_id != null ? payload.parent_id : latest.parentId),
          name: normalizeNfc(payload.name || latest.name || basename(payload.filename)),
          path: normalizeRelativePath(
            payload.relative_path || payload.path || latest.path || payload.filename
          ),
          content: String(payload.content == null ? '' : payload.content),
          savedContent: String(payload.content == null ? '' : payload.content),
          dirty: false,
          editRevision: 0,
          version: payload.file_version != null
            ? payload.file_version
            : payload.version != null
              ? payload.version
              : latest.version,
        };
        state.focusedDirectoryId = state.current.parentId;
        expandAncestors(latest);
        setEditorContent(state.current.content, state.current.name);
        updateEditorChrome();
        renderTree();
        renderOutline();
        closeFilesDrawer();
        if (settings.line) {
          window.requestAnimationFrame(function () { revealLine(settings.line); });
        }
        return true;
      });
    }).catch(function (error) {
      showToast('打开文件失败', error.message, 'error');
      updateEditorChrome();
      return false;
    });
  }

  function expandAncestors(entry) {
    var parentId = entry ? entry.parentId : null;
    while (parentId != null) {
      state.expanded.add(String(parentId));
      var parent = entryForId(parentId);
      parentId = parent ? parent.parentId : null;
    }
  }

  function outlineSymbols(content, filename) {
    var symbols = [];
    var extension = String(filename || '').split('.').pop().toLocaleLowerCase();
    String(content || '').split('\n').forEach(function (line, index) {
      var match;
      if (extension === 'py') {
        match = line.match(/^\s*class\s+([A-Za-z_]\w*)/);
        if (match) symbols.push({ type: 'C', kind: 'class', name: match[1], line: index + 1 });
        match = line.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
        if (match) symbols.push({ type: 'ƒ', kind: 'function', name: match[1], line: index + 1 });
        return;
      }
      if (extension === 'm') {
        match = line.match(/^\s*function\s+(?:\[[^\]]+\]\s*=\s*|\w+\s*=\s*)?([A-Za-z_]\w*)/i);
        if (match) symbols.push({ type: 'ƒ', kind: 'function', name: match[1], line: index + 1 });
        match = line.match(/^\s*classdef\s+([A-Za-z_]\w*)/i);
        if (match) symbols.push({ type: 'C', kind: 'class', name: match[1], line: index + 1 });
        return;
      }
      match = line.match(/^\s*(?:struct|class)\s+([A-Za-z_]\w*)/);
      if (match) symbols.push({ type: 'T', kind: 'type', name: match[1], line: index + 1 });
      match = line.match(/^\s*namespace\s+([A-Za-z_]\w*)/);
      if (match) symbols.push({ type: 'N', kind: 'namespace', name: match[1], line: index + 1 });
      match = line.match(
        /^\s*(?:(?:inline|static|constexpr|virtual|extern)\s+)*(?:[\w:<>*&,\s]+)\s+([A-Za-z_~]\w*)\s*\([^;]*\)\s*(?:const)?\s*(?:\{|$)/
      );
      if (match && !/^(if|for|while|switch|catch)$/.test(match[1])) {
        symbols.push({ type: 'ƒ', kind: 'function', name: match[1], line: index + 1 });
      }
    });
    return symbols.slice(0, 300);
  }

  function renderOutline() {
    if (!state.current) {
      elements.outlineList.innerHTML =
        '<div class="repository-inspector-empty">打开文件后显示结构。</div>';
      return;
    }
    var content = state.codeEditor
      ? state.codeEditor.getValue()
      : state.current.content;
    var symbols = outlineSymbols(content, state.current.name);
    elements.outlineList.innerHTML = symbols.length
      ? symbols.map(function (symbol) {
          return (
            '<button class="repository-outline-item" type="button" data-outline-line="' + symbol.line + '">' +
              '<span class="repository-symbol">' + escapeHtml(symbol.type) + '</span>' +
              '<strong>' + escapeHtml(symbol.name) + '</strong>' +
              '<small>L' + symbol.line + '</small>' +
            '</button>'
          );
        }).join('')
      : '<div class="repository-inspector-empty">当前文件没有可识别的结构。</div>';
  }

  function revealLine(lineNumber) {
    if (!state.codeEditor || !state.current) return;
    var line = Math.max(0, Math.min(
      state.codeEditor.lineCount() - 1,
      Number(lineNumber || 1) - 1
    ));
    state.codeEditor.focus();
    state.codeEditor.setCursor({ line: line, ch: 0 });
    state.codeEditor.scrollIntoView({ line: line, ch: 0 }, 90);
    state.codeEditor.addLineClass(line, 'background', 'repository-located-line');
    window.setTimeout(function () {
      if (state.codeEditor) {
        state.codeEditor.removeLineClass(
          line,
          'background',
          'repository-located-line'
        );
      }
    }, 1200);
  }

  function showDialog(dialog) {
    if (!dialog.open) dialog.showModal();
  }

  function closeDialog(dialog) {
    if (dialog && dialog.open) dialog.close();
  }

  function beginInlineCreate(kind) {
    var parentId = actionDirectoryId();
    elements.fileFilter.value = '';
    if (parentId != null) state.expanded.add(String(parentId));
    state.inlineCreate = {
      kind: kind === 'directory' ? 'directory' : 'file',
      parentId: parentId,
      value: '',
      error: '',
      saving: false,
    };
    renderTree();
  }

  function cancelInlineCreate() {
    state.inlineCreate = null;
    renderTree();
  }

  function submitInlineCreate() {
    var draft = state.inlineCreate;
    if (!draft || draft.saving) return Promise.resolve(false);
    var validated = validateEntryName(draft.value);
    if (!validated.valid) {
      draft.error = validated.message;
      renderTree();
      return Promise.resolve(false);
    }
    draft.error = '';
    draft.saving = true;
    renderTree();
    var url = draft.kind === 'directory' ? endpoints.directory : endpoints.file;
    var payload = {
      parent_id: draft.parentId,
      name: validated.name,
      expected_structure_version: state.structureVersion,
    };
    if (draft.kind === 'file') payload.content = '';
    var beforeCreate = draft.kind === 'file'
      ? persistBeforeTransition()
      : Promise.resolve(true);
    return beforeCreate.then(function (saved) {
      if (!saved) throw new HttpError('当前文件未能自动保存，已取消新建文件', 0, {});
      return postJson(url, payload);
    }).then(function (response) {
      if (response.structure_version != null) state.structureVersion = response.structure_version;
      var createdId = normalizeId(
        response.entry_id != null
          ? response.entry_id
          : response.file_id != null
            ? response.file_id
            : response.id
      );
      if (response.entry) createdId = normalizeEntry(response.entry).id;
      if (draft.parentId != null) state.expanded.add(String(draft.parentId));
      state.inlineCreate = null;
      return loadTree({ focusEntryId: draft.kind === 'directory' ? createdId : null })
        .then(function () {
          showToast(
            draft.kind === 'directory' ? '目录已创建' : '文件已创建',
            validated.name
          );
          if (draft.kind === 'file' && createdId != null) return openFile(createdId);
          return true;
        });
    }).catch(function (error) {
      if (state.inlineCreate === draft) {
        draft.saving = false;
        draft.error = error.message;
        renderTree();
      }
      if (error.status === 409 && error.payload && error.payload.structure_version != null) {
        state.structureVersion = error.payload.structure_version;
        void refreshTreeBestEffort();
      }
      showToast(error.status === 409 ? '无法创建' : '创建失败', error.message, 'error');
      return false;
    });
  }

  function handleMutationError(error) {
    if (error.status === 409 && error.payload && error.payload.structure_version != null) {
      state.structureVersion = error.payload.structure_version;
      void refreshTreeBestEffort();
    }
    var title = error.status === 409 ? '目录结构已变化' : '操作失败';
    showToast(title, error.message, 'error');
    return false;
  }

  function directoryOptions(excludedEntry) {
    var excludedPath = excludedEntry && excludedEntry.kind === 'directory'
      ? excludedEntry.path + '/'
      : '';
    var directories = state.entries.filter(function (entry) {
      if (entry.kind !== 'directory') return false;
      if (!excludedEntry) return true;
      return entry.id !== excludedEntry.id &&
        (!excludedPath || entry.path.indexOf(excludedPath) !== 0);
    }).sort(function (left, right) {
      return pathCollator.compare(left.path, right.path);
    });
    return [{ id: null, path: '' }].concat(directories);
  }

  function openMoveDialog(entry, mode) {
    if (!entry) return;
    state.moveEntryId = entry.id;
    elements.moveTitle.textContent = mode === 'rename'
      ? '重命名' + (entry.kind === 'directory' ? '目录' : '文件')
      : '移动或重命名';
    elements.moveName.value = entry.name;
    elements.moveDestination.innerHTML = directoryOptions(entry).map(function (directory) {
      return '<option value="' + (directory.id == null ? '' : directory.id) + '"' +
        (directory.id === entry.parentId || (directory.id == null && entry.parentId == null) ? ' selected' : '') +
        '>' + escapeHtml(directory.id == null ? 'repository /' : 'repository / ' + directory.path) + '</option>';
    }).join('');
    elements.moveMergeWrap.hidden = entry.kind !== 'directory';
    elements.moveMerge.checked = false;
    showDialog(elements.moveDialog);
    window.setTimeout(function () {
      if (mode === 'rename') {
        elements.moveName.focus();
        elements.moveName.select();
      } else {
        elements.moveDestination.focus();
      }
    }, 0);
  }

  function moveEntry(entry, destinationParentId, newName, conflictPolicy) {
    if (!entry) return Promise.resolve(false);
    var destination = entryForId(destinationParentId);
    if (
      entry.kind === 'directory' &&
      destination &&
      (destination.id === entry.id || destination.path.indexOf(entry.path + '/') === 0)
    ) {
      showToast('无法移动目录', '不能把目录移动到自身或它的子目录中。', 'error');
      return Promise.resolve(false);
    }
    return persistBeforeTransition().then(function (saved) {
      if (!saved) return false;
      return postJson(endpoints.entry + '/' + encodeURIComponent(entry.id) + '/move', {
        destination_parent_id: destinationParentId,
        new_name: newName || entry.name,
        expected_structure_version: state.structureVersion,
        conflict_policy: conflictPolicy === 'merge' ? 'merge' : 'error',
      }).then(function (payload) {
        if (payload.structure_version != null) state.structureVersion = payload.structure_version;
        if (destinationParentId != null) state.expanded.add(String(destinationParentId));
        closeDialog(elements.moveDialog);
        return loadTree().then(function () {
          showToast(
            conflictPolicy === 'merge' ? '目录已合并' : '位置已更新',
            (newName || entry.name) + ' 已移动到 ' + directoryLabel(destinationParentId)
          );
          return true;
        });
      });
    }).catch(function (error) {
      if (error.status === 409 && error.payload && error.payload.code === 'name_conflict') {
        if (!elements.moveDialog.open) {
          openMoveDialog(entry, 'move');
          elements.moveDestination.value = destinationParentId == null ? '' : String(destinationParentId);
        }
        showToast(
          conflictPolicy === 'merge' ? '目录合并未执行' : '目标位置已有同名项目',
          conflictPolicy === 'merge'
            ? '目录内部存在文件重名或类型冲突；为保证原子性，本次移动没有产生任何更改。'
            : entry.kind === 'directory'
            ? '可以修改名称，或勾选“同名目录时递归合并”后重试。'
            : '请在移动窗口中修改名称后重试。',
          'error'
        );
      } else {
        handleMutationError(error);
      }
      return false;
    });
  }

  function submitMove(event) {
    event.preventDefault();
    var entry = entryForId(state.moveEntryId);
    if (!entry) return;
    var validated = validateEntryName(elements.moveName.value);
    elements.moveName.setCustomValidity(validated.valid ? '' : validated.message);
    if (!validated.valid) {
      elements.moveName.reportValidity();
      return;
    }
    var destinationId = normalizeId(elements.moveDestination.value);
    if (destinationId === entry.parentId && validated.name === entry.name) {
      closeDialog(elements.moveDialog);
      return;
    }
    elements.moveForm.querySelector('[type="submit"]').disabled = true;
    moveEntry(
      entry,
      destinationId,
      validated.name,
      entry.kind === 'directory' && elements.moveMerge.checked ? 'merge' : 'error'
    ).finally(function () {
      elements.moveForm.querySelector('[type="submit"]').disabled = false;
    });
  }

  function openDeleteDialog(entry) {
    if (!entry) return;
    state.deleteEntryId = entry.id;
    state.deletePreview = null;
    elements.deleteTitle.textContent = '删除' + (entry.kind === 'directory' ? '目录' : '文件');
    elements.deleteCopy.textContent = '正在核对待删除内容…';
    elements.deleteConfirm.disabled = true;
    elements.deleteConfirm.textContent = '正在核对…';
    showDialog(elements.deleteDialog);
    postJson(
      endpoints.entry + '/' + encodeURIComponent(entry.id) + '/delete-preview',
      {}
    ).then(function (preview) {
      if (state.deleteEntryId !== entry.id || !elements.deleteDialog.open) return;
      state.deletePreview = preview;
      var affectsOpenFile = !!state.current && (
        state.current.id === entry.id ||
        (preview.kind === 'directory' &&
          state.current.path.indexOf(preview.path + '/') === 0)
      );
      var openWarning = affectsOpenFile
        ? '<span class="repository-delete-warning">当前编辑器中的 <strong>' +
            escapeHtml(state.current.path) + '</strong> 位于删除范围内' +
            (state.current.dirty ? '，其中尚有未保存内容' : '') +
            '；确认后编辑器会关闭。</span>'
        : '';
      elements.deleteCopy.innerHTML =
        '将永久删除 <strong>' + escapeHtml(preview.path) + '</strong>。' +
        '<span class="repository-delete-facts">' +
          '<b>' + Number(preview.file_count || 0) + '</b> 个文件 · ' +
          '<b>' + Number(preview.directory_count || 0) + '</b> 个目录 · ' +
          '<b>' + escapeHtml(formatBytes(preview.total_size || 0)) + '</b>' +
        '</span>' +
        openWarning +
        '<span>此操作不可恢复。</span>';
      elements.deleteConfirm.disabled = false;
      elements.deleteConfirm.textContent = '确认永久删除';
    }).catch(function (error) {
      if (state.deleteEntryId !== entry.id) return;
      elements.deleteCopy.textContent = error.message;
      elements.deleteConfirm.textContent = '无法删除';
      showToast('无法生成删除预览', error.message, 'error');
    });
  }

  function deleteEntry() {
    var entry = entryForId(state.deleteEntryId);
    var preview = state.deletePreview;
    if (!entry || !preview || !preview.confirmation_token) return;
    elements.deleteConfirm.disabled = true;
    elements.deleteConfirm.textContent = '正在删除…';
    requestJson(endpoints.entry + '/' + encodeURIComponent(entry.id), {
      method: 'DELETE',
      body: JSON.stringify({
        confirmation_token: preview.confirmation_token,
      }),
    }).then(function (payload) {
      if (payload.structure_version != null) state.structureVersion = payload.structure_version;
      if (
        state.current &&
        (state.current.id === entry.id ||
          (entry.kind === 'directory' && state.current.path.indexOf(entry.path + '/') === 0))
      ) {
        clearEditor();
      }
      state.deletePreview = null;
      closeDialog(elements.deleteDialog);
      return loadTree().then(function () {
        showToast('已删除', entry.path);
        return true;
      });
    }).catch(function (error) {
      if (
        error.status === 409 &&
        error.payload &&
        /confirmation|version_conflict/.test(String(error.payload.code || ''))
      ) {
        showToast('待删除内容已变化', '正在重新生成删除预览。', 'error');
        openDeleteDialog(entry);
      } else {
        handleMutationError(error);
      }
    }).finally(function () {
      if (elements.deleteDialog.open && state.deletePreview) {
        elements.deleteConfirm.disabled = false;
        elements.deleteConfirm.textContent = '确认永久删除';
      }
    });
  }

  function showContextMenu(entry, anchor) {
    if (!entry || !anchor) return;
    state.contextEntryId = entry.id;
    elements.contextMenu.hidden = false;
    var rect = anchor.getBoundingClientRect();
    var menuRect = elements.contextMenu.getBoundingClientRect();
    var left = Math.min(window.innerWidth - menuRect.width - 8, rect.right - menuRect.width);
    var top = Math.min(window.innerHeight - menuRect.height - 8, rect.bottom + 4);
    elements.contextMenu.style.left = Math.max(8, left) + 'px';
    elements.contextMenu.style.top = Math.max(8, top) + 'px';
  }

  function hideContextMenu() {
    elements.contextMenu.hidden = true;
    state.contextEntryId = null;
  }

  /*
   * 新上传协议：选择内容后先创建可续传会话，再逐块校验上传，最后由服务端
   * 统一完成编码识别、冲突预览和原子提交。
   */
  function uploadItemKey(path) {
    return normalizeNfc(path);
  }

  function validateUploadPath(path) {
    return validateRelativePath(path);
  }

  function inspectUploadDescriptor(descriptor) {
    var kind = descriptor.kind === 'directory' ? 'directory' : 'file';
    var file = descriptor.file || null;
    var rawPath = descriptor.relativePath ||
      (file && (file.webkitRelativePath || file.name)) || '';
    var checked = validateUploadPath(rawPath);
    var destination = entryForId(state.upload.parentId);
    var finalPath = checked.valid
      ? ((destination && destination.path)
          ? destination.path + '/' + checked.path
          : checked.path)
      : '';
    var checkedFinal = checked.valid ? validateUploadPath(finalPath) : checked;
    var pathError = checked.valid && !checkedFinal.valid
      ? '目标目录下的最终路径无效：' + checkedFinal.message
      : checked.valid
        ? ''
        : checked.message;
    var item = {
      key: uploadItemKey(checked.path || rawPath),
      kind: kind,
      file: file,
      relativePath: checked.path || normalizeNfc(rawPath),
      error: pathError,
      pathError: pathError,
      sizeError: '',
      encoding: kind === 'directory' ? '目录' : '待服务端识别',
      serverStatus: 'pending',
      serverMessage: '',
      existingEntryId: null,
      resolution: 'overwrite',
      renameTarget: '',
      encodingConfirmed: false,
      candidateEncoding: '',
      encodingPreview: '',
      encodingPreviewTruncated: false,
      encodingHasDisallowedControl: false,
      rawSha256: '',
      token: '',
      receivedBytes: 0,
    };
    if (
      kind === 'file' &&
      !item.error &&
      file.size > state.quota.maxRawFileBytes
    ) {
      item.sizeError = '原始文件超过 ' + formatBytes(state.quota.maxRawFileBytes);
      item.error = item.pathError || item.sizeError;
    }
    return Promise.resolve(item);
  }

  function uploadSessionUrl(suffix, sessionId) {
    var selectedSession = sessionId || state.upload.sessionId;
    if (!selectedSession) return endpoints.uploadSession;
    return endpoints.uploadSession + '/' +
      encodeURIComponent(selectedSession) + (suffix || '');
  }

  function cancelUploadSession(sessionId) {
    if (!sessionId) return Promise.resolve(false);
    return requestJson(uploadSessionUrl('', sessionId), { method: 'DELETE' })
      .then(function () { return true; })
      .catch(function () { return false; });
  }

  function resetUploadPreview(options) {
    var settings = options || {};
    var oldSessionId = state.upload.sessionId;
    state.upload.sessionId = null;
    state.upload.previewStructureVersion = null;
    state.upload.phase = 'idle';
    state.upload.progressBytes = 0;
    state.upload.totalBytes = 0;
    state.upload.previewing = false;
    state.upload.errorMessage = '';
    state.upload.items.forEach(function (item) {
      item.serverStatus = item.error ? 'invalid' : 'pending';
      item.serverMessage = '';
      item.existingEntryId = null;
      item.encodingConfirmed = false;
      item.candidateEncoding = '';
      item.encodingPreview = '';
      item.encodingPreviewTruncated = false;
      item.encodingHasDisallowedControl = false;
      item.token = '';
      item.receivedBytes = 0;
    });
    if (oldSessionId && settings.cancel !== false) {
      void cancelUploadSession(oldSessionId);
    }
  }

  function expandUploadDirectories(descriptors) {
    var source = Array.from(descriptors || []);
    var directoryPaths = new Set();
    source.forEach(function (descriptor) {
      if (descriptor.kind === 'directory') {
        directoryPaths.add(normalizeNfc(descriptor.relativePath));
        return;
      }
      var rawPath = normalizeNfc(
        descriptor.relativePath ||
          (descriptor.file &&
            (descriptor.file.webkitRelativePath || descriptor.file.name)) ||
          ''
      );
      if (rawPath.indexOf('\\') >= 0) return;
      var parts = rawPath.split('/');
      parts.pop();
      var current = '';
      parts.forEach(function (part) {
        if (!part) return;
        current = current ? current + '/' + part : part;
        directoryPaths.add(current);
      });
    });
    var directories = Array.from(directoryPaths).map(function (path) {
      return descriptorFromDirectory(path);
    });
    return directories.concat(source.filter(function (descriptor) {
      return descriptor.kind !== 'directory';
    }));
  }

  function isIgnoredDirectoryMetadataDescriptor(descriptor) {
    if (!descriptor || descriptor.kind === 'directory') return false;
    var file = descriptor.file || null;
    var rawPath = normalizeNfc(
      descriptor.relativePath ||
        (file && (file.webkitRelativePath || file.name)) ||
        ''
    );
    var parts = rawPath.split('/');
    return parts.length > 1 && parts[parts.length - 1] === '.DS_Store';
  }

  function addUploadDescriptors(descriptors, options) {
    var settings = options || {};
    var sequence = ++state.upload.previewSequence;
    if (!settings.append) state.upload.items = [];
    resetUploadPreview({ cancel: true });
    state.upload.phase = 'reading';
    renderUploadQueue();
    return Promise.resolve().then(function () {
      return Promise.all(
        expandUploadDirectories(descriptors)
          .filter(function (descriptor) {
            return !isIgnoredDirectoryMetadataDescriptor(descriptor);
          })
          .map(inspectUploadDescriptor)
      );
    }).then(function (inspected) {
      if (sequence !== state.upload.previewSequence) return false;
      var merged = new Map();
      state.upload.items.forEach(function (item) { merged.set(item.key, item); });
      inspected.forEach(function (item) { merged.set(item.key, item); });
      state.upload.items = Array.from(merged.values()).sort(function (left, right) {
        if (left.kind !== right.kind) return left.kind === 'directory' ? -1 : 1;
        return pathCollator.compare(left.relativePath, right.relativePath);
      });
      renderUploadQueue();
      if (
        state.upload.items.length &&
        state.upload.items.every(function (item) { return !item.error; })
      ) {
        return previewUploads();
      }
      return false;
    }).catch(function (error) {
      if (sequence !== state.upload.previewSequence) return false;
      state.upload.phase = 'error';
      state.upload.previewing = false;
      state.upload.errorMessage =
        '读取上传清单失败：' + (error.message || '未知错误');
      try {
        renderUploadQueue();
      } catch (_renderError) {
        elements.uploadSummary.textContent = state.upload.errorMessage;
        elements.uploadConfirm.disabled = true;
      }
      showToast(
        '无法读取上传清单',
        error.message || '请清空列表后重新选择文件。',
        'error'
      );
      return false;
    });
  }

  function uploadServerEntryMap(payload) {
    var map = new Map();
    var entries = Array.isArray(payload.entries)
      ? payload.entries
      : []
          .concat((payload.directories || []).map(function (item) {
            return Object.assign({ kind: 'directory' }, item);
          }))
          .concat((payload.files || []).map(function (item) {
            return Object.assign({ kind: 'file' }, item);
          }));
    entries.forEach(function (entry) {
      var path = normalizeRelativePath(
        entry.relative_path || entry.path || entry.filename
      );
      if (path) map.set(uploadItemKey(path), entry);
    });
    return map;
  }

  function uploadExcludedDirectoryFor(item) {
    var itemPath = normalizeNfc(item && item.relativePath);
    if (!itemPath) return null;
    return state.upload.items.reduce(function (matched, candidate) {
      if (
        candidate.kind !== 'directory' ||
        candidate.serverStatus !== 'blocking_conflict' ||
        candidate.resolution !== 'exclude'
      ) {
        return matched;
      }
      var directoryPath = normalizeNfc(candidate.relativePath);
      if (
        itemPath !== directoryPath &&
        itemPath.indexOf(directoryPath + '/') !== 0
      ) {
        return matched;
      }
      if (!matched || directoryPath.length < matched.relativePath.length) {
        return candidate;
      }
      return matched;
    }, null);
  }

  function applyUploadSessionPayload(payload) {
    if (payload.session_id) state.upload.sessionId = payload.session_id;
    if (payload.structure_version != null) {
      state.upload.previewStructureVersion = payload.structure_version;
    } else if (payload.base_structure_version != null) {
      state.upload.previewStructureVersion = payload.base_structure_version;
    }
    var serverMap = uploadServerEntryMap(payload);
    state.upload.items.forEach(function (item) {
      var serverItem = serverMap.get(item.key);
      if (!serverItem) return;
      item.token = serverItem.token || item.token;
      item.receivedBytes = Math.max(
        0,
        Number(
          serverItem.received_size != null
            ? serverItem.received_size
            : item.receivedBytes
        ) || 0
      );
      item.serverStatus = serverItem.status || item.serverStatus;
      item.serverMessage = serverItem.message || '';
      item.pathError = serverItem.path_error || item.pathError || '';
      item.existingEntryId = normalizeId(serverItem.existing_entry_id);
      item.candidateEncoding = serverItem.candidate_encoding || '';
      item.encodingPreview = serverItem.encoding_preview || '';
      item.encodingPreviewTruncated = !!serverItem.encoding_preview_truncated;
      item.encodingHasDisallowedControl =
        !!serverItem.encoding_preview_has_disallowed_control;
      if (serverItem.source_encoding) {
        item.encoding = String(serverItem.source_encoding).toLocaleUpperCase();
        if (serverItem.newline_normalized) item.encoding += ' → UTF-8 / LF';
      } else if (item.candidateEncoding) {
        item.encoding = '候选 ' + item.candidateEncoding;
      }
      if (item.serverStatus === 'invalid') {
        item.error = item.serverMessage || '服务端校验未通过';
      } else if (
        item.serverStatus === 'blocking_conflict' &&
        item.kind === 'directory'
      ) {
        item.error = '';
        item.resolution = 'exclude';
      } else if (item.serverStatus === 'blocking_conflict') {
        item.resolution = 'rename';
        if (!item.renameTarget) {
          item.renameTarget = suggestedRenamePath(item.relativePath);
        }
      }
    });
    if (payload.status === 'preview_ready' || payload.ready === true) {
      state.upload.phase = 'ready';
    } else if (payload.status === 'needs_confirmation') {
      state.upload.phase = 'needs_encoding';
    } else if (payload.status === 'receiving') {
      state.upload.phase = 'uploading';
    }
  }

  function digestSha256(blob) {
    return blob.arrayBuffer().then(function (buffer) {
      if (window.crypto && window.crypto.subtle) {
        return window.crypto.subtle.digest('SHA-256', buffer).then(function (digest) {
          return Array.from(new Uint8Array(digest)).map(function (value) {
            return value.toString(16).padStart(2, '0');
          }).join('');
        });
      }
      if (
        window.NumOJRepositorySha256 &&
        typeof window.NumOJRepositorySha256.digestHex === 'function'
      ) {
        return window.NumOJRepositorySha256.digestHex(buffer);
      }
      throw new Error('当前浏览器不支持上传所需的 SHA-256 校验');
    });
  }

  function prepareUploadHashes(items, sequence) {
    state.upload.phase = 'preparing';
    renderUploadQueue();
    return Promise.all(items.filter(function (item) {
      return item.kind === 'file';
    }).map(function (item) {
      if (item.rawSha256) return Promise.resolve();
      return digestSha256(item.file).then(function (digest) {
        if (sequence === state.upload.previewSequence) item.rawSha256 = digest;
      });
    }));
  }

  function uploadChunk(item, offset, sequence, retryCount) {
    if (sequence !== state.upload.previewSequence) return Promise.resolve(false);
    if (offset >= item.file.size) {
      item.receivedBytes = item.file.size;
      item.serverStatus = 'uploaded';
      renderUploadQueue();
      return Promise.resolve(true);
    }
    var chunk = item.file.slice(offset, Math.min(offset + 1024 * 1024, item.file.size));
    return digestSha256(chunk).then(function (chunkHash) {
      return requestJson(
        uploadSessionUrl('/file/' + encodeURIComponent(item.token) + '/chunk'),
        {
          method: 'PUT',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/octet-stream',
            'Upload-Offset': String(offset),
            'Upload-Length': String(item.file.size),
            'Upload-Chunk-SHA256': chunkHash,
          },
          body: chunk,
        }
      );
    }).then(function (payload) {
      if (sequence !== state.upload.previewSequence) return false;
      var nextOffset = Number(payload.offset);
      if (!Number.isFinite(nextOffset) || nextOffset <= offset) {
        throw new HttpError('服务端没有推进上传 offset', 409, payload);
      }
      item.receivedBytes = nextOffset;
      state.upload.progressBytes = state.upload.items.reduce(function (sum, candidate) {
        return sum + (candidate.kind === 'file' ? candidate.receivedBytes : 0);
      }, 0);
      renderUploadQueue();
      return uploadChunk(item, nextOffset, sequence, 0);
    }).catch(function (error) {
      if (sequence !== state.upload.previewSequence) return false;
      if (
        error.status === 409 &&
        error.payload &&
        error.payload.expected_offset != null
      ) {
        var expectedOffset = Number(error.payload.expected_offset);
        if (Number.isFinite(expectedOffset) && expectedOffset >= 0) {
          item.receivedBytes = expectedOffset;
          return uploadChunk(item, expectedOffset, sequence, retryCount + 1);
        }
      }
      if ((retryCount || 0) >= 2 || !state.upload.sessionId) throw error;
      return requestJson(uploadSessionUrl()).then(function (statusPayload) {
        applyUploadSessionPayload(statusPayload);
        return uploadChunk(item, item.receivedBytes, sequence, retryCount + 1);
      });
    });
  }

  function uploadAllChunks(sequence) {
    var files = state.upload.items.filter(function (item) {
      return item.kind === 'file';
    });
    state.upload.phase = 'uploading';
    state.upload.totalBytes = files.reduce(function (sum, item) {
      return sum + item.file.size;
    }, 0);
    state.upload.progressBytes = files.reduce(function (sum, item) {
      return sum + item.receivedBytes;
    }, 0);
    renderUploadQueue();
    return files.reduce(function (promise, item) {
      return promise.then(function () {
        if (!item.token) throw new Error('上传会话缺少文件 token');
        if (item.file.size === 0) {
          item.serverStatus = 'uploaded';
          return true;
        }
        return uploadChunk(item, item.receivedBytes || 0, sequence, 0);
      });
    }, Promise.resolve(true));
  }

  function finalizeUploads(encodings, sequence) {
    state.upload.phase = 'finalizing';
    state.upload.previewing = true;
    renderUploadQueue();
    return postJson(uploadSessionUrl('/finalize'), {
      encodings: encodings || {},
    }).then(function (payload) {
      if (sequence !== state.upload.previewSequence) return false;
      applyUploadSessionPayload(payload);
      renderUploadQueue();
      return payload.ready === true;
    }).finally(function () {
      if (sequence === state.upload.previewSequence) {
        state.upload.previewing = false;
        renderUploadQueue();
      }
    });
  }

  function createAndUploadSession(sequence) {
    var validItems = state.upload.items.filter(function (item) { return !item.error; });
    return prepareUploadHashes(validItems, sequence).then(function () {
      if (sequence !== state.upload.previewSequence) return false;
      return postJson(endpoints.uploadSession, {
        parent_id: state.upload.parentId,
        expected_structure_version: state.structureVersion,
        entries: validItems.map(function (item) {
          if (item.kind === 'directory') {
            return { kind: 'directory', relative_path: item.relativePath };
          }
          return {
            kind: 'file',
            relative_path: item.relativePath,
            size: item.file.size,
            sha256: item.rawSha256,
          };
        }),
      });
    }).then(function (payload) {
      if (!payload) return false;
      if (sequence !== state.upload.previewSequence) {
        void cancelUploadSession(payload.session_id);
        return false;
      }
      applyUploadSessionPayload(payload);
      return uploadAllChunks(sequence);
    }).then(function (uploaded) {
      if (!uploaded || sequence !== state.upload.previewSequence) return false;
      return finalizeUploads({}, sequence);
    });
  }

  function resumeUploadSession(sequence) {
    return requestJson(uploadSessionUrl()).then(function (payload) {
      if (sequence !== state.upload.previewSequence) return false;
      applyUploadSessionPayload(payload);
      if (payload.status === 'preview_ready') {
        renderUploadQueue();
        return true;
      }
      if (payload.status === 'needs_confirmation') {
        renderUploadQueue();
        return false;
      }
      return uploadAllChunks(sequence).then(function (uploaded) {
        return uploaded ? finalizeUploads({}, sequence) : false;
      });
    });
  }

  function markUploadOperationError(error) {
    var payload = error && error.payload ? error.payload : {};
    var path = normalizeRelativePath(
      payload.relative_path || payload.path || ''
    );
    var token = String(payload.token || '');
    var item = state.upload.items.find(function (candidate) {
      return (path && candidate.relativePath === path) ||
        (token && candidate.token === token);
    });
    if (!item) return false;
    item.serverStatus = 'invalid';
    item.serverMessage = error.message;
    item.error = error.message;
    return true;
  }

  function previewUploads() {
    if (
      !state.upload.items.length ||
      state.upload.items.some(function (item) { return !!item.error; })
    ) {
      renderUploadQueue();
      return Promise.resolve(false);
    }
    var sequence = ++state.upload.previewSequence;
    state.upload.previewing = true;
    state.upload.errorMessage = '';
    elements.uploadConfirm.disabled = true;
    var operation = state.upload.sessionId
      ? resumeUploadSession(sequence)
      : createAndUploadSession(sequence);
    return operation.catch(function (error) {
      if (sequence !== state.upload.previewSequence) return false;
      if (
        error.status === 410 ||
        (error.payload && error.payload.code === 'upload_session_expired')
      ) {
        state.upload.sessionId = null;
        state.upload.previewStructureVersion = null;
        state.upload.items.forEach(function (item) {
          item.token = '';
          item.receivedBytes = 0;
          item.serverStatus = item.error ? 'invalid' : 'pending';
        });
      }
      state.upload.phase = 'error';
      state.upload.errorMessage = error.message || '上传检查失败';
      markUploadOperationError(error);
      showToast('上传检查失败', error.message, 'error');
      return false;
    }).finally(function () {
      if (sequence === state.upload.previewSequence) {
        state.upload.previewing = false;
        renderUploadQueue();
      }
    });
  }

  function suggestedRenamePath(path) {
    var directory = dirname(path);
    var name = basename(path);
    var dot = name.lastIndexOf('.');
    var stem = dot > 0 ? name.slice(0, dot) : name;
    var extension = dot > 0 ? name.slice(dot) : '';
    var renamed = stem + '-copy' + extension;
    return directory ? directory + '/' + renamed : renamed;
  }

  function uploadStateMarkup(item) {
    var excludedDirectory = uploadExcludedDirectoryFor(item);
    if (
      excludedDirectory &&
      item.serverStatus !== 'encoding_confirmation_required'
    ) {
      if (excludedDirectory.key === item.key) {
        return '<span class="conflict">排除此目录及全部后代</span>';
      }
      return '<span>随目录“' +
        escapeHtml(excludedDirectory.relativePath) +
        '”一并排除</span>';
    }
    if (item.error) {
      var pathFix = item.pathError
        ? '<input type="text" maxlength="1024" value="' +
            escapeHtml(item.relativePath) + '" data-upload-path-fix="' +
            escapeHtml(item.key) + '" aria-label="修正上传相对路径" ' +
            'placeholder="输入合法相对路径">'
        : '';
      return '<span class="error">' + escapeHtml(item.error) + '</span>' + pathFix;
    }
    if (item.kind === 'directory') {
      if (item.serverStatus === 'merge') return '<span class="conflict">合并目录</span>';
      if (item.serverStatus === 'new') return '<span>新建目录</span>';
      return '<span>待检查目录</span>';
    }
    if (item.serverStatus === 'blocking_conflict') {
      var blockingRename = item.resolution === 'rename'
        ? '<input type="text" maxlength="1024" value="' +
            escapeHtml(item.renameTarget) + '" data-upload-rename="' +
            escapeHtml(item.key) + '" placeholder="完整相对路径">'
        : '';
      return (
        '<select data-upload-resolution="' + escapeHtml(item.key) +
          '" aria-label="路径冲突处理方式">' +
          '<option value="rename"' +
            (item.resolution === 'rename' ? ' selected' : '') + '>另存为</option>' +
          '<option value="skip"' +
            (item.resolution === 'skip' ? ' selected' : '') + '>排除此文件</option>' +
        '</select>' + blockingRename
      );
    }
    if (item.serverStatus === 'conflict') {
      var renameInput = item.resolution === 'rename'
        ? '<input type="text" maxlength="1024" value="' +
            escapeHtml(item.renameTarget) + '" data-upload-rename="' +
            escapeHtml(item.key) + '" placeholder="完整相对路径">'
        : '';
      return (
        '<select data-upload-resolution="' + escapeHtml(item.key) +
          '" aria-label="同名文件处理方式">' +
          '<option value="overwrite"' +
            (item.resolution === 'overwrite' ? ' selected' : '') + '>覆盖现有</option>' +
          '<option value="skip"' +
            (item.resolution === 'skip' ? ' selected' : '') + '>跳过</option>' +
          '<option value="rename"' +
            (item.resolution === 'rename' ? ' selected' : '') + '>另存为</option>' +
        '</select>' + renameInput
      );
    }
    if (item.serverStatus === 'encoding_confirmation_required') {
      return (
        '<label class="repository-encoding-confirm">' +
          '<input type="checkbox" data-upload-encoding="' + escapeHtml(item.key) + '"' +
            (item.encodingConfirmed ? ' checked' : '') +
            (item.encodingHasDisallowedControl ? ' disabled' : '') + '>按 ' +
            escapeHtml(item.candidateEncoding || '候选编码') + ' 解码（已查看预览）' +
        '</label>'
      );
    }
    if (state.upload.phase === 'uploading' || item.serverStatus === 'receiving') {
      var percent = item.file.size
        ? Math.floor((item.receivedBytes / item.file.size) * 100)
        : 100;
      return '<span class="progress">' + percent + '%</span>';
    }
    if (item.serverStatus === 'new') return '<span>新增</span>';
    if (item.serverStatus === 'uploaded') return '<span>已校验</span>';
    return '<span>待检查</span>';
  }

  function uploadCanCommit() {
    if (state.upload.previewing) return false;
    if (state.upload.phase === 'idle' || state.upload.phase === 'error') {
      return state.upload.items.length > 0 &&
        state.upload.items.every(function (item) { return !item.error; });
    }
    if (!state.upload.sessionId) return false;
    if (state.upload.phase === 'needs_encoding') {
      return state.upload.items.every(function (item) {
        if (item.encodingHasDisallowedControl) return false;
        return item.serverStatus !== 'encoding_confirmation_required' ||
          item.encodingConfirmed;
      });
    }
    if (state.upload.phase !== 'ready') return false;
    return state.upload.items.some(function (item) {
      var excludedDirectory = uploadExcludedDirectoryFor(item);
      if (excludedDirectory) return excludedDirectory.key === item.key;
      return !item.error &&
        (item.kind === 'directory' ||
          !(
            (item.serverStatus === 'conflict' ||
              item.serverStatus === 'blocking_conflict') &&
            item.resolution === 'skip'
          ));
    }) && state.upload.items.every(function (item) {
      if (uploadExcludedDirectoryFor(item)) return true;
      if (item.error) return false;
      if (
        (item.serverStatus === 'conflict' ||
          item.serverStatus === 'blocking_conflict') &&
        item.resolution === 'rename'
      ) {
        return validateUploadPath(item.renameTarget).valid;
      }
      return true;
    });
  }

  function renderUploadQueue() {
    var items = state.upload.items;
    var fileCount = items.filter(function (item) { return item.kind === 'file'; }).length;
    var directoryCount = items.length - fileCount;
    elements.uploadQueue.hidden = items.length === 0;
    elements.uploadDropzone.classList.toggle('has-files', items.length > 0);
    elements.uploadQueueTitle.textContent =
      '已选择 ' + fileCount + ' 个文件' +
      (directoryCount ? ' · ' + directoryCount + ' 个目录' : '');
    elements.uploadFileList.innerHTML = items.map(function (item) {
      var excludedDirectory = uploadExcludedDirectoryFor(item);
      var cascadeExcluded = !!excludedDirectory &&
        item.serverStatus !== 'encoding_confirmation_required';
      var invalid = !cascadeExcluded && !!item.error;
      var conflict = !cascadeExcluded &&
        (
          item.serverStatus === 'conflict' ||
          item.serverStatus === 'blocking_conflict'
        );
      var excludeLabel = invalid ||
        item.serverStatus === 'blocking_conflict' ||
        item.encodingHasDisallowedControl
        ? '排除'
        : '×';
      var removeMarkup = cascadeExcluded
        ? ''
        : '<button class="repository-upload-file-remove' +
            (excludeLabel === '排除' ? ' is-exclude' : '') +
            '" type="button" data-upload-remove="' +
            escapeHtml(item.key) + '" aria-label="排除 ' +
            escapeHtml(item.relativePath) + '">' + excludeLabel + '</button>';
      return (
        '<div class="repository-upload-file' +
          (invalid ? ' is-invalid' : '') +
          (conflict ? ' is-conflict' : '') + '">' +
          '<span class="repository-upload-file-icon">' +
            escapeHtml(item.kind === 'directory' ? 'DIR' : extensionLabel(item.relativePath)) +
          '</span>' +
          '<span class="repository-upload-file-copy">' +
            '<strong title="' + escapeHtml(item.relativePath) + '">' +
              escapeHtml(item.relativePath) +
            '</strong>' +
            '<small>' +
              (item.kind === 'directory'
                ? '目录清单'
                : formatBytes(item.file.size) + ' · ' + escapeHtml(item.encoding)) +
            '</small>' +
          '</span>' +
          '<span class="repository-upload-file-state">' + uploadStateMarkup(item) + '</span>' +
          removeMarkup +
          (item.encodingPreview || item.encodingHasDisallowedControl
            ? '<div class="repository-encoding-preview">' +
                '<strong>候选解码预览' +
                  (item.encodingPreviewTruncated ? '（已截断）' : '') +
                '</strong>' +
                '<pre aria-label="候选解码预览">' +
                  escapeHtml(item.encodingPreview) +
                '</pre>' +
                (item.encodingHasDisallowedControl
                  ? '<span role="alert">检测到不允许的控制字符，无法按该编码上传；请排除此文件。</span>'
                  : '') +
              '</div>'
            : '') +
        '</div>'
      );
    }).join('');
    var invalidCount = items.filter(function (item) {
      return !!item.error && !uploadExcludedDirectoryFor(item);
    }).length;
    var conflictCount = items.filter(function (item) {
      return item.serverStatus === 'conflict';
    }).length;
    var validFileCount = items.filter(function (item) {
      return item.kind === 'file' &&
        !item.error &&
        !uploadExcludedDirectoryFor(item);
    }).length;
    var excludedDirectoryCount = items.filter(function (item) {
      var excludedDirectory = uploadExcludedDirectoryFor(item);
      return excludedDirectory && excludedDirectory.key === item.key;
    }).length;
    if (state.upload.phase === 'reading') {
      elements.uploadSummary.textContent = '正在读取上传清单…';
    } else if (state.upload.phase === 'preparing') {
      elements.uploadSummary.textContent = '正在计算 SHA-256 校验值…';
    } else if (state.upload.phase === 'uploading') {
      elements.uploadSummary.textContent =
        '正在上传 ' + formatBytes(state.upload.progressBytes) +
        ' / ' + formatBytes(state.upload.totalBytes);
    } else if (state.upload.phase === 'finalizing') {
      elements.uploadSummary.textContent = '正在识别编码并检查冲突…';
    } else if (state.upload.phase === 'needs_encoding') {
      elements.uploadSummary.textContent = '请确认标记文件的候选编码';
    } else if (state.upload.phase === 'ready' || state.upload.phase === 'committing') {
      elements.uploadSummary.textContent =
        validFileCount + ' 个文件可写入' +
        (directoryCount ? ' · ' + directoryCount + ' 个目录' : '') +
        (excludedDirectoryCount
          ? ' · ' + excludedDirectoryCount + ' 个冲突目录将连同后代排除'
          : '') +
        (conflictCount ? ' · ' + conflictCount + ' 个同名冲突' : '');
    } else if (state.upload.phase === 'error' && state.upload.errorMessage) {
      elements.uploadSummary.textContent = state.upload.errorMessage;
    } else {
      elements.uploadSummary.textContent = items.length
        ? validFileCount + ' 个文件待检查' +
          (directoryCount ? ' · ' + directoryCount + ' 个目录' : '') +
          (invalidCount ? ' · ' + invalidCount + ' 个需修正或排除' : '')
        : '尚未选择文件';
    }
    elements.uploadConfirm.disabled = !uploadCanCommit();
    var labels = {
      idle: '检查文件',
      reading: '正在读取清单…',
      preparing: '正在计算校验值…',
      uploading: '正在分块上传…',
      finalizing: '正在检查…',
      needs_encoding: '确认编码并继续',
      ready: '写入仓库',
      committing: '正在写入…',
      error: '重试检查',
    };
    elements.uploadConfirm.textContent = labels[state.upload.phase] || '检查文件';
  }

  function openUploadDialog(descriptors, parentId) {
    state.upload.previewSequence += 1;
    resetUploadPreview({ cancel: true });
    state.upload.parentId = parentId !== undefined ? parentId : actionDirectoryId();
    state.upload.items = [];
    elements.uploadDestination.textContent = directoryLabel(state.upload.parentId);
    elements.uploadFiles.value = '';
    elements.uploadFolder.value = '';
    renderUploadQueue();
    showDialog(elements.uploadDialog);
    if (descriptors && descriptors.length) {
      void addUploadDescriptors(descriptors, { append: false });
    }
  }

  function commitUploads(event) {
    event.preventDefault();
    if (state.upload.phase === 'idle' || state.upload.phase === 'error') {
      void previewUploads();
      return;
    }
    if (!uploadCanCommit()) return;
    if (state.upload.phase === 'needs_encoding') {
      var encodings = {};
      state.upload.items.forEach(function (item) {
        if (
          item.serverStatus === 'encoding_confirmation_required' &&
          item.encodingConfirmed
        ) {
          encodings[item.token || item.relativePath] = item.candidateEncoding;
        }
      });
      var encodingSequence = state.upload.previewSequence;
      void finalizeUploads(encodings, encodingSequence).catch(function (error) {
        state.upload.phase = 'error';
        state.upload.errorMessage = error.message || '编码确认失败';
        markUploadOperationError(error);
        showToast('编码确认失败', error.message, 'error');
        renderUploadQueue();
      });
      return;
    }
    var resolutions = {};
    var renameTargets = {};
    state.upload.items.forEach(function (item) {
      var excludedDirectory = uploadExcludedDirectoryFor(item);
      if (excludedDirectory) {
        if (excludedDirectory.key === item.key) {
          resolutions[item.relativePath] = 'exclude';
        }
        return;
      }
      if (
        item.serverStatus === 'conflict' ||
        item.serverStatus === 'blocking_conflict'
      ) {
        resolutions[item.relativePath] = item.resolution;
        if (item.resolution === 'rename') {
          renameTargets[item.relativePath] = validateUploadPath(item.renameTarget).path;
        }
      }
    });
    state.upload.phase = 'committing';
    renderUploadQueue();
    persistBeforeTransition().then(function (saved) {
      if (!saved) {
        throw new HttpError('当前编辑文件未能自动保存，已停止写入上传内容', 0, {});
      }
      return postJson(uploadSessionUrl('/commit'), {
        expected_structure_version: state.upload.previewStructureVersion,
        resolutions: resolutions,
        rename_targets: renameTargets,
      });
    }).then(function (payload) {
      if (payload.structure_version != null) state.structureVersion = payload.structure_version;
      var uploadedCount = Number(payload.committed_count);
      if (!Number.isFinite(uploadedCount)) {
        uploadedCount = Array.isArray(payload.committed)
          ? payload.committed.length
          : state.upload.items.filter(function (item) {
              return item.kind === 'file' && !item.error &&
                !uploadExcludedDirectoryFor(item) &&
                !(
                  (item.serverStatus === 'conflict' ||
                    item.serverStatus === 'blocking_conflict') &&
                  item.resolution === 'skip'
                );
            }).length;
      }
      var createdDirectoryCount = state.upload.items.filter(function (item) {
        return item.kind === 'directory' && item.serverStatus === 'new';
      }).length;
      var committedIds = new Set((payload.committed || []).map(function (entry) {
        return normalizeId(entry.entry_id);
      }).filter(Boolean));
      var reopenId = state.current && committedIds.has(state.current.id)
        ? state.current.id
        : null;
      if (reopenId != null) clearEditor();
      closeDialog(elements.uploadDialog);
      state.upload.items = [];
      state.upload.sessionId = null;
      state.upload.phase = 'idle';
      if (state.upload.parentId != null) state.expanded.add(String(state.upload.parentId));
      return loadTree().then(function () {
        showToast(
          '上传完成',
          uploadedCount + ' 个文件' +
            (createdDirectoryCount ? ' · ' + createdDirectoryCount + ' 个新目录' : '') +
            '已写入仓库，目录层级已保留。'
        );
        if (reopenId != null) return openFile(reopenId);
        return true;
      });
    }).catch(function (error) {
      if (error.status === 409) {
        if (error.payload && error.payload.structure_version != null) {
          state.structureVersion = error.payload.structure_version;
        }
        showToast('仓库结构已变化', '正在创建新的上传会话并重新校验。', 'error');
        resetUploadPreview({ cancel: true });
        void previewUploads();
      } else {
        state.upload.phase = 'ready';
        showToast('上传失败', error.message, 'error');
      }
    }).finally(function () {
      renderUploadQueue();
    });
  }

  function descriptorFromFile(file, path) {
    return {
      kind: 'file',
      file: file,
      relativePath: normalizeNfc(path || file.webkitRelativePath || file.name),
    };
  }

  function descriptorFromDirectory(path) {
    return {
      kind: 'directory',
      file: null,
      relativePath: normalizeNfc(path),
    };
  }

  function readWebkitDirectory(reader) {
    return new Promise(function (resolve, reject) {
      var entries = [];

      function readNextBatch() {
        reader.readEntries(function (batch) {
          var next = Array.from(batch || []);
          if (!next.length) {
            resolve(entries);
            return;
          }
          entries.push.apply(entries, next);
          readNextBatch();
        }, reject);
      }

      readNextBatch();
    });
  }

  function walkWebkitEntry(entry, prefix) {
    var path = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isFile) {
      return new Promise(function (resolve, reject) {
        entry.file(function (file) {
          resolve([descriptorFromFile(file, path)]);
        }, reject);
      });
    }
    if (!entry.isDirectory) return Promise.resolve([]);
    return readWebkitDirectory(entry.createReader()).then(function (children) {
      return Promise.all(children.map(function (child) {
        return walkWebkitEntry(child, path);
      })).then(function (nested) {
        return [descriptorFromDirectory(path)].concat(nested.flat());
      });
    });
  }

  function extractDropDescriptors(dataTransfer) {
    var items = Array.from(dataTransfer.items || []);
    var entryItems = items.map(function (item) {
      return typeof item.webkitGetAsEntry === 'function'
        ? item.webkitGetAsEntry()
        : null;
    }).filter(Boolean);
    if (entryItems.length) {
      return Promise.all(entryItems.map(function (entry) {
        return walkWebkitEntry(entry, '');
      })).then(function (nested) {
        return nested.flat();
      });
    }
    return Promise.resolve(Array.from(dataTransfer.files || []).map(function (file) {
      return descriptorFromFile(file);
    }));
  }

  function hasExternalFiles(event) {
    var types = Array.from((event.dataTransfer && event.dataTransfer.types) || []);
    return types.indexOf('Files') >= 0 &&
      types.indexOf('application/x-numoj-entry-id') < 0;
  }

  function directoryAtPointer(event) {
    var row = event.target.closest && event.target.closest('.repository-tree-row[data-entry-kind="directory"]');
    if (row) return normalizeId(row.dataset.entryId);
    return actionDirectoryId();
  }

  function externalDragEnter(event) {
    if (!hasExternalFiles(event)) return;
    event.preventDefault();
    state.externalDragDepth += 1;
    state.treeDropTargetId = directoryAtPointer(event);
    elements.dropTarget.textContent = directoryLabel(state.treeDropTargetId).replace('repository / ', '').toUpperCase() +
      ' · MULTI-FILE / FOLDER';
    elements.filesPane.classList.add('is-external-dragover');
  }

  function externalDragOver(event) {
    if (!hasExternalFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    state.treeDropTargetId = directoryAtPointer(event);
    elements.dropTarget.textContent = directoryLabel(state.treeDropTargetId).replace('repository / ', '').toUpperCase() +
      ' · MULTI-FILE / FOLDER';
  }

  function externalDragLeave(event) {
    if (!hasExternalFiles(event)) return;
    event.preventDefault();
    state.externalDragDepth = Math.max(0, state.externalDragDepth - 1);
    if (state.externalDragDepth === 0) {
      elements.filesPane.classList.remove('is-external-dragover');
    }
  }

  function externalDrop(event) {
    if (!hasExternalFiles(event)) return;
    event.preventDefault();
    event.stopPropagation();
    var parentId = directoryAtPointer(event);
    state.externalDragDepth = 0;
    elements.filesPane.classList.remove('is-external-dragover');
    extractDropDescriptors(event.dataTransfer).then(function (descriptors) {
      if (!descriptors.length) {
        showToast('没有可上传的条目', '浏览器没有返回文件或目录，请改用选择器重试。', 'error');
        return;
      }
      openUploadDialog(descriptors, parentId);
    }).catch(function (error) {
      showToast('无法读取拖入内容', error.message || '浏览器未授权读取该文件夹。', 'error');
    });
  }

  function parseIndexProgressMessage(rawMessage) {
    var text = String(rawMessage || '').trim();
    var match = text.match(/^\[stage:([a-z_]+)\]\s*(.*)$/i);
    if (!match) return { stage: '', detail: text };
    return { stage: match[1].toLocaleLowerCase(), detail: String(match[2] || '').trim() };
  }

  function showIndexProgress(job) {
    var status = String(job.status || 'queued').toLocaleLowerCase();
    var running = status === 'queued' || status === 'pending' || status === 'running';
    var cancelRequested = Number(job.cancel_requested) === 1;
    var failed = status === 'failed' || status === 'canceled';
    var progress = Math.max(0, Math.min(100, Number(job.progress) || 0));
    var parsed = parseIndexProgressMessage(job.progress_message);
    elements.indexProgress.classList.toggle('is-running', running);
    elements.indexProgress.classList.toggle('is-terminal', !running);
    elements.indexProgress.classList.toggle('is-failed', failed);
    elements.indexProgress.setAttribute('aria-hidden', 'false');
    elements.indexTitle.textContent = indexStageLabels[parsed.stage] ||
      (status === 'success' ? '整理完成' : status === 'failed' ? '整理失败' : status === 'canceled' ? '整理已取消' : '结构化整理');
    elements.indexSubtitle.textContent = parsed.detail ||
      ('正在处理 ' + (job.processed_files || 0) + ' / ' + (job.total_files || 0) + ' 个文件');
    elements.indexDetail.textContent = progress + '% · ' + status.toLocaleUpperCase();
    elements.progressBar.style.width = progress + '%';
    elements.indexCancel.hidden = !running || cancelRequested;
    elements.indexCancel.disabled = cancelRequested;
    elements.indexButton.disabled = running;
  }

  function hideIndexProgress(delay) {
    window.clearTimeout(state.indexHideTimer);
    state.indexHideTimer = window.setTimeout(function () {
      elements.indexProgress.classList.remove('is-running', 'is-terminal', 'is-failed');
      elements.indexProgress.setAttribute('aria-hidden', 'true');
      elements.indexCancel.hidden = true;
      elements.indexCancel.disabled = true;
      elements.indexButton.disabled = false;
    }, delay || 0);
  }

  function clearIndexPolling() {
    if (state.indexTimer) {
      window.clearInterval(state.indexTimer);
      state.indexTimer = null;
    }
  }

  function rememberIndexJob(jobId) {
    state.indexJobId = normalizeId(jobId);
    try {
      if (state.indexJobId) {
        window.localStorage.setItem(ACTIVE_INDEX_STORAGE_KEY, String(state.indexJobId));
      } else {
        window.localStorage.removeItem(ACTIVE_INDEX_STORAGE_KEY);
      }
    } catch (_error) {
      // localStorage 不可用时仍可在当前页面轮询。
    }
  }

  function finishIndexJob(job) {
    clearIndexPolling();
    rememberIndexJob(null);
    hideIndexProgress(0);
    var status = String(job.status || '');
    if (status === 'success') {
      showToast(
        '结构化整理完成',
        (job.total_chunks || 0) + ' 个函数片段 · ' + (job.total_classes || 0) + ' 个类'
      );
    } else if (status === 'failed') {
      showToast('结构化整理失败', job.error_message || '请稍后重试。', 'error');
    } else if (status === 'canceled') {
      showToast('结构化整理已取消', job.error_message || '任务已停止。');
    }
  }

  function pollIndexJob(jobId) {
    var normalizedId = normalizeId(jobId);
    if (!normalizedId) return;
    clearIndexPolling();
    rememberIndexJob(normalizedId);
    function update() {
      requestJson(endpoints.indexStatus + '/' + encodeURIComponent(normalizedId)).then(function (payload) {
        var job = payload.job || {};
        var status = String(job.status || '').toLocaleLowerCase();
        if (status === 'queued' || status === 'pending' || status === 'running') {
          showIndexProgress(job);
        } else {
          finishIndexJob(job);
        }
      }).catch(function (error) {
        clearIndexPolling();
        if (error.status === 404) rememberIndexJob(null);
        hideIndexProgress(0);
        elements.indexButton.disabled = false;
        showToast('无法读取整理进度', error.message, 'error');
      });
    }
    update();
    state.indexTimer = window.setInterval(update, 1500);
  }

  function resumeIndexJob() {
    var localJobId = null;
    try {
      localJobId = normalizeId(window.localStorage.getItem(ACTIVE_INDEX_STORAGE_KEY));
    } catch (_error) {
      localJobId = null;
    }
    if (localJobId) {
      pollIndexJob(localJobId);
      return;
    }
    requestJson(endpoints.indexActive).then(function (payload) {
      if (payload.has_active && payload.job) pollIndexJob(payload.job.id);
    }).catch(function () {
      // 恢复状态失败不阻断仓库使用。
    });
  }

  function startIndexBuild() {
    if (state.indexJobId) {
      pollIndexJob(state.indexJobId);
      return;
    }
    elements.indexButton.disabled = true;
    postJson(endpoints.indexBuild, {}).then(function (payload) {
      showToast(
        payload.attached ? '已恢复结构化整理' : '已开始结构化整理',
        payload.message || '进度会显示在页面顶部。'
      );
      pollIndexJob(payload.job_id);
    }).catch(function (error) {
      var activeId = normalizeId(
        error.payload && (error.payload.active_job_id || (error.payload.job || {}).id)
      );
      if (error.status === 409 && activeId) {
        showToast('已有整理任务', '已恢复现有任务进度；如需停止，请使用顶部“取消整理”。');
        pollIndexJob(activeId);
      } else {
        showToast('无法开始结构化整理', error.message, 'error');
        elements.indexButton.disabled = false;
      }
    });
  }

  function cancelIndexBuild() {
    if (!state.indexJobId) return;
    elements.indexCancel.disabled = true;
    var cancelUrl = String(endpoints.indexCancel || '')
      .replace('{job_id}', encodeURIComponent(state.indexJobId));
    postJson(cancelUrl, {}).then(function (payload) {
      var job = payload.job || {
        status: 'canceled',
        progress: Number(elements.progressBar.style.width.replace('%', '')) || 0,
        progress_message: '任务已由用户取消',
      };
      var status = String(job.status || '').toLocaleLowerCase();
      if (status === 'success' || status === 'failed' || status === 'canceled') {
        finishIndexJob(job);
      } else {
        job.progress_message = job.progress_message || '正在安全停止结构化整理…';
        showIndexProgress(job);
        pollIndexJob(state.indexJobId);
      }
    }).catch(function (error) {
      showToast('取消失败', error.message, 'error');
    }).finally(function () {
      elements.indexCancel.disabled = false;
    });
  }

  function searchSemantic(event) {
    event.preventDefault();
    var query = elements.semanticQuery.value.trim();
    if (!query) {
      elements.semanticQuery.focus();
      return;
    }
    elements.semanticMeta.textContent = '正在检索…';
    elements.semanticList.innerHTML =
      '<div class="repository-inspector-empty">' +
        '<span class="math-curve-loader" data-math-curve-loader data-size="sm">' +
          '<span class="math-curve-loader__label">正在检索代码…</span>' +
        '</span>' +
      '</div>';
    postJson(endpoints.indexSearch, {
      query: query,
      top_k: 10,
      score_threshold: 0.05,
    }).then(function (payload) {
      var hits = payload.hits || [];
      elements.semanticMeta.textContent =
        '检索模型 ' + (payload.embedding_model || 'unknown') + ' · 命中 ' + hits.length + ' 条';
      elements.semanticList.innerHTML = hits.length
        ? hits.map(function (hit, index) {
            return (
              '<button class="repository-semantic-hit" type="button"' +
                ' data-semantic-path="' + escapeHtml(hit.filename || '') + '"' +
                ' data-semantic-line="' + escapeHtml(hit.start_line || 1) + '">' +
                '<span><strong>' + (index + 1) + '. ' + escapeHtml(hit.qualified_name || hit.filename || '未命名结构') +
                  '</strong><em>' + Number(hit.score || 0).toFixed(3) + '</em></span>' +
                '<small>' + escapeHtml(hit.filename || '') + ' · L' +
                  escapeHtml(hit.start_line || '-') + '–' + escapeHtml(hit.end_line || '-') + '</small>' +
                '<p>' + escapeHtml(hit.summary || hit.signature || '暂无说明') + '</p>' +
              '</button>'
            );
          }).join('')
        : '<div class="repository-inspector-empty">没有命中结果。可以调整描述，或先重新结构化整理。</div>';
    }).catch(function (error) {
      elements.semanticMeta.textContent = '检索失败';
      elements.semanticList.innerHTML =
        '<div class="repository-inspector-empty">' + escapeHtml(error.message) + '</div>';
    });
  }

  function activateInspector(name) {
    root.querySelectorAll('[data-repository-inspector]').forEach(function (button) {
      var active = button.dataset.repositoryInspector === name;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    root.querySelectorAll('[data-repository-panel]').forEach(function (panel) {
      panel.classList.toggle('active', panel.dataset.repositoryPanel === name);
    });
    if (name === 'semantic') elements.semanticQuery.focus();
  }

  function openFilesDrawer() {
    root.classList.add('is-files-open');
    elements.mobileFiles.setAttribute('aria-expanded', 'true');
    elements.drawerBackdrop.hidden = false;
  }

  function closeFilesDrawer() {
    root.classList.remove('is-files-open');
    elements.mobileFiles.setAttribute('aria-expanded', 'false');
    window.setTimeout(function () {
      if (!root.classList.contains('is-files-open')) elements.drawerBackdrop.hidden = true;
    }, 200);
  }

  function bindTreeEvents() {
    elements.tree.addEventListener('input', function (event) {
      var input = event.target.closest('[data-tree-inline-create]');
      if (!input || !state.inlineCreate) return;
      state.inlineCreate.value = input.value;
      state.inlineCreate.error = '';
      input.setAttribute('aria-invalid', 'false');
      var inlineRow = input.closest('.repository-tree-inline');
      if (inlineRow) {
        inlineRow.classList.remove('is-invalid');
        var help = inlineRow.querySelector('.repository-tree-inline-field small');
        if (help) help.textContent = 'Enter 创建 · Esc 取消';
      }
    });

    elements.tree.addEventListener('keydown', function (event) {
      var input = event.target.closest('[data-tree-inline-create]');
      if (!input || !state.inlineCreate) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        cancelInlineCreate();
      } else if (event.key === 'Enter') {
        event.preventDefault();
        state.inlineCreate.value = input.value;
        void submitInlineCreate();
      }
    });

    elements.tree.addEventListener('click', function (event) {
      var toggle = event.target.closest('[data-tree-toggle]');
      if (toggle) {
        var toggleId = normalizeId(toggle.dataset.treeToggle);
        var key = String(toggleId);
        if (state.expanded.has(key)) state.expanded.delete(key);
        else state.expanded.add(key);
        renderTree();
        return;
      }
      var menu = event.target.closest('[data-tree-menu]');
      if (menu) {
        event.stopPropagation();
        showContextMenu(entryForId(menu.dataset.treeMenu), menu);
        return;
      }
      var opener = event.target.closest('[data-tree-open]');
      if (!opener) return;
      var entry = entryForId(opener.dataset.treeOpen);
      if (!entry) return;
      if (entry.kind === 'directory') {
        state.focusedDirectoryId = entry.id;
        var directoryKey = String(entry.id);
        if (state.expanded.has(directoryKey)) state.expanded.delete(directoryKey);
        else state.expanded.add(directoryKey);
        renderTree();
      } else {
        void openFile(entry.id);
      }
    });

    elements.tree.addEventListener('dblclick', function (event) {
      var opener = event.target.closest('[data-tree-open]');
      if (!opener) return;
      var entry = entryForId(opener.dataset.treeOpen);
      if (entry && entry.kind === 'directory') beginInlineCreate('file');
    });

    elements.tree.addEventListener('dragstart', function (event) {
      var row = event.target.closest('.repository-tree-row[data-entry-id]');
      if (!row) return;
      var entry = entryForId(row.dataset.entryId);
      if (!entry) return;
      state.draggedEntryId = entry.id;
      elements.tree.classList.add('is-internal-dragging');
      row.classList.add('is-dragging');
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('application/x-numoj-entry-id', String(entry.id));
      event.dataTransfer.setData('text/plain', entry.path);
    });

    function clearTreeDropIndicators() {
      elements.tree.classList.remove('is-root-drop-target');
      elements.tree.querySelectorAll('.is-drop-target').forEach(function (item) {
        item.classList.remove('is-drop-target');
      });
    }

    elements.tree.addEventListener('dragover', function (event) {
      if (!state.draggedEntryId) return;
      clearTreeDropIndicators();
      var anyRow = event.target.closest('.repository-tree-row[data-entry-id]');
      var row = event.target.closest('.repository-tree-row[data-entry-kind="directory"]');
      var droppingAtRoot = !anyRow;
      if (!row && !droppingAtRoot) return;
      var source = entryForId(state.draggedEntryId);
      var destination = row ? entryForId(row.dataset.entryId) : null;
      if (!source || (row && !destination)) return;
      if (
        destination && (
          source.id === destination.id ||
          (source.kind === 'directory' && destination.path.indexOf(source.path + '/') === 0)
        )
      ) return;
      if (droppingAtRoot && source.parentId == null) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      if (row) row.classList.add('is-drop-target');
      else elements.tree.classList.add('is-root-drop-target');
    });

    elements.tree.addEventListener('drop', function (event) {
      if (!state.draggedEntryId) return;
      var anyRow = event.target.closest('.repository-tree-row[data-entry-id]');
      var row = event.target.closest('.repository-tree-row[data-entry-kind="directory"]');
      var droppingAtRoot = !anyRow;
      if (!row && !droppingAtRoot) return;
      event.preventDefault();
      var source = entryForId(state.draggedEntryId);
      var destinationId = row ? normalizeId(row.dataset.entryId) : null;
      state.draggedEntryId = null;
      clearTreeDropIndicators();
      elements.tree.classList.remove('is-internal-dragging');
      elements.tree.querySelectorAll('.is-drop-target, .is-dragging').forEach(function (item) {
        item.classList.remove('is-drop-target', 'is-dragging');
      });
      if (source && destinationId !== source.parentId) {
        void moveEntry(source, destinationId, source.name);
      }
    });

    elements.tree.addEventListener('dragend', function () {
      state.draggedEntryId = null;
      clearTreeDropIndicators();
      elements.tree.classList.remove('is-internal-dragging');
      elements.tree.querySelectorAll('.is-drop-target, .is-dragging').forEach(function (item) {
        item.classList.remove('is-drop-target', 'is-dragging');
      });
    });
  }

  function bindUploadEvents() {
    elements.chooseFiles.addEventListener('click', function () { elements.uploadFiles.click(); });
    elements.chooseFolder.addEventListener('click', function () { elements.uploadFolder.click(); });
    elements.uploadFiles.addEventListener('change', function (event) {
      var descriptors = Array.from(event.target.files || []).map(function (file) {
        return descriptorFromFile(file);
      });
      event.target.value = '';
      void addUploadDescriptors(descriptors, { append: true });
    });
    elements.uploadFolder.addEventListener('change', function (event) {
      var descriptors = Array.from(event.target.files || []).map(function (file) {
        return descriptorFromFile(file, file.webkitRelativePath || file.name);
      });
      event.target.value = '';
      void addUploadDescriptors(descriptors, { append: true });
    });
    elements.clearUploads.addEventListener('click', function () {
      state.upload.previewSequence += 1;
      resetUploadPreview({ cancel: true });
      state.upload.items = [];
      renderUploadQueue();
    });
    elements.uploadFileList.addEventListener('click', function (event) {
      var remove = event.target.closest('[data-upload-remove]');
      if (!remove) return;
      state.upload.items = state.upload.items.filter(function (item) {
        return item.key !== remove.dataset.uploadRemove;
      });
      state.upload.previewSequence += 1;
      resetUploadPreview();
      renderUploadQueue();
      if (state.upload.items.some(function (item) { return !item.error; })) void previewUploads();
    });
    elements.uploadFileList.addEventListener('change', function (event) {
      var pathFix = event.target.closest('[data-upload-path-fix]');
      if (pathFix) {
        var pathItem = state.upload.items.find(function (item) {
          return item.key === pathFix.dataset.uploadPathFix;
        });
        if (!pathItem) return;
        var checkedPath = validateUploadPath(pathFix.value);
        var destination = entryForId(state.upload.parentId);
        var finalPath = checkedPath.valid && destination && destination.path
          ? destination.path + '/' + checkedPath.path
          : checkedPath.path;
        var checkedFinalPath = checkedPath.valid
          ? validateUploadPath(finalPath)
          : checkedPath;
        var duplicate = checkedPath.valid && state.upload.items.some(function (candidate) {
          return candidate !== pathItem &&
            uploadItemKey(candidate.relativePath) === uploadItemKey(checkedPath.path);
        });
        if (!checkedPath.valid || !checkedFinalPath.valid || duplicate) {
          pathItem.pathError = duplicate
            ? '上传清单中已有相同路径'
            : !checkedPath.valid
              ? checkedPath.message
              : '目标目录下的最终路径无效：' + checkedFinalPath.message;
          pathItem.error = pathItem.pathError;
          renderUploadQueue();
          return;
        }
        state.upload.previewSequence += 1;
        resetUploadPreview({ cancel: true });
        pathItem.relativePath = checkedPath.path;
        pathItem.key = uploadItemKey(checkedPath.path);
        pathItem.pathError = '';
        pathItem.error = pathItem.sizeError || '';
        pathItem.serverStatus = pathItem.error ? 'invalid' : 'pending';
        renderUploadQueue();
        if (state.upload.items.every(function (item) { return !item.error; })) {
          void previewUploads();
        }
        return;
      }
      var resolution = event.target.closest('[data-upload-resolution]');
      if (resolution) {
        var resolutionItem = state.upload.items.find(function (item) {
          return item.key === resolution.dataset.uploadResolution;
        });
        if (resolutionItem) {
          resolutionItem.resolution = resolution.value;
          if (resolution.value === 'rename' && !resolutionItem.renameTarget) {
            resolutionItem.renameTarget = suggestedRenamePath(resolutionItem.relativePath);
          }
          renderUploadQueue();
        }
        return;
      }
      var encoding = event.target.closest('[data-upload-encoding]');
      if (encoding) {
        var encodingItem = state.upload.items.find(function (item) {
          return item.key === encoding.dataset.uploadEncoding;
        });
        if (encodingItem) encodingItem.encodingConfirmed = encoding.checked;
        renderUploadQueue();
      }
    });
    elements.uploadFileList.addEventListener('input', function (event) {
      var rename = event.target.closest('[data-upload-rename]');
      if (!rename) return;
      var item = state.upload.items.find(function (candidate) {
        return candidate.key === rename.dataset.uploadRename;
      });
      if (item) item.renameTarget = rename.value;
      elements.uploadConfirm.disabled = !uploadCanCommit();
    });

    ['dragenter', 'dragover'].forEach(function (eventName) {
      elements.uploadDropzone.addEventListener(eventName, function (event) {
        if (!hasExternalFiles(event)) return;
        event.preventDefault();
        event.stopPropagation();
        if (eventName === 'dragenter') state.dialogDragDepth += 1;
        elements.uploadDropzone.classList.add('is-dragover');
      });
    });
    elements.uploadDropzone.addEventListener('dragleave', function (event) {
      if (!hasExternalFiles(event)) return;
      event.preventDefault();
      event.stopPropagation();
      state.dialogDragDepth = Math.max(0, state.dialogDragDepth - 1);
      if (state.dialogDragDepth === 0) elements.uploadDropzone.classList.remove('is-dragover');
    });
    elements.uploadDropzone.addEventListener('drop', function (event) {
      if (!hasExternalFiles(event)) return;
      event.preventDefault();
      event.stopPropagation();
      state.dialogDragDepth = 0;
      elements.uploadDropzone.classList.remove('is-dragover');
      extractDropDescriptors(event.dataTransfer).then(function (descriptors) {
        return addUploadDescriptors(descriptors, { append: true });
      }).catch(function (error) {
        showToast('无法读取拖入内容', error.message || '请改用文件夹选择器。', 'error');
      });
    });
  }

  function bindGeneralEvents() {
    elements.fileFilter.addEventListener('input', renderTree);
    elements.newFile.addEventListener('click', function () { beginInlineCreate('file'); });
    elements.newDirectory.addEventListener('click', function () { beginInlineCreate('directory'); });
    elements.upload.addEventListener('click', function () { openUploadDialog([], actionDirectoryId()); });
    elements.save.addEventListener('click', function () { void saveCurrentFile(); });
    elements.manageCurrent.addEventListener('click', function () {
      if (state.current) openMoveDialog(entryForId(state.current.id), 'move');
    });
    elements.deleteCurrent.addEventListener('click', function () {
      if (state.current) openDeleteDialog(entryForId(state.current.id));
    });
    elements.moveForm.addEventListener('submit', submitMove);
    elements.deleteConfirm.addEventListener('click', deleteEntry);
    elements.uploadForm.addEventListener('submit', commitUploads);
    elements.indexButton.addEventListener('click', startIndexBuild);
    elements.indexCancel.addEventListener('click', cancelIndexBuild);
    elements.semanticForm.addEventListener('submit', searchSemantic);
    elements.outlineList.addEventListener('click', function (event) {
      var item = event.target.closest('[data-outline-line]');
      if (item) revealLine(item.dataset.outlineLine);
    });
    elements.semanticList.addEventListener('click', function (event) {
      var hit = event.target.closest('[data-semantic-path]');
      if (!hit) return;
      var path = normalizeRelativePath(hit.dataset.semanticPath);
      var entry = state.entries.find(function (candidate) {
        return candidate.kind === 'file' &&
          (candidate.path === path || candidate.name === path);
      });
      if (entry) void openFile(entry.id, { line: Number(hit.dataset.semanticLine) || 1 });
    });
    root.querySelectorAll('[data-repository-inspector]').forEach(function (button) {
      button.addEventListener('click', function () {
        activateInspector(button.dataset.repositoryInspector);
      });
    });
    elements.mobileFiles.addEventListener('click', function () {
      if (root.classList.contains('is-files-open')) closeFilesDrawer();
      else openFilesDrawer();
    });
    elements.drawerBackdrop.addEventListener('click', closeFilesDrawer);

    root.querySelectorAll('[data-close-upload]').forEach(function (button) {
      button.addEventListener('click', function () {
        state.upload.previewSequence += 1;
        resetUploadPreview({ cancel: true });
        state.upload.items = [];
        renderUploadQueue();
        closeDialog(elements.uploadDialog);
      });
    });
    elements.uploadDialog.addEventListener('cancel', function (event) {
      event.preventDefault();
      state.upload.previewSequence += 1;
      resetUploadPreview({ cancel: true });
      state.upload.items = [];
      renderUploadQueue();
      closeDialog(elements.uploadDialog);
    });
    root.querySelectorAll('[data-close-move]').forEach(function (button) {
      button.addEventListener('click', function () { closeDialog(elements.moveDialog); });
    });
    root.querySelectorAll('[data-close-delete]').forEach(function (button) {
      button.addEventListener('click', function () {
        state.deletePreview = null;
        closeDialog(elements.deleteDialog);
      });
    });
    elements.conflictCopy.addEventListener('click', function () {
      resolveSaveConflictByBackup('copy');
    });
    elements.conflictDownload.addEventListener('click', function () {
      resolveSaveConflictByBackup('download');
    });
    elements.conflictReloadCheck.addEventListener('change', function () {
      elements.conflictReload.disabled = !elements.conflictReloadCheck.checked;
    });
    elements.conflictReload.addEventListener('click', reloadServerAfterConflict);
    elements.saveConflictDialog.addEventListener('cancel', function (event) {
      event.preventDefault();
    });

    elements.contextMenu.addEventListener('click', function (event) {
      var action = event.target.closest('[data-repository-action]');
      if (!action) return;
      var entry = entryForId(state.contextEntryId);
      var name = action.dataset.repositoryAction;
      hideContextMenu();
      if (!entry) return;
      if (name === 'rename' || name === 'move') openMoveDialog(entry, name);
      if (name === 'delete') openDeleteDialog(entry);
    });
    document.addEventListener('pointerdown', function (event) {
      if (!elements.contextMenu.hidden && !elements.contextMenu.contains(event.target)) {
        hideContextMenu();
      }
    });
    window.addEventListener('resize', hideContextMenu);
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        hideContextMenu();
        closeFilesDrawer();
      }
    });
    window.addEventListener('beforeunload', function (event) {
      if (state.current && state.current.dirty) {
        event.preventDefault();
        event.returnValue = '';
      }
    });
  }

  function bindExternalDropEvents() {
    elements.filesPane.addEventListener('dragenter', externalDragEnter);
    elements.filesPane.addEventListener('dragover', externalDragOver);
    elements.filesPane.addEventListener('dragleave', externalDragLeave);
    elements.filesPane.addEventListener('drop', externalDrop);
  }

  function initialize() {
    var siteShell = root.closest('.numoj-site-shell');
    var globalNavigationToggle = siteShell
      ? siteShell.querySelector('button[data-bs-target="#offcanvasNavbar"]')
      : null;
    if (globalNavigationToggle) {
      globalNavigationToggle.classList.add('repository-page-nav-toggle');
    }
    bindTreeEvents();
    bindUploadEvents();
    bindGeneralEvents();
    bindExternalDropEvents();
    updateEditorChrome();
    renderUploadQueue();
    loadTree().catch(function () {
      // 页面内已经呈现错误状态。
    });
    resumeIndexJob();
    initializeEditor().catch(function (error) {
      state.editorInitializing = false;
      updateEditorChrome();
      console.error('代码编辑器初始化失败。', error);
      showToast(
        '编辑器初始化失败',
        error && error.message ? error.message : '请刷新页面重试。',
        'error'
      );
    });
  }

  initialize();
})();
