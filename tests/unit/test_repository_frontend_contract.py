from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKBENCH_JS = ROOT / "static" / "app" / "repository" / "workbench.js"
WORKBENCH_CSS = ROOT / "static" / "styles" / "repository" / "workbench.css"


def test_folder_drop_reader_drains_every_webkit_directory_batch():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    helper_start = source.index("function readWebkitDirectory(reader)")
    walker_start = source.index("function walkWebkitEntry", helper_start)
    helper = source[helper_start:walker_start]

    assert "reader.readEntries" in helper
    assert "if (!next.length)" in helper
    assert "resolve(entries)" in helper
    assert helper.count("readNextBatch();") >= 2


def test_folder_drop_keeps_empty_directories_in_the_upload_manifest():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    walker_start = source.index("function walkWebkitEntry")
    extractor_start = source.index("function extractDropDescriptors", walker_start)
    walker = source[walker_start:extractor_start]

    assert "readWebkitDirectory(entry.createReader())" in walker
    assert "[descriptorFromDirectory(path)].concat(nested.flat())" in walker


def test_directory_upload_silently_ignores_ds_store_metadata_files():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    helper_start = source.index(
        "function isIgnoredDirectoryMetadataDescriptor"
    )
    add_start = source.index("function addUploadDescriptors", helper_start)
    helper = source[helper_start:add_start]
    server_map_start = source.index("function uploadServerEntryMap", add_start)
    add_descriptors = source[add_start:server_map_start]

    assert "descriptor.kind === 'directory'" in helper
    assert "file.webkitRelativePath || file.name" in helper
    assert "var parts = rawPath.split('/')" in helper
    assert "parts.length > 1" in helper
    assert "parts[parts.length - 1] === '.DS_Store'" in helper
    assert "expandUploadDirectories(descriptors)" in add_descriptors
    assert "!isIgnoredDirectoryMetadataDescriptor(descriptor)" in add_descriptors
    assert add_descriptors.index(
        "!isIgnoredDirectoryMetadataDescriptor(descriptor)"
    ) < add_descriptors.index(".map(inspectUploadDescriptor)")


def test_in_flight_save_never_marks_newer_editor_content_as_saved():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    change_start = source.index("editor.on('change'")
    extension_start = source.index("function extensionLabel", change_start)
    change_handler = source[change_start:extension_start]
    save_start = source.index("function saveCurrentFile")
    transition_start = source.index("function persistBeforeTransition", save_start)
    save = source[save_start:transition_start]

    assert "state.current.editRevision += 1" in change_handler
    assert "editRevision: state.current.editRevision" in save
    assert "state.current.editRevision !== snapshot.editRevision" in save
    assert "latestContent !== snapshot.content" in save
    assert "state.current.content = snapshot.content" not in save


def test_file_transition_drains_edits_made_while_save_is_in_flight():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    save_start = source.index("function saveCurrentFile")
    open_start = source.index("function openFile", save_start)
    transition_logic = source[save_start:open_start]

    assert "Object.assign({}, settings, { drain: true })" in transition_logic
    assert "saveCurrentFile({ silent: true, drain: true })" in transition_logic
    assert "!settings.drain" in transition_logic
    assert "return saveCurrentFile(settings)" in transition_logic


def test_save_conflict_backup_uses_the_latest_local_buffer():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    save_start = source.index("function saveCurrentFile")
    transition_start = source.index("function persistBeforeTransition", save_start)
    save = source[save_start:transition_start]

    assert "var latestSnapshot = snapshot" in save
    assert "state.codeEditor.getValue()" in save
    assert "openSaveConflictDialog(latestSnapshot, error)" in save


def test_repository_uses_the_shared_monaco_dark_plus_semantic_stack():
    source = WORKBENCH_JS.read_text(encoding="utf-8")
    template = (
        ROOT / "templates" / "repository" / "index.html"
    ).read_text(encoding="utf-8")
    runtime = (
        ROOT / "static" / "app" / "code-editor-runtime.js"
    ).read_text(encoding="utf-8")

    assert "{% include 'components/editor/monaco.html' %}" in template
    assert "components/editor/codemirror.html" not in template
    assert 'id="repositoryMonacoContainer"' in template
    assert "repositoryCodeMirrorContainer" not in template
    assert "await runtime.prepareMonaco(monaco)" in source
    assert "runtime.monacoOptions({" in source
    assert "context: 'repository'" in source
    assert "repositoryEntryId: function (model)" in source
    assert "'inmemory://repository/' + safeDocumentId" in source
    assert "previousModel.dispose()" in source
    assert "state.current ? 'entry-' + state.current.id" in source
    assert "semanticHighlighting.enabled" in runtime
    assert 'monaco.editor.setTheme("dark-plus")' in runtime
    assert 'h: "cpp"' in runtime
    assert "createCodeMirrorEditor" not in source
    assert "NumOJCodeMirrorReady" not in source
    assert "codeMirrorMode" not in source
    assert "matchMedia" not in source


def test_repository_boot_does_not_wait_for_editor_assets_before_file_actions():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    initialize_start = source.index("function initialize()")
    initialize = source[initialize_start:]

    assert initialize.index("bindTreeEvents()") < initialize.index(
        "initializeEditor().catch"
    )
    assert initialize.index("bindUploadEvents()") < initialize.index(
        "initializeEditor().catch"
    )
    assert initialize.index("loadTree().catch") < initialize.index(
        "initializeEditor().catch"
    )
    assert "editorInitializing: true" in source
    assert "repositoryEditorLoading" in source


def test_blocking_upload_directory_uses_cascading_exclude_instead_of_error():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    apply_start = source.index("function applyUploadSessionPayload")
    digest_start = source.index("function digestSha256", apply_start)
    apply_payload = source[apply_start:digest_start]

    directory_branch = apply_payload[
        apply_payload.index("item.kind === 'directory'") :
        apply_payload.index(
            "} else if (item.serverStatus === 'blocking_conflict')",
            apply_payload.index("item.kind === 'directory'"),
        )
    ]
    assert "item.error = ''" in directory_branch
    assert "item.resolution = 'exclude'" in directory_branch
    assert "item.error = item.serverMessage" not in directory_branch


def test_upload_directory_exclusion_cascades_to_all_descendants():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    helper_start = source.index("function uploadExcludedDirectoryFor")
    apply_start = source.index("function applyUploadSessionPayload", helper_start)
    helper = source[helper_start:apply_start]

    assert "candidate.kind !== 'directory'" in helper
    assert "candidate.serverStatus !== 'blocking_conflict'" in helper
    assert "candidate.resolution !== 'exclude'" in helper
    assert "itemPath !== directoryPath" in helper
    assert "itemPath.indexOf(directoryPath + '/') !== 0" in helper


def test_upload_directory_exclusion_is_visible_and_commit_safe():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    markup_start = source.index("function uploadStateMarkup")
    commit_check_start = source.index("function uploadCanCommit", markup_start)
    markup = source[markup_start:commit_check_start]
    render_start = source.index("function renderUploadQueue", commit_check_start)
    commit_check = source[commit_check_start:render_start]
    open_dialog_start = source.index("function openUploadDialog", render_start)
    render = source[render_start:open_dialog_start]
    commit_start = source.index("function commitUploads")
    descriptors_start = source.index("function descriptorFromFile", commit_start)
    commit = source[commit_start:descriptors_start]

    assert "排除此目录及全部后代" in markup
    assert "一并排除" in markup
    assert "if (uploadExcludedDirectoryFor(item)) return true" in commit_check
    assert "return excludedDirectory.key === item.key" in commit_check
    assert "var removeMarkup = cascadeExcluded" in render
    assert "? ''" in render
    assert "resolutions[item.relativePath] = 'exclude'" in commit
    assert "if (excludedDirectory.key === item.key)" in commit


def test_upload_path_validation_includes_the_selected_destination_directory():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    inspect_start = source.index("function inspectUploadDescriptor")
    session_url_start = source.index("function uploadSessionUrl", inspect_start)
    inspect = source[inspect_start:session_url_start]

    assert "var destination = entryForId(state.upload.parentId)" in inspect
    assert "destination.path + '/' + checked.path" in inspect
    assert "目标目录下的最终路径无效" in inspect


def test_upload_queue_uses_the_defined_extension_label_helper():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    render_start = source.index("function renderUploadQueue")
    open_dialog_start = source.index("function openUploadDialog", render_start)
    render = source[render_start:open_dialog_start]

    assert "extensionLabel(item.relativePath)" in render
    assert "fileTypeLabel(" not in source


def test_upload_manifest_failure_reaches_a_visible_terminal_state():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    add_start = source.index("function addUploadDescriptors")
    server_map_start = source.index("function uploadServerEntryMap", add_start)
    add_descriptors = source[add_start:server_map_start]

    assert "return Promise.resolve().then(function ()" in add_descriptors
    assert "读取上传清单失败：" in add_descriptors
    assert "state.upload.phase = 'error'" in add_descriptors
    assert "state.upload.errorMessage =" in add_descriptors
    assert "try {" in add_descriptors
    assert "renderUploadQueue()" in add_descriptors

    render_start = source.index("function renderUploadQueue")
    open_dialog_start = source.index("function openUploadDialog", render_start)
    render = source[render_start:open_dialog_start]
    assert "state.upload.phase === 'reading'" in render
    assert "state.upload.phase === 'error' && state.upload.errorMessage" in render


def test_repository_upload_has_an_http_sha256_fallback():
    source = WORKBENCH_JS.read_text(encoding="utf-8")
    template = (
        ROOT / "templates" / "repository" / "index.html"
    ).read_text(encoding="utf-8")

    digest_start = source.index("function digestSha256")
    prepare_start = source.index("function prepareUploadHashes", digest_start)
    digest = source[digest_start:prepare_start]

    assert "window.crypto && window.crypto.subtle" in digest
    assert "window.NumOJRepositorySha256.digestHex(buffer)" in digest
    assert template.index("app/repository/sha256.js") < template.index(
        "app/repository/workbench.js"
    )


def test_invalid_upload_path_can_be_corrected_or_excluded_without_blocking_batch():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    markup_start = source.index("function uploadStateMarkup")
    commit_check_start = source.index("function uploadCanCommit", markup_start)
    markup = source[markup_start:commit_check_start]
    listeners_start = source.index(
        "elements.uploadFileList.addEventListener('change'"
    )
    input_listener_start = source.index(
        "elements.uploadFileList.addEventListener('input'",
        listeners_start,
    )
    change_handler = source[listeners_start:input_listener_start]

    assert "data-upload-path-fix" in markup
    assert "修正上传相对路径" in markup
    assert "data-upload-remove" in source
    assert "validateUploadPath(pathFix.value)" in change_handler
    assert "resetUploadPreview({ cancel: true })" in change_handler
    assert "pathItem.error = pathItem.sizeError || ''" in change_handler
    assert "void previewUploads()" in change_handler


def test_tree_refresh_never_advances_the_open_buffer_file_version():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    apply_start = source.index("function applyTreePayload")
    load_start = source.index("function loadTree", apply_start)
    apply_tree = source[apply_start:load_start]

    assert "state.current.name = currentEntry.name" in apply_tree
    assert "state.current.path = currentEntry.path" in apply_tree
    assert "state.current.version = currentEntry.version" not in apply_tree


def test_index_progress_bar_is_only_visible_while_a_job_is_active():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    finish_start = source.index("function finishIndexJob")
    poll_start = source.index("function pollIndexJob", finish_start)
    finish = source[finish_start:poll_start]
    resume_start = source.index("function resumeIndexJob", poll_start)
    poll = source[poll_start:resume_start]

    assert "hideIndexProgress(0)" in finish
    assert "showIndexProgress(job)" not in finish
    assert "showToast(" in finish
    assert (
        "if (status === 'queued' || status === 'pending' || status === 'running')"
        in poll
    )
    assert "showIndexProgress(job)" in poll
    assert "finishIndexJob(job)" in poll
    assert "showToast('无法读取整理进度'" in poll


def test_hidden_index_progress_cannot_leave_a_focusable_cancel_button():
    source = WORKBENCH_JS.read_text(encoding="utf-8")
    template = (
        ROOT / "templates" / "repository" / "index.html"
    ).read_text(encoding="utf-8")

    hide_start = source.index("function hideIndexProgress")
    clear_start = source.index("function clearIndexPolling", hide_start)
    hide = source[hide_start:clear_start]

    assert 'id="repositoryIndexCancel" type="button" hidden' in template
    assert "elements.indexCancel.hidden = true" in hide
    assert "elements.indexCancel.disabled = true" in hide


def test_internal_tree_drag_can_move_an_entry_back_to_repository_root():
    source = WORKBENCH_JS.read_text(encoding="utf-8")

    drag_start = source.index("elements.tree.addEventListener('dragstart'")
    upload_start = source.index("function bindUploadEvents", drag_start)
    drag_handlers = source[drag_start:upload_start]

    assert "var droppingAtRoot = !anyRow" in drag_handlers
    assert "elements.tree.classList.add('is-internal-dragging')" in drag_handlers
    assert "elements.tree.classList.add('is-root-drop-target')" in drag_handlers
    assert "var destinationId = row ? normalizeId(row.dataset.entryId) : null" in drag_handlers
    assert "destinationId !== source.parentId" in drag_handlers
    assert "clearTreeDropIndicators()" in drag_handlers


def test_file_action_tooltips_stack_above_the_search_field():
    source = WORKBENCH_CSS.read_text(encoding="utf-8")

    pane_start = source.index(".repository-files-pane {")
    pane_end = source.index("}", pane_start)
    pane = source[pane_start:pane_end]
    head_start = source.index(".repository-pane-head {")
    head_end = source.index("}", head_start)
    head = source[head_start:head_end]
    tooltip_start = source.index(".repository-file-tool::after {")
    tooltip_end = source.index("}", tooltip_start)
    tooltip = source[tooltip_start:tooltip_end]
    search_start = source.index(".repository-file-search {")
    search_end = source.index("}", search_start)
    search = source[search_start:search_end]

    assert "overflow: visible" in pane
    assert "overflow: visible" in head
    assert "z-index: 50" in head
    assert "z-index: 100" in tooltip
    assert "z-index: 1" in search
