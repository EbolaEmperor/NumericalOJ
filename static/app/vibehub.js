(function () {
  "use strict";

  function one(selector, scope) {
    return (scope || document).querySelector(selector);
  }

  function all(selector, scope) {
    return Array.from((scope || document).querySelectorAll(selector));
  }

  async function apiRequest(url, options) {
    var config = Object.assign({ credentials: "same-origin" }, options || {});
    config.headers = Object.assign({ Accept: "application/json" }, config.headers || {});
    var response = await fetch(url, config);
    var payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw new Error("服务器返回了无法读取的响应。");
    }
    if (!response.ok || !payload.success) {
      throw new Error(payload.message || payload.error || "操作失败，请稍后重试。");
    }
    return payload;
  }

  function showMessage(element, text, error) {
    if (!element) return;
    element.textContent = text || "";
    element.classList.toggle("is-error", Boolean(error));
  }

  function setBusy(button, busy, label) {
    if (!button) return;
    if (busy) {
      button.dataset.idleHtml = button.innerHTML;
      button.disabled = true;
      button.textContent = label || "处理中…";
    } else {
      button.disabled = false;
      if (button.dataset.idleHtml) button.innerHTML = button.dataset.idleHtml;
      delete button.dataset.idleHtml;
    }
  }

  function projectUrl(template, slug) {
    return template.replace("__SLUG__", encodeURIComponent(slug));
  }

  function openDialog(dialog, focusTarget) {
    if (!dialog || dialog.open) return;
    dialog._returnFocus = document.activeElement;
    dialog.showModal();
    document.body.classList.add("vibe-modal-open");
    requestAnimationFrame(function () {
      dialog.classList.add("is-open");
      if (focusTarget) focusTarget.focus();
    });
  }

  function closeDialog(dialog) {
    if (dialog && dialog.open) dialog.close();
  }

  function setupDialog(dialog, closeSelector) {
    if (!dialog) return;
    all(closeSelector, dialog).forEach(function (button) {
      button.addEventListener("click", function () { closeDialog(dialog); });
    });
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) closeDialog(dialog);
    });
    dialog.addEventListener("close", function () {
      dialog.classList.remove("is-open");
      if (!one("dialog.vibe-modal[open]")) document.body.classList.remove("vibe-modal-open");
      if (dialog._returnFocus && dialog._returnFocus.isConnected) dialog._returnFocus.focus();
      dialog._returnFocus = null;
    });
  }

  function initSharedVisuals() {
    var identicon = window.NumojIdenticon;
    if (identicon) {
      all(".vibe-author-avatar[data-avatar-seed]").forEach(function (avatar) {
        var seed = avatar.dataset.avatarSeed || "numericaloj";
        identicon.paint(avatar, identicon.cellsForSeed(seed), avatar.dataset.avatarLabel || seed);
      });
    }
  }

  function initGallery(root) {
    var search = one("[data-vibe-search]", root);
    var cards = all("[data-vibe-card]", root);
    var filters = all("[data-vibe-filter]", root);
    var empty = one("[data-vibe-empty]", root);
    var activeFilter = root.dataset.initialFilter || "all";

    function applyFilters() {
      var query = search ? search.value.trim().toLocaleLowerCase() : "";
      var visible = 0;
      cards.forEach(function (card) {
        var text = (card.dataset.vibeTitle + " " + card.dataset.vibeAuthor).toLocaleLowerCase();
        var match = !query || text.includes(query);
        match = match && (
          activeFilter === "all"
          || (activeFilter === "featured" && card.dataset.vibeFeatured === "true")
          || (activeFilter === "mine" && card.dataset.vibeMine === "true")
        );
        card.hidden = !match;
        if (match) visible += 1;
      });
      filters.forEach(function (button) {
        var selected = button.dataset.vibeFilter === activeFilter;
        button.classList.toggle("is-active", selected);
        button.setAttribute("aria-pressed", selected ? "true" : "false");
      });
      if (empty) empty.hidden = visible !== 0;
    }

    if (!filters.some(function (button) { return button.dataset.vibeFilter === activeFilter; })) {
      activeFilter = "all";
    }
    filters.forEach(function (button) {
      button.addEventListener("click", function () {
        activeFilter = button.dataset.vibeFilter;
        applyFilters();
      });
    });
    if (search) search.addEventListener("input", applyFilters);
    document.addEventListener("keydown", function (event) {
      if (event.key !== "/" || one("dialog.vibe-modal[open]")) return;
      if (/^(INPUT|TEXTAREA|SELECT)$/.test((event.target || {}).tagName || "")) return;
      event.preventDefault();
      search.focus();
    });
    applyFilters();

    var projectDialog = one("[data-vibe-project-modal]", root);
    var projectForm = one("[data-vibe-project-form]", root);
    if (!projectDialog || !projectForm) return;
    var projectStatus = one("[data-vibe-form-status]", projectDialog);
    var projectSubmit = one("[data-vibe-submit-project]", projectDialog);
    var loadGeneration = 0;
    var loadController = null;

    function cancelLoad() {
      loadGeneration += 1;
      if (loadController) loadController.abort();
      loadController = null;
    }

    function setFileLabel() {
      var input = projectForm.elements.package;
      var label = one("[data-vibe-file-label]", projectForm);
      label.textContent = input.files.length
        ? input.files[0].name
        : (input.required ? "选择 ZIP 程序包" : "保留现有程序包");
    }

    function configureForm(mode, project) {
      var editing = mode === "edit";
      project = project || {};
      projectForm.reset();
      projectForm.dataset.mode = mode;
      projectForm.dataset.slug = project.slug || "";
      projectForm.elements.package.required = !editing;
      one("[data-vibe-modal-title]", projectDialog).textContent = editing ? "编辑作品" : "创建作品";
      one("[data-vibe-modal-description]", projectDialog).textContent = editing
        ? "修改信息，可选上传新的完整程序包。"
        : "上传一个完整的 VibeHub ZIP 程序包。";
      projectSubmit.textContent = editing ? "更新并提交审核" : "创建并提交审核";
      projectForm.elements.title.value = project.title || "";
      setFileLabel();
      showMessage(projectStatus, "");
    }

    async function openEditor(button) {
      cancelLoad();
      var generation = loadGeneration;
      var slug = button.dataset.projectSlug;
      loadController = new AbortController();
      configureForm("edit", { slug: slug });
      showMessage(projectStatus, "正在读取作品信息…");
      openDialog(projectDialog, one("[data-vibe-close-modal]", projectDialog));
      button.disabled = true;
      try {
        var payload = await apiRequest(
          projectUrl(root.dataset.projectUrlTemplate, slug) + "?view=latest",
          { signal: loadController.signal }
        );
        if (generation !== loadGeneration) return;
        configureForm("edit", payload.project);
        projectForm.elements.title.focus();
      } catch (error) {
        if (error.name !== "AbortError" && generation === loadGeneration) {
          showMessage(projectStatus, error.message, true);
        }
      } finally {
        button.disabled = false;
        if (generation === loadGeneration) loadController = null;
      }
    }

    setupDialog(projectDialog, "[data-vibe-close-modal]");
    if (projectDialog) projectDialog.addEventListener("close", cancelLoad);
    all("[data-vibe-open-create]", root).forEach(function (button) {
      button.addEventListener("click", function () {
        cancelLoad();
        configureForm("create");
        openDialog(projectDialog, projectForm.elements.title);
      });
    });
    all("[data-vibe-edit-project]", root).forEach(function (button) {
      button.addEventListener("click", function () { openEditor(button); });
    });
    projectForm.elements.package.addEventListener("change", setFileLabel);

    projectForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var editing = projectForm.dataset.mode === "edit";
      var hasPackage = projectForm.elements.package.files.length > 0;
      if (!editing && !hasPackage) {
        showMessage(projectStatus, "请选择 ZIP 程序包。", true);
        projectForm.elements.package.focus();
        return;
      }
      var data = new FormData(projectForm);
      data.set("submit_for_review", "true");
      var url = root.dataset.createUrl;
      var method = "POST";
      if (editing) {
        url = projectUrl(
          hasPackage ? root.dataset.versionUrlTemplate : root.dataset.editUrlTemplate,
          projectForm.dataset.slug
        );
        method = hasPackage ? "POST" : "PATCH";
      }
      showMessage(projectStatus, editing ? "正在更新并提交审核…" : "正在创建并提交审核…");
      setBusy(projectSubmit, true, "提交中…");
      try {
        await apiRequest(url, { method: method, body: data });
        showMessage(projectStatus, "已进入审核队列，正在刷新我的作品…");
        setTimeout(function () { window.location.assign("/vibehub/?view=mine"); }, 350);
      } catch (error) {
        showMessage(projectStatus, error.message, true);
        setBusy(projectSubmit, false);
      }
    });

    var approveDialog = one("[data-vibe-approve-modal]", root);
    var approveSubmit = one("[data-vibe-confirm-approve]", approveDialog);
    var approveStatus = one("[data-vibe-approve-status]", approveDialog);
    setupDialog(approveDialog, "[data-vibe-close-approve]");
    all("[data-vibe-approve-project]", root).forEach(function (button) {
      button.addEventListener("click", function () {
        approveDialog.dataset.slug = button.dataset.projectSlug;
        approveDialog.dataset.version = button.dataset.projectVersion;
        one("[data-vibe-approve-description]", approveDialog).textContent =
          "通过《" + button.dataset.projectTitle + "》后，当前待审版本会立即公开。";
        showMessage(approveStatus, "");
        openDialog(approveDialog, approveSubmit);
      });
    });
    if (approveSubmit) {
      approveSubmit.addEventListener("click", async function () {
        setBusy(approveSubmit, true, "通过中…");
        try {
          await apiRequest(projectUrl(root.dataset.adminReviewUrlTemplate, approveDialog.dataset.slug), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              decision: "approve",
              note: "",
              expected_version: Number(approveDialog.dataset.version)
            })
          });
          showMessage(approveStatus, "审核已通过，正在刷新…");
          setTimeout(function () { window.location.reload(); }, 300);
        } catch (error) {
          showMessage(approveStatus, error.message, true);
          setBusy(approveSubmit, false);
        }
      });
    }

    var initialSlug = root.dataset.initialEdit;
    var initialButton = all("[data-vibe-edit-project]", root).find(function (button) {
      return button.dataset.projectSlug === initialSlug;
    });
    if (initialButton) openEditor(initialButton);
  }

  function initReviewDesk(root) {
    all("[data-vibe-review-tab]", root).forEach(function (button) {
      button.addEventListener("click", function () {
        all("[data-vibe-review-tab]", root).forEach(function (tab) {
          tab.classList.toggle("is-active", tab === button);
        });
        all("[data-vibe-review-panel]", root).forEach(function (panel) {
          panel.hidden = panel.dataset.vibeReviewPanel !== button.dataset.vibeReviewTab;
        });
      });
    });

    all("[data-review-card]", root).forEach(function (card) {
      var form = one("[data-vibe-review-form]", card);
      if (!form) return;
      form.addEventListener("submit", async function (event) {
        event.preventDefault();
        var submitter = event.submitter;
        var featured = card.dataset.reviewKind === "featured";
        var template = featured ? root.dataset.featuredUrlTemplate : root.dataset.reviewUrlTemplate;
        var status = one("[data-vibe-review-status]", form);
        setBusy(submitter, true, submitter.value === "approve" ? "通过中…" : "退回中…");
        try {
          await apiRequest(projectUrl(template, card.dataset.projectSlug), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              decision: submitter.value,
              note: form.elements.note.value,
              expected_version: featured ? null : Number(card.dataset.projectVersion)
            })
          });
          showMessage(status, submitter.value === "approve" ? "已通过。" : "已退回作者修改。");
          setTimeout(function () { card.remove(); }, 350);
        } catch (error) {
          showMessage(status, error.message, true);
          setBusy(submitter, false);
        }
      });
    });
  }

  initSharedVisuals();
  all("[data-vibehub-app]").forEach(function (root) {
    if (root.dataset.vibeView === "gallery") initGallery(root);
    if (root.dataset.vibeView === "review") initReviewDesk(root);
  });
}());
