(function () {
  "use strict";

  function parseResponse(response) {
    return response.json().catch(function () {
      return { success: false, message: "服务器返回了无法读取的响应。" };
    }).then(function (payload) {
      if (!response.ok || !payload.success) {
        var message = payload.message || payload.error || "操作失败，请稍后重试。";
        throw new Error(message);
      }
      return payload;
    });
  }

  function apiRequest(url, options) {
    var requestOptions = options || {};
    requestOptions.credentials = "same-origin";
    requestOptions.headers = requestOptions.headers || {};
    requestOptions.headers.Accept = "application/json";
    return fetch(url, requestOptions).then(parseResponse);
  }

  function setMessage(element, message, isError) {
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("is-error", Boolean(isError));
  }

  function setBusy(button, busy, busyText) {
    if (!button) return;
    if (busy) {
      button.dataset.originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = busyText || "处理中…";
    } else {
      button.disabled = false;
      if (button.dataset.originalLabel) {
        button.textContent = button.dataset.originalLabel;
        delete button.dataset.originalLabel;
      }
    }
  }

  function initCoverFallbacks() {
    document.querySelectorAll("[data-vibe-cover-image]").forEach(function (image) {
      image.addEventListener("error", function () {
        image.hidden = true;
        image.parentElement.classList.add("is-cover-missing");
        image.parentElement.setAttribute("aria-label", "作品封面暂时不可用");
      }, { once: true });
    });
  }

  function initGallery(root) {
    var search = root.querySelector("[data-vibe-search]");
    var cards = Array.prototype.slice.call(root.querySelectorAll("[data-vibe-card]"));
    var filters = Array.prototype.slice.call(root.querySelectorAll("[data-vibe-filter]"));
    var empty = root.querySelector("[data-vibe-empty]");
    var activeFilter = "all";

    function applyFilters() {
      var query = search ? search.value.trim().toLocaleLowerCase() : "";
      var visibleCount = 0;
      cards.forEach(function (card) {
        var haystack = [
          card.dataset.vibeTitle,
          card.dataset.vibeAuthor,
          card.dataset.vibeTags
        ].join(" ").toLocaleLowerCase();
        var matchesQuery = !query || haystack.indexOf(query) !== -1;
        var matchesKind = activeFilter === "all"
          || (activeFilter === "featured" && card.dataset.vibeFeatured === "true")
          || (activeFilter === "builtin" && card.dataset.vibeKind === "builtin");
        var visible = matchesQuery && matchesKind;
        card.hidden = !visible;
        if (visible) visibleCount += 1;
      });
      if (empty) empty.hidden = visibleCount !== 0;
    }

    if (search) search.addEventListener("input", applyFilters);
    filters.forEach(function (button) {
      button.addEventListener("click", function () {
        activeFilter = button.dataset.vibeFilter || "all";
        filters.forEach(function (candidate) {
          candidate.classList.toggle("is-active", candidate === button);
        });
        applyFilters();
      });
    });
    document.addEventListener("keydown", function (event) {
      var target = event.target;
      var isTyping = target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
      if (event.key === "/" && !isTyping && search) {
        event.preventDefault();
        search.focus();
      }
    });
  }

  function updateFileLabel(input) {
    var scope = input.closest("label") || input.parentElement;
    var label = scope ? scope.querySelector("[data-vibe-file-label]") : null;
    if (!label) return;
    label.textContent = input.files && input.files[0]
      ? input.files[0].name
      : "选择 ZIP 程序包";
  }

  function initFileFields(root) {
    root.querySelectorAll('input[type="file"]').forEach(function (input) {
      input.addEventListener("change", function () { updateFileLabel(input); });
    });
    root.querySelectorAll("[data-vibe-dropzone]").forEach(function (dropzone) {
      ["dragenter", "dragover"].forEach(function (name) {
        dropzone.addEventListener(name, function (event) {
          event.preventDefault();
          dropzone.classList.add("is-dragging");
        });
      });
      dropzone.addEventListener("dragleave", function () {
        dropzone.classList.remove("is-dragging");
      });
      dropzone.addEventListener("drop", function (event) {
        event.preventDefault();
        dropzone.classList.remove("is-dragging");
        var input = dropzone.querySelector('input[type="file"]');
        var files = event.dataTransfer && event.dataTransfer.files;
        if (!input || !files || !files.length) return;
        try {
          input.files = files;
          updateFileLabel(input);
        } catch (_error) {
          // 极旧浏览器不允许给 FileList 赋值；保留点击选择作为兼容入口。
        }
      });
    });
  }

  function closeRowMenus(row) {
    row.querySelectorAll(".vibe-row-menu[open]").forEach(function (details) {
      details.open = false;
    });
  }

  function showProjectPanel(row, panelName) {
    row.querySelectorAll("[data-vibe-panel]").forEach(function (panel) {
      panel.hidden = panel.dataset.vibePanel !== panelName;
    });
    closeRowMenus(row);
    var active = row.querySelector('[data-vibe-panel="' + panelName + '"]');
    if (active) {
      active.hidden = false;
      var focusTarget = active.querySelector("input, textarea");
      if (focusTarget) focusTarget.focus();
    }
  }

  function submitForm(form, url, method, busyText) {
    var button = form.querySelector('button[type="submit"]');
    setBusy(button, true, busyText);
    return apiRequest(url, { method: method, body: new FormData(form) })
      .finally(function () { setBusy(button, false); });
  }

  function initWorkspace(root) {
    initFileFields(root);

    root.querySelectorAll("[data-vibe-project]").forEach(function (row) {
      row.querySelectorAll("[data-vibe-toggle-panel]").forEach(function (button) {
        button.addEventListener("click", function () {
          showProjectPanel(row, button.dataset.vibeTogglePanel);
        });
      });
      row.querySelectorAll("[data-vibe-close-panel]").forEach(function (button) {
        button.addEventListener("click", function () {
          var panel = button.closest("[data-vibe-panel]");
          if (panel) panel.hidden = true;
        });
      });

      var versionForm = row.querySelector("[data-vibe-version-form]");
      if (versionForm) {
        versionForm.addEventListener("submit", function (event) {
          event.preventDefault();
          var slug = versionForm.dataset.slug;
          var url = root.dataset.versionUrlTemplate.replace("__SLUG__", encodeURIComponent(slug));
          var message = row.querySelector("[data-vibe-project-status]");
          setMessage(message, "正在上传并校验程序包…", false);
          submitForm(versionForm, url, "POST", "上传中…").then(function () {
            setMessage(message, "新版本已创建，正在刷新版本信息…", false);
            window.setTimeout(function () { window.location.reload(); }, 650);
          }).catch(function (error) {
            setMessage(message, error.message, true);
          });
        });
      }

      var metadataForm = row.querySelector("[data-vibe-metadata-form]");
      if (metadataForm) {
        metadataForm.addEventListener("submit", function (event) {
          event.preventDefault();
          var slug = metadataForm.dataset.slug;
          var url = root.dataset.projectUrlTemplate.replace("__SLUG__", encodeURIComponent(slug));
          var message = row.querySelector("[data-vibe-project-status]");
          submitForm(metadataForm, url, "PATCH", "保存中…").then(function () {
            setMessage(message, "作品信息已保存为新版本，正在刷新…", false);
            window.setTimeout(function () { window.location.reload(); }, 650);
          }).catch(function (error) {
            setMessage(message, error.message, true);
          });
        });
      }

      row.querySelectorAll("[data-vibe-submit-review], [data-vibe-request-featured]").forEach(function (button) {
        button.addEventListener("click", function () {
          var message = row.querySelector("[data-vibe-project-status]");
          var isFeatured = button.hasAttribute("data-vibe-request-featured");
          var isAdminPublish = button.hasAttribute("data-admin-publish");
          setBusy(button, true, "提交中…");
          apiRequest(button.dataset.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}"
          }).then(function () {
            closeRowMenus(row);
            setMessage(message, isFeatured
              ? "精品申请已提交。"
              : (isAdminPublish ? "新版本已直接发布。" : "审核申请已提交。"), false);
            button.remove();
            window.setTimeout(function () { window.location.reload(); }, 650);
          }).catch(function (error) {
            setMessage(message, error.message, true);
          }).finally(function () {
            if (button.isConnected) setBusy(button, false);
          });
        });
      });
    });

    var createForm = root.querySelector("[data-vibe-create-form]");
    if (createForm) {
      createForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var status = createForm.querySelector("[data-vibe-form-status]");
        setMessage(status, "正在上传并校验第一个版本…", false);
        submitForm(createForm, root.dataset.createUrl, "POST", "创建中…").then(function (payload) {
          var project = payload.project || {};
          setMessage(status, "作品已创建，正在打开工作台…", false);
          var target = project.slug ? "#project-" + encodeURIComponent(project.slug) : "";
          window.setTimeout(function () {
            window.location.href = window.location.pathname + target;
            window.location.reload();
          }, 650);
        }).catch(function (error) {
          setMessage(status, error.message, true);
        });
      });
    }
  }

  function initDetail(root) {
    var button = root.querySelector("[data-vibe-request-featured]");
    if (!button) return;
    button.addEventListener("click", function () {
      var status = root.querySelector("[data-vibe-action-status]");
      setBusy(button, true, "…");
      apiRequest(root.dataset.featuredUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      }).then(function () {
        setMessage(status, "精品申请已提交，管理员审核后会更新资源规格。", false);
        button.remove();
      }).catch(function (error) {
        setMessage(status, error.message, true);
      }).finally(function () {
        if (button.isConnected) setBusy(button, false);
      });
    });
  }

  function initReviewDesk(root) {
    var tabs = Array.prototype.slice.call(root.querySelectorAll("[data-vibe-review-tab]"));
    tabs.forEach(function (button) {
      button.addEventListener("click", function () {
        var target = button.dataset.vibeReviewTab;
        tabs.forEach(function (tab) { tab.classList.toggle("is-active", tab === button); });
        root.querySelectorAll("[data-vibe-review-panel]").forEach(function (panel) {
          panel.hidden = panel.dataset.vibeReviewPanel !== target;
        });
      });
    });

    root.querySelectorAll("[data-review-card]").forEach(function (card) {
      var form = card.querySelector("[data-vibe-review-form]");
      if (!form) return;
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var submitter = event.submitter || document.activeElement;
        var decision = submitter && submitter.value;
        if (decision !== "approve" && decision !== "reject") return;
        var slug = card.dataset.projectSlug;
        var template = card.dataset.reviewKind === "featured"
          ? root.dataset.featuredUrlTemplate
          : root.dataset.reviewUrlTemplate;
        var url = template.replace("__SLUG__", encodeURIComponent(slug));
        var status = form.querySelector("[data-vibe-review-status]");
        var note = form.elements.note ? form.elements.note.value : "";
        setBusy(submitter, true, decision === "approve" ? "通过中…" : "退回中…");
        apiRequest(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision: decision, note: note })
        }).then(function () {
          setMessage(status, decision === "approve" ? "已通过。" : "已退回作者修改。", false);
          card.classList.add("is-complete");
          window.setTimeout(function () { card.remove(); }, 450);
        }).catch(function (error) {
          setMessage(status, error.message, true);
          setBusy(submitter, false);
        });
      });
    });
  }

  initCoverFallbacks();
  document.querySelectorAll("[data-vibehub-app]").forEach(function (root) {
    var view = root.dataset.vibeView;
    if (view === "gallery") initGallery(root);
    if (view === "workspace") initWorkspace(root);
    if (view === "detail") initDetail(root);
    if (view === "review") initReviewDesk(root);
  });
}());
