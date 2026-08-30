(function () {
  "use strict";

  var modalElement = document.getElementById("homeworkDeadlineWarningModal");
  if (!modalElement || typeof bootstrap === "undefined") return;

  var modal = bootstrap.Modal.getOrCreateInstance(modalElement);
  var list = modalElement.querySelector("[data-deadline-warning-list]");
  var lead = modalElement.querySelector(".problem-deadline-modal-lead");
  var error = modalElement.querySelector("[data-deadline-warning-error]");
  var confirmButton = modalElement.querySelector("[data-deadline-warning-confirm]");
  var submitContextUrl = modalElement.getAttribute("data-submit-context-url");
  var pendingForm = null;
  var submittingConfirmedForm = false;

  function acknowledgementInput(form) {
    var input = form.querySelector('input[name="deadline_warning_ack"]');
    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = "deadline_warning_ack";
      form.appendChild(input);
    }
    return input;
  }

  function renderWarning(warning) {
    list.replaceChildren();
    error.hidden = true;
    lead.hidden = false;
    confirmButton.hidden = false;
    confirmButton.disabled = false;
    (warning.homeworks || []).forEach(function (homework) {
      var item = document.createElement("li");
      var className = document.createElement("strong");
      var deadline = document.createElement("span");
      className.textContent = homework.class_cn || homework.class_en || "未命名班级";
      deadline.textContent = "截止 " + (homework.ddl || "—");
      item.append(className, deadline);
      list.appendChild(item);
    });
  }

  function renderLoadError() {
    list.replaceChildren();
    lead.hidden = true;
    confirmButton.hidden = true;
    error.textContent = "暂时无法确认作业截止状态，请关闭提示后重试。";
    error.hidden = false;
    modal.show();
  }

  function submitConfirmed(form) {
    acknowledgementInput(form).value = "1";
    submittingConfirmedForm = true;
    HTMLFormElement.prototype.submit.call(form);
  }

  document.querySelectorAll("form.problem-submit-form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (submittingConfirmedForm) return;
      event.preventDefault();
      pendingForm = form;
      confirmButton.disabled = true;

      fetch(submitContextUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      })
        .then(function (response) {
          if (!response.ok) throw new Error("deadline status request failed");
          return response.json();
        })
        .then(function (payload) {
          var warning = payload && payload.submit_warning;
          if (!warning || !(warning.homeworks || []).length) {
            submitConfirmed(form);
            return;
          }
          renderWarning(warning);
          modal.show();
        })
        .catch(renderLoadError);
    });
  });

  confirmButton.addEventListener("click", function () {
    if (!pendingForm) return;
    var form = pendingForm;
    pendingForm = null;
    modal.hide();
    submitConfirmed(form);
  });

  modalElement.addEventListener("hidden.bs.modal", function () {
    if (!submittingConfirmedForm) pendingForm = null;
  });
})();
