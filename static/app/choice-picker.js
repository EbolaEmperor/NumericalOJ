(function (global) {
  'use strict';

  var controllers = [];

  function element(value) {
    return typeof value === 'string' ? document.getElementById(value) : value;
  }

  function closeOthers(except) {
    controllers.forEach(function (controller) {
      if (controller !== except) controller.setOpen(false);
    });
  }

  function create(config) {
    config = config || {};
    var picker = element(config.picker);
    var input = element(config.input);
    var trigger = element(config.trigger);
    var menu = element(config.menu);
    var label = element(config.label);
    var icon = element(config.icon);
    if (!picker || !input || !trigger || !menu) return null;
    if (picker.__choicePickerController) return picker.__choicePickerController;

    function options() {
      return Array.prototype.slice.call(menu.querySelectorAll('[data-choice-value]'));
    }

    var controller = {
      picker: picker,
      value: function () { return input.value; },
      setOpen: function (open) {
        picker.classList.toggle('open', !!open);
        trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
      },
      setValue: function (value, notify) {
        var choices = options();
        var selected = choices.find(function (choice) {
          return choice.getAttribute('data-choice-value') === value;
        }) || choices[0];
        if (!selected) return;
        input.value = selected.getAttribute('data-choice-value') || value || '';
        if (label) {
          label.textContent = selected.getAttribute('data-choice-label') || selected.textContent.trim();
        }
        if (icon) {
          icon.className = 'fas ' + (selected.getAttribute('data-choice-icon') || 'fa-circle');
        }
        choices.forEach(function (choice) {
          var active = choice === selected;
          choice.classList.toggle('active', active);
          choice.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        var shouldNotify = notify == null ? config.notifyByDefault === true : notify === true;
        if (shouldNotify) {
          if (typeof config.onChange === 'function') config.onChange(input.value);
          if (config.dispatchChange !== false) {
            input.dispatchEvent(new Event('change', {bubbles: true}));
          }
        }
      }
    };

    trigger.addEventListener('click', function (event) {
      event.stopPropagation();
      var willOpen = !picker.classList.contains('open');
      closeOthers(controller);
      controller.setOpen(willOpen);
    });
    trigger.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        trigger.click();
      } else if (event.key === 'Escape') {
        controller.setOpen(false);
      }
    });
    menu.addEventListener('click', function (event) {
      var choice = event.target.closest('[data-choice-value]');
      if (!choice || !menu.contains(choice)) return;
      controller.setValue(choice.getAttribute('data-choice-value'), true);
      controller.setOpen(false);
    });

    picker.__choicePickerController = controller;
    controllers.push(controller);
    controller.setValue(input.value, config.notifyOnInit === true);
    return controller;
  }

  function init(root) {
    root = root || document;
    return Array.prototype.slice.call(root.querySelectorAll('[data-rk-choice]')).map(function (picker) {
      return create({
        picker: picker,
        input: picker.getAttribute('data-rk-choice-input') || '',
        trigger: picker.querySelector('.rk-choice-trigger'),
        menu: picker.querySelector('.rk-choice-menu'),
        label: picker.querySelector('[data-rk-choice-label]'),
        icon: picker.querySelector('[data-rk-choice-icon]')
      });
    }).filter(Boolean);
  }

  document.addEventListener('click', function (event) {
    var inside = controllers.some(function (controller) {
      return controller.picker.contains(event.target);
    });
    if (!inside) closeOthers(null);
  });
  document.addEventListener('DOMContentLoaded', function () { init(document); });

  global.ChoicePicker = Object.freeze({create: create, init: init, closeAll: closeOthers});
})(window);
