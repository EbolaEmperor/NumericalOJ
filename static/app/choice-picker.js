(function (global) {
  'use strict';

  var controllers = [];
  var nextId = 1;

  function element(value) {
    return typeof value === 'string' ? document.getElementById(value) : value;
  }

  function connectedControllers() {
    controllers = controllers.filter(function (controller) {
      return controller.picker && controller.picker.isConnected;
    });
    return controllers;
  }

  function closeOthers(except) {
    connectedControllers().forEach(function (controller) {
      if (controller !== except) controller.setOpen(false);
    });
  }

  function optionLabel(option) {
    return option.getAttribute('data-choice-label') || option.textContent.trim();
  }

  function isOptionDisabled(option) {
    return option.disabled || option.getAttribute('aria-disabled') === 'true' ||
      option.getAttribute('data-choice-disabled') === 'true';
  }

  function optionsTemplate(input) {
    if (!input || !input.id) return null;
    return Array.prototype.slice.call(
      document.querySelectorAll('template[data-choice-options-for]')
    ).find(function (template) {
      return template.getAttribute('data-choice-options-for') === input.id;
    }) || null;
  }

  function hydrateStaticOptions(input, menu) {
    var template = optionsTemplate(input);
    if (!template) return;
    menu.replaceChildren(template.content.cloneNode(true));
  }

  function optionElement(entry) {
    entry = entry || {};
    var icon = String(entry.icon || 'fa-circle');
    var option = document.createElement('button');
    option.type = 'button';
    option.className = 'rk-choice-option' + (entry.missing ? ' is-missing' : '');
    option.setAttribute('data-choice-value', entry.value == null ? '' : String(entry.value));
    option.setAttribute('data-choice-label', String(entry.label || ''));
    option.setAttribute('data-choice-icon', icon);
    if (entry.disabled) {
      option.setAttribute('aria-disabled', 'true');
      option.setAttribute('data-choice-disabled', 'true');
    }

    var main = document.createElement('span');
    main.className = 'rk-choice-option-main';
    var iconElement = document.createElement('i');
    iconElement.className = icon.indexOf(' ') >= 0 ? icon : 'fas ' + icon;
    iconElement.setAttribute('aria-hidden', 'true');
    var copy = document.createElement('span');
    var name = document.createElement('span');
    name.className = 'rk-choice-option-name';
    name.textContent = String(entry.label || '');
    copy.appendChild(name);
    if (entry.meta) {
      var meta = document.createElement('span');
      meta.className = 'rk-choice-option-meta';
      meta.textContent = String(entry.meta);
      copy.appendChild(meta);
    }
    main.appendChild(iconElement);
    main.appendChild(copy);

    var check = document.createElement('i');
    check.className = 'fas fa-check rk-choice-option-check';
    check.setAttribute('aria-hidden', 'true');
    option.appendChild(main);
    option.appendChild(check);
    return option;
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

    hydrateStaticOptions(input, menu);

    var activeIndex = -1;
    var disabled = config.disabled === true || trigger.disabled === true || input.disabled === true;
    var required = input.getAttribute('data-choice-required') === 'true';
    var typeahead = '';
    var typeaheadTimer = null;

    if (!menu.id) menu.id = 'choice-picker-menu-' + nextId++;
    trigger.setAttribute('role', 'combobox');
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-controls', menu.id);
    menu.setAttribute('role', 'listbox');

    function options() {
      return Array.prototype.slice.call(menu.querySelectorAll('[data-choice-value]'));
    }

    function enabledOptions() {
      return options().filter(function (option) { return !isOptionDisabled(option); });
    }

    function selectedIndex() {
      return options().findIndex(function (option) {
        return option.getAttribute('data-choice-value') === String(input.value);
      });
    }

    function setActive(index) {
      var choices = options();
      choices.forEach(function (choice, optionIndex) {
        var active = optionIndex === index && !isOptionDisabled(choice);
        choice.classList.toggle('is-active', active);
        if (active) trigger.setAttribute('aria-activedescendant', choice.id);
      });
      activeIndex = index;
      if (index < 0 || !choices[index] || isOptionDisabled(choices[index])) {
        trigger.removeAttribute('aria-activedescendant');
        return;
      }
      if (picker.classList.contains('open')) {
        choices[index].scrollIntoView({block: 'nearest'});
      }
    }

    function prepareOptions() {
      options().forEach(function (option) {
        if (!option.id) option.id = menu.id + '-option-' + nextId++;
        option.setAttribute('role', 'option');
        option.setAttribute('tabindex', '-1');
        if (isOptionDisabled(option)) option.setAttribute('aria-disabled', 'true');
      });
    }

    function adjacentIndex(direction, from) {
      var choices = options();
      if (!choices.length) return -1;
      var cursor = typeof from === 'number' && from >= 0 ? from :
        (direction > 0 ? -1 : choices.length);
      for (var count = 0; count < choices.length; count += 1) {
        cursor = (cursor + direction + choices.length) % choices.length;
        if (!isOptionDisabled(choices[cursor])) return cursor;
      }
      return -1;
    }

    function boundaryIndex(fromEnd) {
      var choices = options();
      var direction = fromEnd ? -1 : 1;
      var cursor = fromEnd ? choices.length - 1 : 0;
      while (cursor >= 0 && cursor < choices.length) {
        if (!isOptionDisabled(choices[cursor])) return cursor;
        cursor += direction;
      }
      return -1;
    }

    function chooseActive() {
      var choices = options();
      if (activeIndex < 0 || !choices[activeIndex] || isOptionDisabled(choices[activeIndex])) return;
      controller.setValue(choices[activeIndex].getAttribute('data-choice-value'), true);
      controller.setOpen(false);
      trigger.focus();
    }

    function openWithIndex(index) {
      if (disabled || enabledOptions().length === 0) return;
      closeOthers(controller);
      controller.setOpen(true);
      setActive(index >= 0 ? index : adjacentIndex(1, selectedIndex()));
    }

    function handleNavigation(event) {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        var direction = event.key === 'ArrowDown' ? 1 : -1;
        if (!picker.classList.contains('open')) {
          openWithIndex(adjacentIndex(direction, selectedIndex()));
        } else {
          setActive(adjacentIndex(direction, activeIndex));
        }
        return true;
      }
      if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault();
        openWithIndex(boundaryIndex(event.key === 'End'));
        return true;
      }
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        if (picker.classList.contains('open')) chooseActive();
        else openWithIndex(selectedIndex() >= 0 ? selectedIndex() : boundaryIndex(false));
        return true;
      }
      if (event.key === 'Escape') {
        if (picker.classList.contains('open')) {
          event.preventDefault();
          event.stopPropagation();
          controller.setOpen(false);
          trigger.focus();
        }
        return true;
      }
      if (event.key === 'Tab') {
        controller.setOpen(false);
        return false;
      }
      if (!event.ctrlKey && !event.metaKey && !event.altKey && event.key.length === 1) {
        typeahead += event.key.toLocaleLowerCase();
        global.clearTimeout(typeaheadTimer);
        typeaheadTimer = global.setTimeout(function () { typeahead = ''; }, 600);
        var choices = options();
        var match = choices.findIndex(function (option) {
          return !isOptionDisabled(option) &&
            optionLabel(option).toLocaleLowerCase().indexOf(typeahead) === 0;
        });
        if (match >= 0) {
          event.preventDefault();
          openWithIndex(match);
        }
        return match >= 0;
      }
      return false;
    }

    var controller = {
      picker: picker,
      value: function () { return input.value; },
      setOpen: function (open) {
        var shouldOpen = !!open && !disabled && enabledOptions().length > 0;
        picker.classList.toggle('open', shouldOpen);
        trigger.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
        menu.hidden = !shouldOpen;
        if (!shouldOpen) setActive(-1);
      },
      setDisabled: function (value) {
        disabled = value === true;
        input.disabled = disabled;
        trigger.disabled = disabled;
        picker.classList.toggle('is-disabled', disabled);
        picker.setAttribute('aria-disabled', disabled ? 'true' : 'false');
        if (disabled) {
          picker.classList.remove('is-invalid');
          trigger.removeAttribute('aria-invalid');
        }
        if (disabled) controller.setOpen(false);
      },
      setValue: function (value, notify) {
        prepareOptions();
        var choices = options();
        var stringValue = value == null ? '' : String(value);
        var selected = choices.find(function (choice) {
          return choice.getAttribute('data-choice-value') === stringValue;
        }) || choices[0];
        if (!selected) {
          input.value = stringValue;
          if (label) label.textContent = '';
          return;
        }
        input.value = selected.getAttribute('data-choice-value') || '';
        if (input.value || !required) {
          picker.classList.remove('is-invalid');
          trigger.removeAttribute('aria-invalid');
        }
        if (label) label.textContent = optionLabel(selected);
        if (icon) {
          var selectedIcon = selected.getAttribute('data-choice-icon') || 'fa-circle';
          if (selectedIcon.indexOf(' ') >= 0) icon.className = selectedIcon;
          else icon.className = 'fas ' + selectedIcon;
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
      },
      refresh: function () {
        hydrateStaticOptions(input, menu);
        prepareOptions();
        controller.setValue(input.value, false);
        controller.setDisabled(input.disabled || disabled);
      }
    };

    trigger.addEventListener('click', function (event) {
      event.stopPropagation();
      if (disabled) return;
      if (picker.classList.contains('open')) controller.setOpen(false);
      else openWithIndex(selectedIndex() >= 0 ? selectedIndex() : boundaryIndex(false));
    });
    trigger.addEventListener('keydown', handleNavigation);
    input.addEventListener('focus', function () { trigger.focus(); });
    menu.addEventListener('mousemove', function (event) {
      var choice = event.target.closest('[data-choice-value]');
      if (!choice || !menu.contains(choice) || isOptionDisabled(choice)) return;
      setActive(options().indexOf(choice));
    });
    menu.addEventListener('click', function (event) {
      var choice = event.target.closest('[data-choice-value]');
      if (!choice || !menu.contains(choice) || isOptionDisabled(choice)) return;
      controller.setValue(choice.getAttribute('data-choice-value'), true);
      controller.setOpen(false);
      trigger.focus();
    });
    input.addEventListener('change', function () {
      controller.setValue(input.value, false);
      if (input.getAttribute('data-choice-submit') === 'true') {
        var submitForm = input.form || input.closest('form');
        if (submitForm) {
          if (typeof submitForm.requestSubmit === 'function') submitForm.requestSubmit();
          else submitForm.submit();
        }
      }
    });
    input.addEventListener('invalid', function (event) {
      event.preventDefault();
      picker.classList.add('is-invalid');
      trigger.setAttribute('aria-invalid', 'true');
      controller.setOpen(false);
      trigger.focus();
    });

    var form = input.form || input.closest('form');
    if (form && required) {
      form.addEventListener('submit', function (event) {
        if (input.disabled || input.value) return;
        event.preventDefault();
        picker.classList.add('is-invalid');
        trigger.setAttribute('aria-invalid', 'true');
        controller.setOpen(false);
        trigger.focus();
      });
    }
    if (form) {
      form.addEventListener('reset', function () {
        global.requestAnimationFrame(function () { controller.refresh(); });
      });
    }

    picker.__choicePickerController = controller;
    input.__choicePickerController = controller;
    controllers.push(controller);
    prepareOptions();
    controller.setDisabled(disabled);
    controller.setValue(input.value, config.notifyOnInit === true);
    controller.setOpen(false);
    return controller;
  }

  function configure(picker, entries, value, settings) {
    picker = element(picker);
    settings = settings || {};
    if (!picker) return null;
    var input = settings.input ? element(settings.input) :
      element(picker.getAttribute('data-rk-choice-input')) || picker.querySelector('input');
    var menu = settings.menu ? element(settings.menu) : picker.querySelector('.rk-choice-menu');
    if (!input || !menu) return null;
    menu.replaceChildren.apply(menu, (entries || []).map(optionElement));
    var controller = picker.__choicePickerController || create({
      picker: picker,
      input: input,
      trigger: settings.trigger || picker.querySelector('.rk-choice-trigger'),
      menu: menu,
      label: settings.label || picker.querySelector('[data-rk-choice-label]'),
      icon: settings.icon || picker.querySelector('[data-rk-choice-icon]')
    });
    if (!controller) return null;
    controller.refresh();
    controller.setValue(value == null ? '' : String(value), false);
    controller.setDisabled(settings.disabled === true);
    return controller;
  }

  function setDisabled(target, value) {
    target = element(target);
    if (!target) return;
    var controller = target.__choicePickerController ||
      target.closest('.rk-choice')?.__choicePickerController;
    if (controller) controller.setDisabled(value === true);
    else target.disabled = value === true;
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
    var inside = connectedControllers().some(function (controller) {
      return controller.picker.contains(event.target);
    });
    if (!inside) closeOthers(null);
  });
  document.addEventListener('DOMContentLoaded', function () { init(document); });

  global.ChoicePicker = Object.freeze({
    create: create,
    init: init,
    configure: configure,
    setDisabled: setDisabled,
    closeAll: closeOthers
  });
})(window);
