(function (global) {
  'use strict';

  const MAX_VISIBLE_OPTIONS = 8;
  const OPTION_HEIGHT_PX = 46;
  const OPTION_GAP_PX = 3;
  const MENU_PADDING_PX = 6;
  const controllers = [];
  let optionSequence = 0;

  function resolveElement(value) {
    return typeof value === 'string' ? document.querySelector(value) : value;
  }

  function optionElements(menu) {
    return Array.from(menu.querySelectorAll('[data-class-select-option]'));
  }

  function enabledOptions(menu) {
    return optionElements(menu).filter((option) => !option.disabled);
  }

  function optionValue(option) {
    return option?.dataset.classSelectValue || '';
  }

  function closeOthers(activeController) {
    controllers.forEach((controller) => {
      if (controller !== activeController) controller.setOpen(false);
    });
  }

  function updateMenuCapacity(menu) {
    const visibleCount = Math.max(
      1,
      Math.min(optionElements(menu).length, MAX_VISIBLE_OPTIONS)
    );
    const height = (
      visibleCount * OPTION_HEIGHT_PX
      + Math.max(0, visibleCount - 1) * OPTION_GAP_PX
      + MENU_PADDING_PX * 2
    );
    menu.style.setProperty('--numoj-class-menu-capacity', `${height}px`);
  }

  function normalizeLogoCells(item) {
    const raw = item?.logo && Array.isArray(item.logo.cells)
      ? item.logo.cells
      : [];
    return raw.filter((cell) => (
      Array.isArray(cell)
      && cell.length >= 2
      && Number.isInteger(cell[0])
      && Number.isInteger(cell[1])
      && cell[0] >= 0
      && cell[0] < 5
      && cell[1] >= 0
      && cell[1] < 5
    ));
  }

  function createLogo(item, className = 'numoj-class-select-logo') {
    const mark = document.createElement('span');
    mark.className = className;
    mark.setAttribute('aria-hidden', 'true');

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 7 7');
    svg.setAttribute('focusable', 'false');
    svg.setAttribute('shape-rendering', 'crispEdges');
    normalizeLogoCells(item).forEach(([column, row]) => {
      const cell = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      cell.setAttribute('x', String(column + 1));
      cell.setAttribute('y', String(row + 1));
      cell.setAttribute('width', '1');
      cell.setAttribute('height', '1');
      svg.appendChild(cell);
    });
    mark.appendChild(svg);
    return mark;
  }

  function createOption(item) {
    const value = String(item?.class_en || '');
    const label = String(item?.class_cn || value);
    const option = document.createElement('button');
    option.type = 'button';
    option.className = 'numoj-class-select-option';
    option.id = `numoj-class-select-option-${optionSequence += 1}`;
    option.setAttribute('role', 'option');
    option.setAttribute('aria-selected', 'false');
    option.setAttribute('data-class-select-option', '');
    option.dataset.classSelectValue = value;
    option.dataset.classSelectLabel = label;
    option.dataset.classSelectCode = value;
    option.disabled = Boolean(item?.disabled);
    option.classList.toggle('is-disabled', option.disabled);
    if (option.disabled) option.setAttribute('aria-disabled', 'true');

    option.appendChild(createLogo(item));

    const copy = document.createElement('span');
    copy.className = 'numoj-class-select-option-copy';
    const name = document.createElement('strong');
    name.textContent = label;
    const code = document.createElement('small');
    code.textContent = value;
    copy.append(name, code);
    option.appendChild(copy);

    const state = document.createElement('span');
    state.className = 'numoj-class-select-option-state';
    state.setAttribute('aria-hidden', 'true');
    state.textContent = option.disabled
      ? String(item?.disabled_label || '已加入')
      : '✓';
    option.appendChild(state);
    return option;
  }

  function create(pickerValue, config = {}) {
    const picker = resolveElement(pickerValue);
    if (!picker) return null;
    if (picker.__numojClassSelectController) {
      picker.__numojClassSelectController.configure(config);
      return picker.__numojClassSelectController;
    }

    const input = picker.querySelector('[data-class-select-input]');
    const trigger = picker.querySelector('[data-class-select-trigger]');
    const menu = picker.querySelector('[data-class-select-menu]');
    const currentLogo = picker.querySelector('[data-class-select-current-logo]');
    const currentLabel = picker.querySelector('[data-class-select-current-label]');
    const currentCode = picker.querySelector('[data-class-select-current-code]');
    const error = picker.querySelector('[data-class-select-error]');
    if (!input || !trigger || !menu || !currentLabel) return null;

    const settings = {
      onChange: null,
      dispatchChange: true,
      ...config,
    };
    const placeholder = picker.dataset.classSelectPlaceholder || '请选择班级';
    const placeholderCode = picker.dataset.classSelectPlaceholderCode || 'SELECT';
    optionElements(menu).forEach((option) => {
      if (!option.id) {
        option.id = `numoj-class-select-option-${optionSequence += 1}`;
      }
    });
    updateMenuCapacity(menu);

    function selectedOption(value = input.value) {
      return optionElements(menu).find(
        (option) => optionValue(option) === String(value || '') && !option.disabled
      ) || null;
    }

    function copyLogo(option) {
      if (!currentLogo) return;
      const svg = option?.querySelector('.numoj-class-select-logo svg');
      currentLogo.replaceChildren();
      currentLogo.classList.toggle('is-placeholder', !svg);
      if (svg) currentLogo.appendChild(svg.cloneNode(true));
    }

    function setInvalid(message = '') {
      const active = Boolean(message);
      picker.classList.toggle('is-invalid', active);
      trigger.setAttribute('aria-invalid', active ? 'true' : 'false');
      if (error) {
        error.textContent = message;
        error.hidden = !active;
      }
    }

    const controller = {
      picker,
      input,
      trigger,
      menu,
      configure(nextConfig = {}) {
        Object.assign(settings, nextConfig);
      },
      value() {
        return input.value;
      },
      setOpen(open, { focusOption = false, direction = 1 } = {}) {
        const willOpen = Boolean(open) && enabledOptions(menu).length > 0;
        if (willOpen) closeOthers(controller);
        picker.classList.toggle('open', willOpen);
        trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
        menu.hidden = !willOpen;
        if (!willOpen) {
          trigger.removeAttribute('aria-activedescendant');
          return;
        }
        if (focusOption) {
          const choices = enabledOptions(menu);
          const selected = selectedOption();
          const target = selected || (
            direction < 0 ? choices[choices.length - 1] : choices[0]
          );
          target?.focus();
          if (target?.id) trigger.setAttribute('aria-activedescendant', target.id);
        }
      },
      setValue(value, { notify = false } = {}) {
        const previousValue = input.value;
        const option = selectedOption(value);
        input.value = option ? optionValue(option) : '';
        currentLabel.textContent = option?.dataset.classSelectLabel || placeholder;
        if (currentCode) {
          currentCode.textContent = option?.dataset.classSelectCode || placeholderCode;
        }
        copyLogo(option);
        trigger.title = option?.dataset.classSelectLabel || placeholder;

        optionElements(menu).forEach((candidate) => {
          const active = candidate === option;
          candidate.classList.toggle('is-selected', active);
          candidate.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        if (input.value) setInvalid('');

        if (notify && previousValue !== input.value) {
          if (typeof settings.onChange === 'function') {
            settings.onChange(input.value, option);
          }
          if (settings.dispatchChange !== false) {
            input.dispatchEvent(new Event('change', { bubbles: true }));
          }
        }
      },
      setItems(items) {
        const previousValue = input.value;
        const fragment = document.createDocumentFragment();
        (items || []).forEach((item) => fragment.appendChild(createOption(item)));
        menu.replaceChildren(fragment);
        updateMenuCapacity(menu);
        controller.setValue(previousValue);
        if (!optionElements(menu).length) {
          const empty = document.createElement('div');
          empty.className = 'numoj-class-select-empty';
          empty.textContent = '暂无可选班级';
          menu.replaceChildren(empty);
          updateMenuCapacity(menu);
        }
      },
      setLoading(message = '正在加载班级…') {
        controller.setValue('');
        const loading = document.createElement('div');
        loading.className = 'numoj-class-select-empty';
        loading.textContent = message;
        menu.replaceChildren(loading);
        updateMenuCapacity(menu);
        trigger.disabled = true;
      },
      setReady() {
        trigger.disabled = false;
      },
      setInvalid,
    };

    trigger.addEventListener('click', (event) => {
      event.stopPropagation();
      controller.setOpen(!picker.classList.contains('open'));
    });

    trigger.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        controller.setOpen(true, {
          focusOption: true,
          direction: event.key === 'ArrowUp' ? -1 : 1,
        });
      } else if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        controller.setOpen(!picker.classList.contains('open'), {
          focusOption: true,
        });
      } else if (event.key === 'Escape') {
        controller.setOpen(false);
      }
    });

    menu.addEventListener('click', (event) => {
      const option = event.target.closest('[data-class-select-option]');
      if (!option || option.disabled || !menu.contains(option)) return;
      controller.setValue(optionValue(option), { notify: true });
      controller.setOpen(false);
      trigger.focus();
    });

    menu.addEventListener('keydown', (event) => {
      const choices = enabledOptions(menu);
      const currentIndex = choices.indexOf(document.activeElement);
      let nextIndex = null;
      if (event.key === 'ArrowDown') {
        nextIndex = currentIndex < choices.length - 1 ? currentIndex + 1 : 0;
      } else if (event.key === 'ArrowUp') {
        nextIndex = currentIndex > 0 ? currentIndex - 1 : choices.length - 1;
      } else if (event.key === 'Home') {
        nextIndex = 0;
      } else if (event.key === 'End') {
        nextIndex = choices.length - 1;
      } else if (event.key === 'Escape') {
        event.preventDefault();
        controller.setOpen(false);
        trigger.focus();
      } else if (event.key === 'Tab') {
        controller.setOpen(false);
      }
      if (nextIndex != null && choices[nextIndex]) {
        event.preventDefault();
        choices[nextIndex].focus();
        trigger.setAttribute('aria-activedescendant', choices[nextIndex].id);
      }
    });

    const form = picker.closest('form');
    if (form && picker.hasAttribute('data-class-select-required')) {
      form.addEventListener('submit', (event) => {
        if (input.value) return;
        event.preventDefault();
        controller.setInvalid('请选择班级');
        controller.setOpen(true);
        trigger.focus();
      });
    }

    picker.__numojClassSelectController = controller;
    controllers.push(controller);
    controller.setValue(input.value);
    return controller;
  }

  function init(root = document) {
    return Array.from(
      root.querySelectorAll(
        '[data-numoj-class-select][data-class-select-auto]'
      )
    ).map((picker) => create(picker)).filter(Boolean);
  }

  document.addEventListener('click', (event) => {
    controllers.forEach((controller) => {
      if (!controller.picker.contains(event.target)) controller.setOpen(false);
    });
  });

  init(document);

  global.NumojClassSelect = Object.freeze({
    create,
    createLogo,
    init,
  });
}(window));
