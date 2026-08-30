(() => {
  const pickers = [...document.querySelectorAll('[data-numoj-class-picker]')];
  if (!pickers.length) return;

  const optionsFor = picker => [
    ...picker.querySelectorAll('.numoj-class-picker-option')
  ];

  const closePicker = (picker, { restoreFocus = false } = {}) => {
    const trigger = picker.querySelector('[data-numoj-class-picker-trigger]');
    const menu = picker.querySelector('[data-numoj-class-picker-menu]');
    if (!trigger || !menu) return;
    picker.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    menu.hidden = true;
    if (restoreFocus) trigger.focus();
  };

  const closeOtherPickers = activePicker => {
    pickers.forEach(picker => {
      if (picker !== activePicker) closePicker(picker);
    });
  };

  const openPicker = (picker, { focusOption = false } = {}) => {
    const trigger = picker.querySelector('[data-numoj-class-picker-trigger]');
    const menu = picker.querySelector('[data-numoj-class-picker-menu]');
    if (!trigger || !menu) return;
    closeOtherPickers(picker);
    picker.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    menu.hidden = false;
    if (focusOption) {
      const options = optionsFor(picker);
      const selected = options.find(
        option => option.getAttribute('aria-selected') === 'true'
      );
      (selected || options[0])?.focus();
    }
  };

  pickers.forEach(picker => {
    const trigger = picker.querySelector('[data-numoj-class-picker-trigger]');
    const menu = picker.querySelector('[data-numoj-class-picker-menu]');
    if (!trigger || !menu) return;

    trigger.addEventListener('click', () => {
      if (picker.classList.contains('open')) {
        closePicker(picker);
      } else {
        openPicker(picker);
      }
    });

    trigger.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        openPicker(picker, { focusOption: true });
      } else if (event.key === 'Escape') {
        closePicker(picker);
      }
    });

    menu.addEventListener('keydown', event => {
      const options = optionsFor(picker);
      const currentIndex = options.indexOf(document.activeElement);
      let nextIndex = null;

      if (event.key === 'ArrowDown') {
        nextIndex = currentIndex < options.length - 1 ? currentIndex + 1 : 0;
      } else if (event.key === 'ArrowUp') {
        nextIndex = currentIndex > 0 ? currentIndex - 1 : options.length - 1;
      } else if (event.key === 'Home') {
        nextIndex = 0;
      } else if (event.key === 'End') {
        nextIndex = options.length - 1;
      } else if (event.key === 'Escape') {
        event.preventDefault();
        closePicker(picker, { restoreFocus: true });
      } else if (event.key === 'Tab') {
        closePicker(picker);
      }

      if (nextIndex !== null && options[nextIndex]) {
        event.preventDefault();
        options[nextIndex].focus();
      }
    });
  });

  document.addEventListener('click', event => {
    pickers.forEach(picker => {
      if (!picker.contains(event.target)) closePicker(picker);
    });
  });
})();
