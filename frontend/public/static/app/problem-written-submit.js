(function () {
  'use strict';

  function assignDroppedFile(input, files) {
    if (!files || !files.length) return false;
    try {
      if (typeof DataTransfer === 'function') {
        const transfer = new DataTransfer();
        transfer.items.add(files[0]);
        input.files = transfer.files;
        return true;
      }
    } catch (_error) {
      // 部分浏览器暴露 DataTransfer，但不允许直接构造。
    }
    try {
      input.files = files;
      return true;
    } catch (_error) {
      return false;
    }
  }

  document.querySelectorAll('[data-written-file-picker]').forEach((picker) => {
    const input = picker.querySelector('[data-written-file-input]');
    const dropzone = picker.querySelector('[data-written-dropzone]');
    const fileName = picker.querySelector('[data-written-file-name]');
    if (!input || !dropzone || !fileName) return;

    const emptyLabel = picker.dataset.fileKind || '';
    let dragDepth = 0;

    function update() {
      const file = input.files && input.files[0];
      dropzone.classList.toggle('has-file', Boolean(file));
      fileName.textContent = file ? file.name : emptyLabel;
      dropzone.title = file ? file.name : '';
    }

    input.addEventListener('change', update);

    dropzone.addEventListener('dragenter', (event) => {
      event.preventDefault();
      dragDepth += 1;
      dropzone.classList.add('is-dragover');
    });

    dropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
    });

    dropzone.addEventListener('dragleave', (event) => {
      event.preventDefault();
      dragDepth = Math.max(0, dragDepth - 1);
      if (!dragDepth) dropzone.classList.remove('is-dragover');
    });

    dropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      dragDepth = 0;
      dropzone.classList.remove('is-dragover');
      if (!event.dataTransfer || !assignDroppedFile(input, event.dataTransfer.files)) return;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });

    picker.closest('form')?.addEventListener('reset', () => {
      requestAnimationFrame(update);
    });
    update();
  });
}());
