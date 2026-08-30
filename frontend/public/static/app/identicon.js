(function () {
  'use strict';

  const GRID_SIZE = 8;
  const CELL_COUNT = GRID_SIZE * GRID_SIZE;

  function normalizeCells(avatar) {
    const raw = Array.isArray(avatar)
      ? avatar
      : (avatar && Array.isArray(avatar.cells) ? avatar.cells : []);
    const cells = new Set();

    raw.forEach((item) => {
      let index = null;
      if (Number.isInteger(item)) {
        index = item;
      } else if (
        Array.isArray(item)
        && item.length >= 2
        && Number.isInteger(item[0])
        && Number.isInteger(item[1])
      ) {
        index = item[1] * GRID_SIZE + item[0];
      }
      if (index != null && index >= 0 && index < CELL_COUNT) {
        cells.add(index);
      }
    });

    return cells;
  }

  function cellsForSeed(seed) {
    const bytes = new TextEncoder().encode(String(seed || 'numericaloj'));
    let hash = 0x811c9dc5;
    bytes.forEach((byte) => {
      hash ^= byte;
      hash = Math.imul(hash, 0x01000193) >>> 0;
    });

    let randomState = hash || 0x9e3779b9;
    const cells = [];
    for (let row = 0; row < GRID_SIZE; row += 1) {
      for (let column = 0; column < GRID_SIZE / 2; column += 1) {
        randomState ^= randomState << 13;
        randomState ^= randomState >>> 17;
        randomState ^= randomState << 5;
        randomState >>>= 0;
        if ((randomState & 1) === 1) {
          cells.push(
            row * GRID_SIZE + column,
            row * GRID_SIZE + (GRID_SIZE - 1 - column)
          );
        }
      }
    }

    return {
      cells: cells.length
        ? cells.sort((left, right) => left - right)
        : [27, 28, 35, 36],
    };
  }

  function paint(element, avatar, label) {
    if (!element) return;

    const cells = normalizeCells(avatar);
    const fragment = document.createDocumentFragment();
    for (let index = 0; index < CELL_COUNT; index += 1) {
      const cell = document.createElement('span');
      if (cells.has(index)) cell.className = 'is-filled';
      fragment.appendChild(cell);
    }
    element.replaceChildren(fragment);

    if (label) {
      element.setAttribute('title', label);
      element.setAttribute('aria-label', `${label} 的头像`);
    }
  }

  window.NumojIdenticon = Object.freeze({
    cellsForSeed,
    normalizeCells,
    paint,
  });
}());
