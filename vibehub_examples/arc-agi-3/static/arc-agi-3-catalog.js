(function () {
  'use strict';

  const helpModal = document.getElementById('arcHelpModal');
  if (helpModal) {
    helpModal.addEventListener('show.bs.modal', function () {
      document.body.classList.add('arc-help-liquid-open');
    });
    helpModal.addEventListener('hidden.bs.modal', function () {
      document.body.classList.remove('arc-help-liquid-open');
    });
  }

  const catalog = document.querySelector('[data-arc-catalog]');
  if (!catalog) {
    return;
  }

  const pages = Array.from(catalog.querySelectorAll('[data-arc-page-index]'));
  const previousButton = catalog.querySelector('[data-arc-page-direction="-1"]');
  const nextButton = catalog.querySelector('[data-arc-page-direction="1"]');
  const announcer = document.getElementById('arcPageAnnouncer');
  const totalGames = Number(catalog.dataset.totalGames) || 0;
  const pageSize = 15;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let activePageIndex = 0;
  let isAnimating = false;

  if (pages.length === 0) {
    previousButton.disabled = true;
    nextButton.disabled = true;
    if (announcer) {
      announcer.textContent = 'ARC-AGI-3 公开集尚未安装';
    }
    return;
  }

  function setPageAccessibility(page, isActive) {
    page.setAttribute('aria-hidden', isActive ? 'false' : 'true');
    if (isActive) {
      page.removeAttribute('inert');
    } else {
      page.setAttribute('inert', '');
    }
  }

  function updateButtons() {
    previousButton.disabled = isAnimating || activePageIndex === 0;
    nextButton.disabled = isAnimating || activePageIndex === pages.length - 1;
  }

  function announcePage() {
    if (!announcer) {
      return;
    }
    const firstGame = activePageIndex * pageSize + 1;
    const lastGame = Math.min((activePageIndex + 1) * pageSize, totalGames);
    announcer.textContent = '正在显示第 ' + firstGame + ' 至 ' + lastGame + ' 个游戏';
  }

  function showPageImmediately(targetPageIndex) {
    pages.forEach(function (page, index) {
      const isActive = index === targetPageIndex;
      page.classList.toggle('is-active', isActive);
      page.classList.remove(
        'is-transitioning',
        'is-leaving-next',
        'is-entering-next',
        'is-leaving-previous',
        'is-entering-previous'
      );
      setPageAccessibility(page, isActive);
    });
    activePageIndex = targetPageIndex;
    isAnimating = false;
    catalog.classList.remove('is-flipping-next', 'is-flipping-previous');
    updateButtons();
    announcePage();
  }

  function turnPage(direction) {
    if (isAnimating) {
      return;
    }
    const targetPageIndex = activePageIndex + direction;
    if (targetPageIndex < 0 || targetPageIndex >= pages.length) {
      return;
    }

    if (reducedMotion.matches) {
      showPageImmediately(targetPageIndex);
      return;
    }

    const outgoingPage = pages[activePageIndex];
    const incomingPage = pages[targetPageIndex];
    const directionName = direction > 0 ? 'next' : 'previous';
    let finished = false;

    isAnimating = true;
    updateButtons();
    catalog.classList.add('is-flipping-' + directionName);
    outgoingPage.classList.add('is-transitioning', 'is-leaving-' + directionName);
    incomingPage.classList.add('is-transitioning', 'is-entering-' + directionName);

    function finishTurn() {
      if (finished) {
        return;
      }
      finished = true;
      showPageImmediately(targetPageIndex);
    }

    incomingPage.addEventListener('animationend', function handleAnimationEnd(event) {
      if (event.target === incomingPage) {
        finishTurn();
      }
    }, { once: true });
    window.setTimeout(finishTurn, 900);
  }

  previousButton.addEventListener('click', function () {
    turnPage(-1);
  });

  nextButton.addEventListener('click', function () {
    turnPage(1);
  });

  updateButtons();
  announcePage();
})();
