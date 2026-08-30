(function () {
  'use strict';

  const root = document.documentElement;
  try {
    root.classList.toggle(
      'numoj-sidebar-prefers-collapsed',
      window.localStorage.getItem('numoj.desktopSidebarCollapsed') === '1'
    );
  } catch (_error) {
    root.classList.remove('numoj-sidebar-prefers-collapsed');
  }
})();
