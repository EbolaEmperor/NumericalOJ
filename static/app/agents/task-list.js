(function () {
  'use strict';

  var identicon = window.NumojIdenticon;
  if (!identicon) return;

  document.querySelectorAll('[data-agent-task-list] [data-avatar-seed]').forEach(function (avatar) {
    var seed = avatar.getAttribute('data-avatar-seed') || 'numericaloj';
    identicon.paint(
      avatar,
      identicon.cellsForSeed(seed),
      avatar.getAttribute('data-avatar-label') || seed
    );
  });
}());
