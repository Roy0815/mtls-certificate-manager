document.addEventListener('click', function (e) {
  var btn = e.target.closest('[data-copy-target]');
  if (!btn) return;
  var input = document.querySelector(btn.getAttribute('data-copy-target'));
  if (!input) return;
  navigator.clipboard.writeText(input.value).then(function () {
    var original = btn.textContent;
    btn.textContent = 'Kopiert!';
    setTimeout(function () {
      btn.textContent = original;
    }, 1500);
  });
});

// CSP (script-src 'self') blocks inline onsubmit="..." handlers, so
// confirmation prompts on forms go through this instead of an inline attribute.
document.addEventListener('submit', function (e) {
  var form = e.target;
  if (form.matches('[data-confirm]') && !window.confirm(form.getAttribute('data-confirm'))) {
    e.preventDefault();
  }
});
