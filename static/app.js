'use strict';
document.querySelectorAll('[data-target]').forEach(button => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.target);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.textContent = show ? 'Hide' : 'Show';
    button.setAttribute('aria-pressed', String(show));
    button.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${input.labels[0].textContent}`);
  });
  const input = document.getElementById(button.dataset.target);
  button.setAttribute('aria-label', `Show ${input.labels[0].textContent}`);
});
