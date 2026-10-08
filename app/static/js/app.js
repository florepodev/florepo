// Copy-to-clipboard buttons: <button data-copy="element-id">
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  const el = document.getElementById(btn.dataset.copy);
  navigator.clipboard.writeText(el.innerText.trim()).then(() => {
    const t = btn.innerText; btn.innerText = 'Copied'; setTimeout(() => btn.innerText = t, 1200);
  });
});

// Client-side sorting for <table class="sortable">. A cell may provide data-sort with a
// machine-sortable value (bytes, ISO timestamps, severity scores); otherwise its text is used.
// Header cells with data-nosort are skipped. Paginated tables sort server-side instead.
(() => {
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const NUMERIC = /^-?\d+(\.\d+)?$/;

  function value(row, idx) {
    const cell = row.cells[idx];
    if (!cell) return '';
    return (cell.dataset.sort ?? cell.textContent).trim();
  }

  function compare(a, b) {
    if (NUMERIC.test(a) && NUMERIC.test(b)) return parseFloat(a) - parseFloat(b);
    if (a === '' || a === '–') return 1;
    if (b === '' || b === '–') return -1;
    return collator.compare(a, b);
  }

  function sortTable(table, idx, th) {
    const tbody = table.tBodies[0];
    const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
    table.querySelectorAll('th[data-dir]').forEach(h => {
      delete h.dataset.dir;
      h.querySelector('.sort-ind').textContent = '↕';
    });
    th.dataset.dir = dir;
    th.querySelector('.sort-ind').textContent = dir === 'asc' ? '▲' : '▼';
    // rows spanning the whole table (e.g. "no data") are not sortable
    const rows = [...tbody.rows].filter(r => r.cells.length > 1);
    rows.sort((r1, r2) => {
      const res = compare(value(r1, idx), value(r2, idx));
      return dir === 'asc' ? res : -res;
    });
    rows.forEach(r => tbody.appendChild(r));
  }

  document.querySelectorAll('table.sortable').forEach(table => {
    if (!table.tHead) return;
    [...table.tHead.rows[0].cells].forEach((th, idx) => {
      if ('nosort' in th.dataset || !th.textContent.trim()) return;
      th.classList.add('cursor-pointer', 'select-none', 'hover:text-slate-900');
      th.title = 'Sort';
      th.insertAdjacentHTML('beforeend', '<span class="sort-ind ml-1 text-slate-300">↕</span>');
      th.addEventListener('click', () => sortTable(table, idx, th));
    });
  });
})();
