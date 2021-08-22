const sortBy = document.querySelector('#sortBy');
if (sortBy) {
  sortBy.addEventListener('change', (e) => {
    e.preventDefault();
    const url = `${window.location.origin}${window.location.pathname}?sort_by=${e.target.value}`;
    window.location.href = url;
  });
}
