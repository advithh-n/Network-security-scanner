(() => {
  const filterInputs = document.querySelectorAll("[data-filter-target]");
  filterInputs.forEach((input) => {
    input.addEventListener("input", (event) => {
      const targetId = event.target.dataset.filterTarget;
      const table = document.getElementById(targetId);
      if (!table) return;
      const value = event.target.value.toLowerCase();
      const rows = table.querySelectorAll(".table-row");
      rows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(value) ? "grid" : "none";
      });
    });
  });

  if (window.__SCAN_ID__) {
    const scanId = window.__SCAN_ID__;
    const poll = async () => {
      try {
        const res = await fetch(`/api/scan/${scanId}`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.status === "finished" || data.status === "failed") {
          window.location.reload();
        }
      } catch (err) {
        // ignore
      }
    };
    setInterval(poll, 2500);
  }
})();
