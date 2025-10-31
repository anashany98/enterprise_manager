/* global bootstrap, Chart */

function showToasts() {
  document.querySelectorAll('.toast').forEach((toastEl) => {
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
  });
}

function initDataTable(selector) {
  if (!window.jQuery) {
    return;
  }
  const $table = window.jQuery(selector);
  if (!$table.length) {
    return;
  }
  if ($table.hasClass('dataTable')) {
    $table.DataTable().destroy();
  }
  $table.DataTable({
    responsive: true,
    pageLength: 10,
    order: [],
    language: {
      url: 'https://cdn.datatables.net/plug-ins/1.13.8/i18n/es-ES.json',
    },
  });
}

function randomColor(index) {
  const palette = [
    '#2563eb', '#1d4ed8', '#16a34a', '#15803d', '#e11d48', '#f97316', '#facc15', '#14b8a6',
    '#8b5cf6', '#0ea5e9', '#ea580c', '#f59e0b', '#9333ea', '#22c55e',
  ];
  return palette[index % palette.length];
}

function renderPieChart(canvasId, labels, data, label) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: 'pie',
    data: {
      labels,
      datasets: [
        {
          label,
          data,
          backgroundColor: labels.map((_, idx) => randomColor(idx)),
        },
      ],
    },
    options: { plugins: { legend: { position: 'bottom' } } },
  });
}

function renderDoughnutChart(canvasId, labels, data, label) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [
        {
          label,
          data,
          backgroundColor: labels.map((_, idx) => randomColor(idx + 4)),
        },
      ],
    },
    options: { plugins: { legend: { position: 'bottom' } } },
  });
}

function renderBarChart(canvasId, labels, data, label) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label,
          data,
          backgroundColor: labels.map((_, idx) => randomColor(idx + 8)),
          borderRadius: 6,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, precision: 0 } },
    },
  });
}

function bindRevealPassword() {
  document.querySelectorAll('.reveal-password').forEach((button) => {
    button.addEventListener('click', async () => {
      const accountId = button.dataset.account;
      try {
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
        const response = await fetch(`/accounts/${accountId}/reveal`, {
          method: 'POST',
          headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': csrf,
          },
        });
        if (!response.ok) {
          throw new Error('No autorizado');
        }
        const data = await response.json();
        navigator.clipboard.writeText(data.password).catch(() => {});
        showInlineToast(`Contrasena copiada: ${data.password}`);
      } catch (error) {
        showInlineToast('No fue posible obtener la contrasena', 'danger');
      }
    });
  });
}

function showInlineToast(message, variant = 'success') {
  const container = document.querySelector('.toast-container') || document.body;
  const wrapper = document.createElement('div');
  wrapper.className = `toast align-items-center text-bg-${variant === 'success' ? 'success' : 'danger'} border-0 shadow`;
  wrapper.setAttribute('role', 'alert');
  wrapper.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${message}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>`;
  container.appendChild(wrapper);
  const toast = new bootstrap.Toast(wrapper, { delay: 4000 });
  toast.show();
  toast._element.addEventListener('hidden.bs.toast', () => wrapper.remove());
}

function initPasswordStrength(selector) {
  document.querySelectorAll(selector).forEach((input) => {
    const meter = input.closest('.password-meter')?.querySelector('.password-strength');
    if (!meter) return;
    const updateMeter = () => {
      const value = input.value || '';
      const lengthScore = Math.min(value.length, 12) * 5;
      const varietyScore = ['[A-Z]', '[a-z]', '\\d', '[^\\w]']
        .reduce((score, pattern) => (new RegExp(pattern).test(value) ? score + 15 : score), 0);
      const total = Math.min(lengthScore + varietyScore, 100);
      meter.textContent = `${total}%`;
      meter.classList.toggle('text-bg-danger', total < 40);
      meter.classList.toggle('text-bg-warning', total >= 40 && total < 70);
      meter.classList.toggle('text-bg-success', total >= 70);
    };
    input.addEventListener('input', updateMeter);
    updateMeter();
  });
}

function initThemeToggle() {
  const html = document.documentElement;
  const toggle = document.getElementById('themeToggle');
  const stored = localStorage.getItem('theme');
  if (stored) {
    html.setAttribute('data-bs-theme', stored);
  }
  if (toggle) {
    toggle.addEventListener('click', () => {
      const current = html.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-bs-theme', current);
      localStorage.setItem('theme', current);
    });
  }
}

function bindPasswordToggles() {
  document.querySelectorAll('.toggle-password').forEach((button) => {
    const input = button.closest('.input-group')?.querySelector('input');
    if (!input) return;
    button.addEventListener('click', () => {
      const isPassword = input.getAttribute('type') === 'password';
      input.setAttribute('type', isPassword ? 'text' : 'password');
      button.innerHTML = `<i class="fa-solid fa-${isPassword ? 'eye-slash' : 'eye'}"></i>`;
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  showToasts();
  initThemeToggle();
  bindRevealPassword();
  bindPasswordToggles();
});
