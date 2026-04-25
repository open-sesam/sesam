(function () {
    const STORAGE_KEY = 'sesam-theme';
    const html = document.documentElement;

    const getPref = () => localStorage.getItem(STORAGE_KEY) || 'auto';
    const setPref = (p) => {
        if (p === 'auto') localStorage.removeItem(STORAGE_KEY);
        else localStorage.setItem(STORAGE_KEY, p);
    };

    const applyTheme = () => {
        const pref = getPref();
        if (pref === 'dark' || pref === 'light') {
            html.setAttribute('data-theme', pref);
        } else {
            html.removeAttribute('data-theme');
        }
    };

    const updateButtons = () => {
        const pref = getPref();
        document.querySelectorAll('#theme-list [data-sesam-theme]').forEach((btn) => {
            const on = btn.dataset.sesamTheme === pref;
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            btn.classList.toggle('theme-active', on);
        });
    };

    const setupList = () => {
        const list = document.getElementById('theme-list');
        if (!list) return;

        list.innerHTML = '';
        list.setAttribute('role', 'menu');

        const options = [
            ['auto', 'Auto'],
            ['light', 'Light'],
            ['dark', 'Dark'],
        ];

        options.forEach(([value, label]) => {
            const li = document.createElement('li');
            li.setAttribute('role', 'none');
            const btn = document.createElement('button');
            btn.className = 'theme';
            btn.setAttribute('role', 'menuitem');
            btn.dataset.sesamTheme = value;
            btn.textContent = label;
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                setPref(value);
                applyTheme();
                updateButtons();
                list.style.display = 'none';
            });
            li.appendChild(btn);
            list.appendChild(li);
        });

        updateButtons();
    };

    // Apply as early as possible to minimize flash of wrong theme.
    applyTheme();

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupList);
    } else {
        setupList();
    }
})();
