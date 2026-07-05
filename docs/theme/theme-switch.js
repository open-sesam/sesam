(function () {
    const STORAGE_KEY = 'sesam-theme';
    const html = document.documentElement;
    const mql = window.matchMedia('(prefers-color-scheme: dark)');

    const getPref = () => localStorage.getItem(STORAGE_KEY) || 'auto';
    const setPref = (p) => {
        if (p === 'auto') localStorage.removeItem(STORAGE_KEY);
        else localStorage.setItem(STORAGE_KEY, p);
    };

    // Resolve the theme that is actually showing: an explicit choice, or the OS
    // preference when on 'auto'.
    const effective = () => {
        const p = getPref();
        if (p === 'dark' || p === 'light') return p;
        return mql.matches ? 'dark' : 'light';
    };

    // Apply an *explicit* choice via data-theme; on 'auto' we clear it so the
    // prefers-color-scheme media query (in sesam.css) drives the theme — that
    // keeps it working without JS and updating live with the OS.
    const applyTheme = () => {
        const pref = getPref();
        if (pref === 'dark' || pref === 'light') {
            html.setAttribute('data-theme', pref);
        } else {
            html.removeAttribute('data-theme');
        }
    };

    // The menu-bar button shows the *current* celestial body — a sun by day, a
    // moon by night — and clicking it flips to the other (like the landing page).
    const refreshIcon = (btn) => {
        if (!btn) return;
        const eff = effective();
        const icon = btn.querySelector('i');
        if (icon) icon.className = 'fa ' + (eff === 'dark' ? 'fa-moon-o' : 'fa-sun-o');
        const label = eff === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
        btn.setAttribute('aria-label', label);
        btn.setAttribute('title', label);
        btn.setAttribute('aria-haspopup', 'false');
        btn.setAttribute('aria-expanded', 'false');
        btn.removeAttribute('aria-controls');
    };

    const setup = () => {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;

        // Intercept on the capture phase and stop immediately, so mdBook's own
        // bubble-phase click handler (which opens the theme popup) never runs.
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            setPref(effective() === 'dark' ? 'light' : 'dark');
            applyTheme();
            refreshIcon(btn);
        }, true);

        refreshIcon(btn);

        // When following the OS ('auto'), track live changes.
        mql.addEventListener('change', () => {
            if (getPref() === 'auto') {
                applyTheme();
                refreshIcon(btn);
            }
        });
    };

    // Apply as early as possible to minimize a flash of the wrong theme.
    applyTheme();

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setup);
    } else {
        setup();
    }
})();
