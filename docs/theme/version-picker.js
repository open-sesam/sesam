// Version dropdown in the menu bar. Not part of book.toml: CI injects it into
// every built version (scripts/build-docs-versions.sh), so it is absent locally.
(async () => {
    const bar = document.querySelector('#menu-bar .right-buttons');
    if (!bar) return;

    let versions;
    try {
        versions = await (await fetch('/docs/versions.json')).json();
    } catch {
        return;
    }

    // /docs/<version>/<page> or /docs/<page> for main.
    const m = location.pathname.match(/^\/docs\/(v\d+\.\d+\.\d+)\/(.*)$/);
    const current = m ? m[1] : 'main';
    const page = m ? m[2] : location.pathname.replace(/^\/docs\//, '');

    const select = document.createElement('select');
    select.className = 'version-picker';
    select.setAttribute('aria-label', 'Documentation version');
    // Inline, since old tags ship a sesam.css that predates the picker.
    select.style.cssText =
        'height: 2.4rem; margin: auto 8px; padding: 0 4px; cursor: pointer;' +
        'font: inherit; font-size: 1.6rem; font-weight: 700;' +
        // The box is as wide as "VERSIONS"; keep shorter names next to the arrow.
        'text-align: right; text-align-last: right;' +
        'color: var(--links); background: transparent; border: none;';

    const header = new Option('VERSIONS', '');
    header.disabled = true;
    select.add(header);
    for (const v of versions) {
        var name = v;
        if(name == "main") {
          name = "MAIN";
        }
        select.add(new Option(name, v, false, v === current));
    }
    for (const o of select.options) o.style.textAlign = 'left';
    select.addEventListener('change', () => {
        const prefix = select.value === 'main' ? '/docs/' : `/docs/${select.value}/`;
        location.href = prefix + page + location.hash;
    });
    bar.prepend(select);
})();
