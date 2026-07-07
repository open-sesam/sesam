// Colour the ✓/✗ glyphs in content tables (e.g. the comparison matrices in
// alternatives.md). They are bare text, so CSS can't reach them — wrap each in
// a span here and let the stylesheet colour it (theme-aware via CSS tokens).
// Only the glyph is wrapped, so cells like "✓ (automatic)" or "✗³" keep their
// trailing text and footnote markers intact.
(function () {
    const MARK_RE = /[✓✗]/;

    const wrap = (textNode) => {
        const text = textNode.nodeValue;
        if (!MARK_RE.test(text)) return;
        const frag = document.createDocumentFragment();
        for (const part of text.split(/([✓✗])/)) {
            if (part === "") continue;
            if (part === "✓" || part === "✗") {
                const s = document.createElement("span");
                s.className = part === "✓" ? "mark-yes" : "mark-no";
                s.textContent = part;
                frag.appendChild(s);
            } else {
                frag.appendChild(document.createTextNode(part));
            }
        }
        textNode.parentNode.replaceChild(frag, textNode);
    };

    const enhance = () => {
        document.querySelectorAll(".content main table td, .content main table th").forEach((cell) => {
            const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
            const nodes = [];
            for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push(n);
            nodes.forEach(wrap);
        });
    };

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", enhance);
    else enhance();
})();
