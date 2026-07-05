// Brand-aware accents for sesam CLI examples in bash code blocks: the `sesam`
// command, its subcommand(s) and any --flags. Runs after mdBook's highlight.js
// pass (book.js highlights synchronously in its own IIFE, well before window
// 'load') and augments that output rather than replacing it, so ordinary bash
// tokens keep their colours. Colours are driven by CSS tokens, so light/dark is
// handled entirely in the stylesheet.
(function () {
    // Subcommands that open a further sub-subcommand; for these we colour two
    // words (e.g. `hook pre-commit`, `user tell`), otherwise just one.
    const GROUPS = new Set(["user", "hook", "group", "config", "keyring", "recipient"]);
    const FLAG_RE = /^(--?[A-Za-z][A-Za-z0-9-]*)(=.*)?$/;
    const WORD_RE = /^[a-z][a-z0-9-]*$/;

    const span = (cls, text) => {
        const s = document.createElement("span");
        s.className = cls;
        s.textContent = text;
        return s;
    };

    // Tiny state machine, shared across a block's nodes so a `sesam` in one node
    // can colour the subcommand that follows in the next.
    const makeState = () => ({ mode: "idle", subLeft: 0 });

    // Classify one word, advancing the machine. Returns a descriptor or null
    // (plain text). `mode` is "expectSub" only right after `sesam`.
    const classify = (word, st) => {
        const flag = FLAG_RE.exec(word);
        if (flag) {
            if (st.mode === "expectSub") st.mode = "args";
            return { cls: "sesam-flag", flagName: flag[1], rest: flag[2] || "" };
        }
        if (word === "sesam") {
            st.mode = "expectSub";
            st.subLeft = 1;
            return { cls: "sesam-cmd" };
        }
        if (st.mode === "expectSub" && WORD_RE.test(word)) {
            if (st.subLeft === 1 && GROUPS.has(word)) st.subLeft = 2;
            st.subLeft -= 1;
            if (st.subLeft <= 0) st.mode = "args";
            return { cls: "sesam-subcmd" };
        }
        // any other token ends the subcommand region
        if (st.mode === "expectSub") st.mode = "args";
        return null;
    };

    // Re-tokenise a plain text node, wrapping the interesting tokens.
    const processText = (node, st) => {
        const parts = node.nodeValue.split(/(\s+)/);
        const frag = document.createDocumentFragment();
        let changed = false;
        for (const part of parts) {
            if (part === "") continue;
            if (/^\s+$/.test(part)) {
                frag.appendChild(document.createTextNode(part));
                continue;
            }
            const res = classify(part, st);
            if (!res) {
                frag.appendChild(document.createTextNode(part));
                continue;
            }
            changed = true;
            if (res.cls === "sesam-flag" && res.rest) {
                frag.appendChild(span("sesam-flag", res.flagName));
                frag.appendChild(document.createTextNode(res.rest));
            } else {
                frag.appendChild(span(res.cls, part));
            }
        }
        if (changed) node.parentNode.replaceChild(frag, node);
    };

    // An hljs span (e.g. `id`/`mv`/`rm`/`ls` tagged as built_in). If it sits in
    // subcommand position, re-tag it; otherwise just let it advance the machine.
    const processElement = (el, st) => {
        const text = el.textContent;
        if (/^\s*$/.test(text)) return;
        if (/\s/.test(text)) {
            // multi-word (string/comment) — opaque, ends the subcommand region
            if (st.mode === "expectSub") st.mode = "args";
            return;
        }
        const res = classify(text, st);
        if (!res) return;
        if (res.cls === "sesam-flag" && res.rest) {
            el.className = "sesam-flag";
            el.textContent = res.flagName;
            el.parentNode.insertBefore(document.createTextNode(res.rest), el.nextSibling);
        } else {
            el.className = res.cls;
        }
    };

    const enhance = () => {
        document.querySelectorAll("pre > code.language-bash").forEach((code) => {
            const st = makeState();
            Array.from(code.childNodes).forEach((node) => {
                if (node.nodeType === Node.TEXT_NODE) processText(node, st);
                else if (node.nodeType === Node.ELEMENT_NODE) processElement(node, st);
            });
        });
    };

    if (document.readyState === "complete") enhance();
    else window.addEventListener("load", enhance);
})();
