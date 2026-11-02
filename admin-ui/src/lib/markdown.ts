/**
 * Shared lightweight markdown renderer.
 *
 * Used for both trusted content (changelog) and untrusted content (session replay).
 * All input is HTML-escaped before processing — safe for rendering via {@html}.
 *
 * Supports: headings, bold, italic, strikethrough, inline code, fenced code blocks,
 * tables, blockquotes, lists, links (https only), and horizontal rules.
 *
 * Code block highlighting is optional — pass an `hljs` instance for syntax colors,
 * otherwise code blocks render as plain `<pre>`.
 */

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

interface HljsLike {
  getLanguage(lang: string): unknown;
  highlight(code: string, opts: { language: string }): { value: string };
  highlightAuto(code: string): { value: string };
}

/**
 * A fenced code block: an opening fence starting a line — after any indent, so
 * a block nested under a list item is one — with an optional info string (its
 * first word is the language — `c++`, `objective-c`), and a closing fence alone
 * on its own line. Line-anchored, so a fence's backticks inside a line never
 * open or close one. Groups: the opening indent, the info string, the body.
 * Line endings are normalised to `\n` before this runs.
 */
const FENCE_SOURCE = '^([ \\t]*)```([^\\n`]*)\\n([\\s\\S]*?)^[ \\t]*```[ \\t]*$';

/**
 * A list item wrapped onto indented lines is ONE item (CommonMark's
 * continuation lines): joined before any other pass, so emphasis or a link
 * that spans the wrap still pairs up, and no line break lands inside. Never
 * inside a fenced code block — code keeps every line as written — and never an
 * indented list marker, which is a nested item, not a continuation.
 */
function joinListContinuations(text: string): string {
  // split() alternates text and captures. The fence's own groups are turned
  // non-capturing here, so the whole fence is the ONE capture and every odd
  // index is a fence — a capturing inner group would interleave its pieces.
  const parts = text.split(new RegExp(`(${FENCE_SOURCE.replace(/\((?!\?)/g, '(?:')})`, 'm'));
  return parts
    .map((part, i) =>
      i % 2 === 1
        ? part
        : part.replace(/^([ \t]*(?:- |\d+\. ).*)((?:\n[ \t]+(?![-*+] |\d+\. )\S.*)+)/gm, (_m, first: string, rest: string) =>
            first + rest.replace(/\n[ \t]+/g, ' '),
          ),
    )
    .join('');
}

/** Nested list depth (1-based) → its indent class; deeper nesting stays at the last. */
const LIST_INDENT = ['ml-4', 'ml-8', 'ml-12'] as const;

const indentWidth = (lead: string) => lead.replace(/\t/g, '    ').length;

/**
 * The items of one run of list lines (blank lines between items included). An
 * item's depth is the rank of its indent among the distinct indents the run
 * uses, so a list indented by two, three or four columns per level nests one
 * level per step either way; a run that starts indented starts one level in.
 */
function renderListRun(run: string): string {
  const items = run.replace(/\n$/, '').split('\n').map((line) => {
    const m = /^([ \t]*)(- |\d+\. )(.+)$/.exec(line);
    return m ? { width: indentWidth(m[1]), ordered: m[2] !== '- ', body: m[3] } : null;
  });
  const widths = [...new Set(items.flatMap((it) => (it ? [it.width] : [])))].sort((a, b) => a - b);
  // A run with no item at the margin continues a list something else
  // interrupted (a code block, a paragraph line): its shallowest items are
  // nested one level under an item outside the run.
  const base = widths[0] > 0 ? 1 : 0;
  const html = items
    .map((it) => {
      if (!it) return '';
      const depth = Math.min(LIST_INDENT.length - 1, base + widths.indexOf(it.width));
      const kind = it.ordered ? 'list-decimal' : 'list-disc';
      return `<li class="${LIST_INDENT[depth]} ${kind} text-(--text-primary)">${it.body}</li>`;
    })
    .join('\n');
  return run.endsWith('\n') ? `${html}\n` : html;
}

/** Exactly the entities `escapeHtml` produces, undone in one pass. */
const UNESCAPE: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" };
const unescapeHtml = (text: string) => text.replace(/&(amp|lt|gt|quot|#39);/g, (_m, e: string) => UNESCAPE[e]);

export function renderMarkdown(text: string, hljs?: HljsLike): string {
  if (!text) return '';
  // Rendered code (fenced blocks, inline spans) is parked behind a NUL-delimited
  // placeholder so no later pass rewrites its inside, and put back after the
  // last pass that could. The input's own NULs are dropped first, so no input
  // can name a placeholder.
  const parked: string[] = [];
  const park = (rendered: string) => `\u0000MDBLOCK${parked.push(rendered) - 1}\u0000`;
  let html = escapeHtml(joinListContinuations(text.replace(/\u0000/g, '').replace(/\r\n?/g, '\n')));
  // Code blocks with optional syntax highlighting (before other transforms).
  // The code keeps its own whitespace: only the newline before the closing
  // fence is dropped.
  html = html.replace(new RegExp(FENCE_SOURCE, 'gm'), (_m, indent: string, info: string, body: string) => {
    const lang = info.trim().split(/\s+/)[0] ?? '';
    // A nested block's lines carry the fence's indent; it is the list's, not
    // the code's (CommonMark strips up to that much from each line).
    const code = body
      .replace(/\n$/, '')
      .split('\n')
      .map((line) => line.slice(Math.min(indent.length, line.length - line.trimStart().length)))
      .join('\n');
    const raw = unescapeHtml(code);
    let highlighted: string;
    if (hljs) {
      try {
        highlighted = lang && hljs.getLanguage(lang)
          ? hljs.highlight(raw, { language: lang }).value
          : hljs.highlightAuto(raw).value;
        highlighted = highlighted.replace(/<(?!\/?span\b)[^>]*>/g, (tag) => escapeHtml(tag));
      } catch {
        highlighted = code;
      }
    } else {
      highlighted = code;
    }
    const safeLang = lang.replace(/[^a-zA-Z0-9_-]/g, '');
    return park(`<pre class="bg-(--bg-secondary) rounded-lg p-3 my-2 overflow-x-auto text-sm"><code class="hljs language-${safeLang}">${highlighted}</code></pre>`);
  });
  html = html.replace(/`([^`\n]+)`/g, (_m, code: string) =>
    park(`<code class="bg-(--bg-secondary) px-1.5 py-0.5 rounded-sm text-sm font-mono">${code}</code>`));
  // Tables: consecutive lines starting with |
  html = html.replace(/((?:^\|.+\|$\n?){2,})/gm, (tableBlock) => {
    const lines = tableBlock.trim().split('\n').filter(l => l.trim());
    if (lines.length < 2) return tableBlock;
    const sepIdx = lines.findIndex(l => /^\|[\s\-:|]+\|$/.test(l.trim()));
    const headerLines = sepIdx > 0 ? lines.slice(0, sepIdx) : [];
    const bodyLines = sepIdx >= 0 ? lines.slice(sepIdx + 1) : lines;
    const parseCells = (line: string) => line.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
    let t = '<div class="overflow-x-auto my-2"><table class="text-xs font-mono border-collapse w-full">';
    if (headerLines.length > 0) {
      t += '<thead>';
      for (const hl of headerLines) {
        t += '<tr>';
        for (const cell of parseCells(hl)) {
          t += `<th class="border border-(--border) px-3 py-1.5 text-left text-(--text-secondary) bg-(--bg-primary)/50 font-semibold">${cell}</th>`;
        }
        t += '</tr>';
      }
      t += '</thead>';
    }
    if (bodyLines.length > 0) {
      t += '<tbody>';
      for (const bl of bodyLines) {
        t += '<tr>';
        for (const cell of parseCells(bl)) {
          t += `<td class="border border-(--border) px-3 py-1.5 text-(--text-primary)">${cell}</td>`;
        }
        t += '</tr>';
      }
      t += '</tbody>';
    }
    t += '</table></div>';
    return t;
  });
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/~~([^~]+)~~/g, '<del class="text-(--text-secondary)">$1</del>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  // Links: [text](url) — only allow http(s) URLs
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match: string, text: string, url: string) => {
    // A URL holding a parked code span is not a link: restoring the span
    // inside the attribute would break out of it.
    if (url.includes('\u0000')) return _match;
    if (/^https?:\/\//i.test(url)) {
      return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="text-(--accent) hover:underline">${text}</a>`;
    }
    return text;
  });
  // Headings (### before ## before #)
  html = html.replace(/^### (.+)$/gm, '<h3 class="text-base font-bold text-(--text-primary) mt-3 mb-1">$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-(--text-primary) mt-3 mb-1">$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold text-(--text-primary) mt-3 mb-1">$1</h1>');
  // Horizontal rules
  html = html.replace(/^-{3,}$/gm, '<hr class="border-(--border) my-3" />');
  html = html.replace(/^\*{3,}$/gm, '<hr class="border-(--border) my-3" />');
  // Blockquotes
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote class="border-l-2 border-(--accent) pl-3 text-(--text-secondary) italic">$1</blockquote>');
  // Lists — an indented marker is a nested item (see renderListRun). A blank
  // line between two items keeps them in one run (a "loose" list), so a nested
  // item set off by blank lines still ranks against its parent.
  html = html.replace(/(?:^[ \t]*(?:- |\d+\. ).+$\n?(?:\n(?=[ \t]*(?:- |\d+\. )))?)+/gm, renderListRun);
  html = html.replace(/\n/g, '<br/>');
  // A parked span can hold another's placeholder (inline code around a fence),
  // so restore until none is left; each pass removes at least one level.
  const placeholder = /\u0000MDBLOCK(\d+)\u0000/g;
  while (html.includes('\u0000MDBLOCK')) {
    html = html.replace(placeholder, (_m, i: string) => parked[Number(i)]);
  }
  // Clean up: remove <br/> after block elements
  html = html.replace(/<\/(pre|table|div|h[1-3]|li|blockquote|hr)><br\/>/g, '</$1>');
  html = html.replace(/<br\/><(pre|div|h[1-3]|li|blockquote|hr)/g, '<$1');
  html = html.replace(/(<hr [^>]*\/>)<br\/>/g, '$1');
  return html;
}
