import { describe, expect, it } from 'vitest';
import { renderMarkdown } from './markdown';

describe('renderMarkdown list items', () => {
  it('joins an item wrapped onto indented lines into one item, with no break inside', () => {
    const html = renderMarkdown('- **A fix.** The first line\n  and its continuation.\n- Next item');
    expect(html).toContain('<li class="ml-4 list-disc text-(--text-primary)"><strong>A fix.</strong> The first line and its continuation.</li>');
    expect(html).not.toMatch(/continuation\.<br\/>/);
    expect((html.match(/<li /g) ?? []).length).toBe(2);
  });
  it('keeps emphasis that spans the wrap', () => {
    expect(renderMarkdown('- **one\n  two**')).toContain('<strong>one two</strong>');
  });
  it('leaves an unindented next line alone — that is a new paragraph, not the item', () => {
    const html = renderMarkdown('- item\nNot part of it');
    expect(html).toContain('>item</li>');
    expect(html).toContain('Not part of it');
  });
  it('never joins lines inside a fenced code block', () => {
    const html = renderMarkdown('```diff\n- return x\n  y = 2\n```');
    expect(html).not.toContain('return x y = 2');
    expect(html).toContain('y = 2');
  });
  it('never merges a nested list item into its parent', () => {
    const html = renderMarkdown('- Parent\n  - child one\n  - child two');
    expect(html).not.toContain('Parent - child one');
    expect(html).toContain('child one');
  });
});

/** The text inside the first `<code class="hljs …">` element, as rendered. */
function codeBlockBody(html: string): string {
  const m = html.match(/<code class="hljs[^"]*">([\s\S]*?)<\/code><\/pre>/);
  if (!m) throw new Error(`no code block in ${html}`);
  return m[1];
}

describe('renderMarkdown fenced code blocks', () => {
  it('keeps a diff or YAML list inside a block as written, not as list items', () => {
    const html = renderMarkdown('```yaml\nitems:\n- one\n- two\n1. three\n```');
    expect(html).not.toContain('<li');
    expect(codeBlockBody(html)).toBe('items:\n- one\n- two\n1. three');
  });
  it('applies no emphasis, inline code, link, heading, quote or rule inside a block', () => {
    const src = '**bold** *it* `tick` ~~del~~ [a](https://x.test)\n# not a heading\n> not a quote\n---';
    const body = codeBlockBody(renderMarkdown('```\n' + src + '\n```'));
    expect(body).not.toMatch(/<(strong|em|code|del|a|h1|blockquote|hr)\b/);
    expect(body).toContain('**bold** *it*');
    expect(body).toContain('# not a heading');
    expect(body).toContain('---');
  });
  it('keeps the newlines of a block as newlines, never <br/>', () => {
    const body = codeBlockBody(renderMarkdown('```\na\nb\n\nc\n```'));
    expect(body).toBe('a\nb\n\nc');
  });
  it('still renders markdown around a block', () => {
    const html = renderMarkdown('**before**\n```\n**inside**\n```\n- after');
    expect(html).toContain('<strong>before</strong>');
    expect(html).toContain('>after</li>');
    expect(codeBlockBody(html)).toBe('**inside**');
  });
  it('keeps two blocks apart and in order', () => {
    const html = renderMarkdown('```\nfirst *a*\n```\nmid *b*\n```\nsecond *c*\n```');
    const bodies = [...html.matchAll(/<code class="hljs[^"]*">([\s\S]*?)<\/code>/g)].map((m) => m[1]);
    expect(bodies).toEqual(['first *a*', 'second *c*']);
    expect(html).toContain('mid <em>b</em>');
  });
  it('a NUL in the input cannot address a block placeholder', () => {
    const html = renderMarkdown('```\nsecret\n```\nx\u0000MDBLOCK0\u0000y');
    expect((html.match(/secret/g) ?? []).length).toBe(1);
  });
});

describe('renderMarkdown inline code', () => {
  it('applies no emphasis inside a code span', () => {
    expect(renderMarkdown('use `**kwargs` and `*args*`')).toBe(
      'use <code class="bg-(--bg-secondary) px-1.5 py-0.5 rounded-sm text-sm font-mono">**kwargs</code> and <code class="bg-(--bg-secondary) px-1.5 py-0.5 rounded-sm text-sm font-mono">*args*</code>',
    );
  });
});

describe('renderMarkdown nested lists', () => {
  it('renders an indented item as a nested list item, one level deeper', () => {
    const html = renderMarkdown('- Parent\n  - child one\n  - child two');
    const items = html.match(/<li class="[^"]*">[^<]*<\/li>/g) ?? [];
    expect(items).toHaveLength(3);
    expect(items[0]).toContain('ml-4');
    expect(items[1]).toContain('ml-8');
    expect(items[1]).toContain('>child one<');
    expect(html).not.toContain('  - child');
  });
  it('renders an indented numbered item nested too', () => {
    const html = renderMarkdown('1. Parent\n   1. child');
    expect(html).toMatch(/<li class="ml-8 list-decimal[^"]*">child<\/li>/);
  });

  it('joins a wrapped nested item onto its line', () => {
    const html = renderMarkdown('- Parent\n  - child that wraps\n    onto this line');
    expect(html).toMatch(/<li class="ml-8[^"]*">child that wraps onto this line<\/li>/);
  });

  it('restores a fence parked inside an inline-code span', () => {
    const html = renderMarkdown('`a ```\nx\n``` b`');
    expect(html).not.toContain('\u0000');
    expect(html).not.toContain('MDBLOCK');
    expect(html).toContain('x');
  });
});

/** A stand-in for hljs that returns its input escaped, as hljs does for plain text. */
const echoHljs = {
  getLanguage: () => true,
  highlight: (code: string) => ({ value: code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }),
  highlightAuto: (code: string) => ({ value: code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }),
};

describe('renderMarkdown code as written', () => {
  it('hands the highlighter the source text exactly, quotes and entities included', () => {
    const seen: string[] = [];
    const spy = { ...echoHljs, highlight: (code: string) => { seen.push(code); return echoHljs.highlight(code); } };
    renderMarkdown("```js\nconst s = 'a' + \"b\"; // &lt; & <\n```", spy);
    expect(seen).toEqual(["const s = 'a' + \"b\"; // &lt; & <"]);
  });
  it('shows a quote as a quote, never &#39;', () => {
    expect(codeBlockBody(renderMarkdown("```js\nx = 'a'\n```", echoHljs))).toBe("x = 'a'");
  });
  it('opens a fence with any info string, trailing spaces or CRLF line endings', () => {
    for (const src of ['```c++\nint a;\n```', '```python   \nint a;\n```', '```js\r\nint a;\r\n```\r\n', '```js title="a.js"\nint a;\n```']) {
      expect(codeBlockBody(renderMarkdown(src))).toBe('int a;');
    }
    expect(renderMarkdown('```c++\nint a;\n```')).toContain('language-c');
  });
  it('closes a fence only on a line of its own, so the next block stays a block', () => {
    const html = renderMarkdown('```c++\na\n```\ntext\n```py\nb\n```');
    const bodies = [...html.matchAll(/<code class="hljs[^"]*">([\s\S]*?)<\/code>/g)].map((m) => m[1]);
    expect(bodies).toEqual(['a', 'b']);
    expect(html).toContain('text');
  });
  it("keeps the first line's indent", () => {
    expect(codeBlockBody(renderMarkdown('```\n    indented\n  less\n```'))).toBe('    indented\n  less');
  });
});

describe('renderMarkdown links', () => {
  it('never puts a code span inside a link URL', () => {
    const html = renderMarkdown('[x](https://a.test/`code`)');
    expect(html).not.toMatch(/href="[^"]*<code/);
    expect(html).not.toContain('<a ');
  });
  it('still renders an https link (positive control)', () => {
    expect(renderMarkdown('[x](https://a.test/p)')).toContain('<a href="https://a.test/p"');
  });
});

describe('renderMarkdown nesting by the indents used', () => {
  it('nests a four-space list one level per step', () => {
    const items = renderMarkdown('- a\n    - b\n        - c').match(/<li class="(ml-\d+)/g) ?? [];
    expect(items).toEqual(['<li class="ml-4', '<li class="ml-8', '<li class="ml-12']);
  });
  it('nests a two-space list the same way', () => {
    const items = renderMarkdown('- a\n  - b\n    - c').match(/<li class="(ml-\d+)/g) ?? [];
    expect(items).toEqual(['<li class="ml-4', '<li class="ml-8', '<li class="ml-12']);
  });
});

describe('renderMarkdown blocks inside lists', () => {
  it('renders a fence indented under a list item as a code block, without the list indent', () => {
    const html = renderMarkdown('1. Install:\n   ```bash\n   npm install\n     --save\n   ```\n2. Run');
    expect(codeBlockBody(html)).toBe('npm install\n  --save');
    expect(html).toContain('>Install:</li>');
    expect(html).toContain('>Run</li>');
  });
  it('nests an item set off by blank lines under its parent (a loose list)', () => {
    const items = renderMarkdown('1. Step one\n\n   - detail\n\n2. Step two').match(/<li class="(ml-\d+)/g) ?? [];
    expect(items).toEqual(['<li class="ml-4', '<li class="ml-8', '<li class="ml-4']);
  });
  it('keeps an item after a code block nested under the item before it', () => {
    const items = renderMarkdown('- parent\n  ```\n  code\n  ```\n  - child').match(/<li class="(ml-\d+)/g) ?? [];
    expect(items).toEqual(['<li class="ml-4', '<li class="ml-8']);
  });
});
