import { describe, expect, it } from 'vitest';
import { attach, attachmentsChanged, detach, entriesFromText, unattached } from '#lib/destinationAttachments.js';

describe('attach / detach', () => {
  it('attaches a list once, and re-attaching changes only its mode', () => {
    const one = attach([], 'a', 'allow');
    expect(one).toEqual([{ list_id: 'a', mode: 'allow' }]);
    const two = attach(one, 'b', 'block');
    expect(two).toHaveLength(2);
    const flipped = attach(two, 'a', 'block');
    expect(flipped).toHaveLength(2);
    expect(flipped.find((x) => x.list_id === 'a')?.mode).toBe('block');
  });

  it('detaches only the list named', () => {
    const both = [{ list_id: 'a', mode: 'allow' as const }, { list_id: 'b', mode: 'block' as const }];
    expect(detach(both, 'a')).toEqual([{ list_id: 'b', mode: 'block' }]);
    expect(detach(both, 'zzz')).toEqual(both);
  });
});

describe('unattached', () => {
  it('lists what is not attached yet, in order', () => {
    const lists = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    expect(unattached(lists, [{ list_id: 'b', mode: 'allow' }])).toEqual([{ id: 'a' }, { id: 'c' }]);
    expect(unattached(lists, [])).toEqual(lists);
  });
});

describe('attachmentsChanged', () => {
  it('ignores order and sees an add, a removal and a mode flip', () => {
    const a = [{ list_id: 'a', mode: 'allow' as const }, { list_id: 'b', mode: 'block' as const }];
    expect(attachmentsChanged(a, [...a].reverse())).toBe(false);
    expect(attachmentsChanged(a, a.slice(1))).toBe(true);
    expect(attachmentsChanged(a.slice(1), a)).toBe(true);
    expect(attachmentsChanged(a, [{ list_id: 'a', mode: 'block' }, { list_id: 'b', mode: 'block' }])).toBe(true);
    expect(attachmentsChanged(a, [{ list_id: 'a', mode: 'allow' }, { list_id: 'c', mode: 'block' }])).toBe(true);
  });
});

describe('entriesFromText', () => {
  it('reads one entry per line and drops blank lines', () => {
    expect(entriesFromText(' github.com:443,22 \n\n*.corp.example\n  \n10.0.0.0/8')).toEqual([
      'github.com:443,22',
      '*.corp.example',
      '10.0.0.0/8',
    ]);
    expect(entriesFromText('')).toEqual([]);
  });
});
