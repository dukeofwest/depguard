import { describe, expect, it } from 'vitest';
import { formatRef, parseRepositoryUrl } from './github-url';

describe('parseRepositoryUrl', () => {
  describe('accepts the forms people actually paste', () => {
    const accepted: readonly [string, string][] = [
      ['https://github.com/expressjs/express', 'expressjs/express'],
      ['http://github.com/expressjs/express', 'expressjs/express'],
      ['https://www.github.com/expressjs/express', 'expressjs/express'],
      ['https://github.com/expressjs/express/', 'expressjs/express'],
      ['https://github.com/expressjs/express.git', 'expressjs/express'],
      ['github.com/expressjs/express', 'expressjs/express'],
      ['expressjs/express', 'expressjs/express'],
      ['  https://github.com/expressjs/express  ', 'expressjs/express'],
      // Deep links — people copy these straight from the file browser.
      ['https://github.com/expressjs/express/tree/master/lib', 'expressjs/express'],
      ['https://github.com/expressjs/express/blob/master/README.md', 'expressjs/express'],
      ['https://github.com/expressjs/express/issues/42', 'expressjs/express'],
      ['https://github.com/expressjs/express?tab=readme', 'expressjs/express'],
      ['https://github.com/expressjs/express#install', 'expressjs/express'],
      // Names using the full legal character set.
      ['https://github.com/a-b/c.d_e-f', 'a-b/c.d_e-f'],
      ['https://github.com/dot-net/Core', 'dot-net/Core'],
    ];

    for (const [input, expected] of accepted) {
      it(`parses ${input}`, () => {
        const result = parseRepositoryUrl(input);
        expect(result.ok, `expected ${input} to parse`).toBe(true);
        if (result.ok) {
          expect(formatRef(result.ref)).toBe(expected);
        }
      });
    }
  });

  describe('rejects non-GitHub and non-repository URLs', () => {
    const rejected: readonly [string, string][] = [
      ['', 'empty input'],
      ['   ', 'whitespace only'],
      ['https://gitlab.com/owner/repo', 'a different host'],
      ['https://github.evil.com/owner/repo', 'a lookalike host'],
      ['https://evil.com/github.com/owner/repo', 'host in the path'],
      ['https://github.com', 'no path'],
      ['https://github.com/expressjs', 'owner only'],
      ['https://gist.github.com/owner/id', 'a gist'],
      ['https://github.com/settings/profile', 'a settings page'],
      ['https://github.com/marketplace/actions/x', 'a marketplace page'],
      ['not a url at all', 'free text'],
      ['https://github.com/owner/repo with space', 'a space in the name'],
    ];

    for (const [input, why] of rejected) {
      it(`rejects ${why}: ${JSON.stringify(input)}`, () => {
        expect(parseRepositoryUrl(input).ok).toBe(false);
      });
    }
  });

  describe('rejects inputs that could escape the API path', () => {
    // These matter because the parsed values are interpolated into api.github.com URLs.
    const dangerous: readonly string[] = [
      'https://github.com/owner/..',
      'https://github.com/owner/.',
      'https://github.com/../../etc/passwd',
      'owner/repo/../../../admin',
      'https://github.com/owner/repo%2F..%2Fadmin',
      'javascript:alert(1)//github.com/a/b',
      'file:///etc/passwd',
      'https://github.com/own er/repo',
      `https://github.com/owner/${'x'.repeat(200)}`,
      `${'a'.repeat(600)}/b`,
    ];

    for (const input of dangerous) {
      it(`rejects ${JSON.stringify(input.slice(0, 60))}`, () => {
        const result = parseRepositoryUrl(input);
        expect(result.ok).toBe(false);
      });
    }

    it('never yields a ref containing a path separator or traversal', () => {
      // Property-style sweep: whatever gets through must be safe to interpolate.
      const inputs = [
        'https://github.com/a/b',
        'a/b',
        'github.com/a/b.git',
        'https://github.com/a/b/tree/main',
        'https://github.com/a/b%2Fc',
        'https://github.com/a/..',
      ];
      for (const input of inputs) {
        const result = parseRepositoryUrl(input);
        if (result.ok) {
          for (const value of [result.ref.owner, result.ref.repo]) {
            expect(value).not.toContain('/');
            expect(value).not.toContain('\\');
            expect(value).not.toContain('..');
            expect(value).not.toContain('%');
            expect(value.length).toBeGreaterThan(0);
          }
        }
      }
    });
  });

  it('returns a typed, user-facing error rather than throwing', () => {
    const result = parseRepositoryUrl('https://gitlab.com/a/b');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('unsupported-url');
      expect(result.error.message).toContain('github.com');
      // §10.5 — messages are safe to render directly, with no stack trace.
      expect(result.error.message).not.toContain('Error:');
    }
  });

  it('is deterministic', () => {
    const first = parseRepositoryUrl('https://github.com/npm/cli');
    const second = parseRepositoryUrl('https://github.com/npm/cli');
    expect(first).toEqual(second);
  });
});
