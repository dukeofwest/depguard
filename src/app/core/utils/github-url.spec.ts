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

  describe('rejects hosts that are not github.com', () => {
    // MANDATORY_SECURITY_REQUIREMENT §A8. The parsed owner and repo are interpolated into
    // api.github.com URLs, so over-permissiveness here is what would turn a text field
    // into a request-forgery primitive. Every form of "somewhere else" is covered,
    // including the ones that look like github.com to a careless check.
    const rejected: readonly [string, string][] = [
      ['https://127.0.0.1/owner/repo', 'a loopback address'],
      ['http://localhost:8080/owner/repo', 'localhost'],
      ['https://192.168.1.1/owner/repo', 'a private network address'],
      ['https://10.0.0.1/owner/repo', 'another private range'],
      ['https://172.16.0.1/owner/repo', 'a third private range'],
      ['https://169.254.169.254/owner/repo', 'the cloud metadata address'],
      ['https://[::1]/owner/repo', 'an IPv6 loopback'],
      ['https://2130706433/owner/repo', 'a loopback address in decimal form'],
      ['https://0x7f000001/owner/repo', 'a loopback address in hexadecimal form'],
      ['https://github.com./owner/repo', 'a trailing-dot hostname'],
      ['https://github.com@evil.com/owner/repo', 'github.com as userinfo on another host'],
      ['https://github.com.evil.com/owner/repo', 'github.com as a subdomain of another host'],
      ['https://api.github.com/repos/owner/repo', 'the API host rather than the web host'],
      ['https://raw.githubusercontent.com/owner/repo/main/x', 'the raw content host'],
    ];

    for (const [input, why] of rejected) {
      it(`rejects ${why}: ${JSON.stringify(input)}`, () => {
        expect(parseRepositoryUrl(input).ok).toBe(false);
      });
    }
  });

  describe('rejects credentials and unexpected ports', () => {
    // Both of these parsed to a clean owner/repo before being rejected explicitly, which
    // is why they are pinned here: the failure was silent acceptance, not a crash.
    const rejected: readonly [string, string][] = [
      ['https://user:pass@github.com/owner/repo', 'a username and password'],
      ['https://token@github.com/owner/repo', 'a token as userinfo'],
      ['https://:pass@github.com/owner/repo', 'a password alone'],
      ['https://github.com:8080/owner/repo', 'a non-default port'],
      ['https://github.com:22/owner/repo', 'a port for another protocol'],
    ];

    for (const [input, why] of rejected) {
      it(`rejects ${why}: ${JSON.stringify(input)}`, () => {
        expect(parseRepositoryUrl(input).ok).toBe(false);
      });
    }

    it('still accepts the explicit default HTTPS port', () => {
      const result = parseRepositoryUrl('https://github.com:443/expressjs/express');
      expect(result.ok).toBe(true);
    });

    it('names the credential problem instead of silently dropping it', () => {
      const result = parseRepositoryUrl('https://user:token@github.com/owner/repo');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message.toLowerCase()).toContain('credential');
      }
    });
  });

  describe('is case-insensitive about the host but not the repository', () => {
    it('accepts an upper-case host', () => {
      expect(parseRepositoryUrl('https://GITHUB.COM/expressjs/express').ok).toBe(true);
    });

    it('preserves the case of owner and repo, which GitHub treats as given', () => {
      const result = parseRepositoryUrl('https://github.com/ExpressJS/Express');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.ref).toEqual({ owner: 'ExpressJS', repo: 'Express' });
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
