/**
 * A minimal, bounded XML reader for untrusted project files.
 *
 * ## Why this exists rather than `DOMParser` or a library
 *
 * The engine is pure (§4.4): no DOM, no browser APIs. `DOMParser` is a browser global, so
 * using it here would break that boundary and make the parser untestable in the engine's
 * own environment. A library would be a new runtime dependency processing untrusted input,
 * which ADR-0005 declined for YAML on the same reasoning.
 *
 * So this reads exactly as much XML as MSBuild project files need — elements, attributes
 * and text — and **refuses** everything else rather than ignoring it. It is not a
 * general-purpose XML parser and must not be used as one.
 *
 * ## What it refuses, and why
 *
 * - **Any DOCTYPE declaration.** This forecloses the entire external-entity (XXE) and
 *   entity-expansion ("billion laughs") class in one rule, rather than trying to
 *   distinguish a safe DTD from a hostile one. No real `.csproj` has a DOCTYPE.
 * - **Any entity reference other than the five XML built-ins.** A custom entity cannot be
 *   defined without a DOCTYPE, so one appearing here is either malformed or an attack.
 * - **Depth, node count, attribute count, name and value length**, each bounded, because
 *   this input arrives from a repository DepGuard does not control.
 *
 * Nothing is ever resolved from outside the string passed in: no network access, no file
 * access, no entity resolution.
 *
 * ## Recursion, stated accurately
 *
 * `XmlReader.readElement` is **recursive**: one call per element, nested as the document
 * nests. It is safe because the depth bound is checked on entry, before the element is
 * read, so the recursion cannot go deeper than `XML_LIMITS.maxDepth` (64) regardless of
 * the input — a 10,000-level document is rejected at level 65, which `nuget.spec.ts`
 * tests directly.
 *
 * Worth saying plainly, because the elimination of recursion elsewhere in the engine
 * could be read as a claim about this file. The npm lockfile walker and `findElements`
 * below are iterative for a different reason: they traverse structures whose depth is
 * bounded only *after* parsing, or not at all, so recursion there would overflow on
 * exactly the input the bound exists to reject. Here the bound comes first, so bounded
 * recursion is adequate and the shape of the code follows the shape of the grammar.
 */

export const XML_LIMITS = {
  maxBytes: 512 * 1024,
  maxDepth: 64,
  maxNodes: 50_000,
  maxAttributesPerElement: 64,
  maxNameLength: 256,
  maxValueLength: 4096,
} as const;

export interface XmlElement {
  readonly name: string;
  /** Attribute names are lowercased for lookup; MSBuild treats them case-insensitively. */
  readonly attributes: Readonly<Record<string, string>>;
  readonly children: readonly XmlElement[];
  /** Direct text content, trimmed. Empty when the element has none. */
  readonly text: string;
}

export type XmlParseResult =
  | { readonly kind: 'parsed'; readonly root: XmlElement }
  | { readonly kind: 'rejected'; readonly reason: string };

/** The five entities XML defines without a DTD. Nothing else is accepted. */
const BUILT_IN_ENTITIES: Readonly<Record<string, string>> = {
  lt: '<',
  gt: '>',
  amp: '&',
  apos: "'",
  quot: '"',
};

/**
 * Parses an MSBuild-style XML document.
 *
 * Total: every input produces a result and none throws. Rejection carries a reason that
 * is safe to show a user and specific enough to act on.
 */
export function parseXml(text: string): XmlParseResult {
  if (typeof text !== 'string') {
    return { kind: 'rejected', reason: 'The project file was not text.' };
  }
  if (text.length === 0) {
    return { kind: 'rejected', reason: 'The project file is empty.' };
  }
  if (text.length > XML_LIMITS.maxBytes) {
    return {
      kind: 'rejected',
      reason: `The project file is larger than the ${Math.round(XML_LIMITS.maxBytes / 1024)} KB DepGuard will parse.`,
    };
  }

  // Checked on the raw text, before any structural parsing, so a hostile DTD is refused
  // without being examined. `<!DOCTYPE` cannot appear legitimately in a project file.
  if (/<!DOCTYPE/i.test(text)) {
    return {
      kind: 'rejected',
      reason:
        'The project file contains a DOCTYPE declaration, which DepGuard refuses: it is the mechanism behind XML external entity and entity expansion attacks, and no MSBuild project file needs one.',
    };
  }
  if (/<!ENTITY/i.test(text)) {
    return {
      kind: 'rejected',
      reason: 'The project file declares XML entities, which DepGuard refuses to process.',
    };
  }

  return new XmlReader(text).read();
}

/** Finds all descendants with the given element name, case-insensitively. */
export function findElements(root: XmlElement, name: string): readonly XmlElement[] {
  const wanted = name.toLowerCase();
  const found: XmlElement[] = [];

  // Iterative, for the same reason the JSON shape checker is. Unlike `readElement`, this
  // runs over an already-parsed tree and is reachable from callers that did not build it
  // here, so it cannot rely on `maxDepth` having been checked on the way in.
  const stack: XmlElement[] = [root];
  while (stack.length > 0) {
    const element = stack.pop();
    if (element === undefined) {
      break;
    }
    if (element.name.toLowerCase() === wanted) {
      found.push(element);
    }
    for (const child of element.children) {
      stack.push(child);
    }
  }

  return found;
}

/** An attribute's value by name, case-insensitively, or null. */
export function attribute(element: XmlElement, name: string): string | null {
  const value = element.attributes[name.toLowerCase()];
  return value === undefined || value.length === 0 ? null : value;
}

/** A direct child element by name, case-insensitively, or null. */
export function childElement(element: XmlElement, name: string): XmlElement | null {
  const wanted = name.toLowerCase();
  return element.children.find((child) => child.name.toLowerCase() === wanted) ?? null;
}

/**
 * A hand-written scanner.
 *
 * Deliberately small and deliberately strict. Anything it does not understand becomes a
 * rejection with a reason, never a silent skip — a parser that quietly ignores what it
 * cannot read produces an inventory that looks complete and is not.
 */
class XmlReader {
  private position = 0;
  private nodes = 0;

  constructor(private readonly text: string) {}

  read(): XmlParseResult {
    this.skipProlog();

    const root = this.readElement(1);
    if (root.kind !== 'parsed') {
      return root;
    }

    // Trailing content after the root element is checked, because a document with two
    // roots is malformed and silently taking the first would be a guess.
    this.skipWhitespaceAndComments();
    if (this.position < this.text.length) {
      return { kind: 'rejected', reason: 'The project file has content after its root element.' };
    }

    return root;
  }

  /** Skips the XML declaration, comments, processing instructions and whitespace. */
  private skipProlog(): void {
    for (;;) {
      this.skipWhitespaceAndComments();
      if (this.text.startsWith('<?', this.position)) {
        const end = this.text.indexOf('?>', this.position);
        if (end < 0) {
          this.position = this.text.length;
          return;
        }
        this.position = end + 2;
        continue;
      }
      return;
    }
  }

  private skipWhitespaceAndComments(): void {
    for (;;) {
      while (this.position < this.text.length && /\s/.test(this.text[this.position] ?? '')) {
        this.position += 1;
      }
      if (this.text.startsWith('<!--', this.position)) {
        const end = this.text.indexOf('-->', this.position);
        this.position = end < 0 ? this.text.length : end + 3;
        continue;
      }
      // CDATA is skipped rather than read: MSBuild package metadata never uses it, and
      // treating its contents as markup would be wrong.
      if (this.text.startsWith('<![CDATA[', this.position)) {
        const end = this.text.indexOf(']]>', this.position);
        this.position = end < 0 ? this.text.length : end + 3;
        continue;
      }
      return;
    }
  }

  private readElement(depth: number): XmlParseResult {
    if (depth > XML_LIMITS.maxDepth) {
      return {
        kind: 'rejected',
        reason: `The project file nests elements more than ${XML_LIMITS.maxDepth} levels deep.`,
      };
    }
    this.nodes += 1;
    if (this.nodes > XML_LIMITS.maxNodes) {
      return {
        kind: 'rejected',
        reason: `The project file contains more than ${XML_LIMITS.maxNodes} elements.`,
      };
    }

    if (this.text[this.position] !== '<') {
      return { kind: 'rejected', reason: 'The project file is not valid XML.' };
    }
    this.position += 1;

    const name = this.readName();
    if (name === null) {
      return { kind: 'rejected', reason: 'The project file contains an element with no name.' };
    }

    const attributes: Record<string, string> = Object.create(null) as Record<string, string>;
    let attributeCount = 0;

    for (;;) {
      this.skipSpaces();

      if (this.text.startsWith('/>', this.position)) {
        this.position += 2;
        return { kind: 'parsed', root: { name, attributes, children: [], text: '' } };
      }
      if (this.text[this.position] === '>') {
        this.position += 1;
        break;
      }
      if (this.position >= this.text.length) {
        return { kind: 'rejected', reason: `The element <${name}> is not closed.` };
      }

      attributeCount += 1;
      if (attributeCount > XML_LIMITS.maxAttributesPerElement) {
        return {
          kind: 'rejected',
          reason: `The element <${name}> has more than ${XML_LIMITS.maxAttributesPerElement} attributes.`,
        };
      }

      const attributeName = this.readName();
      if (attributeName === null) {
        return { kind: 'rejected', reason: `The element <${name}> has a malformed attribute.` };
      }

      this.skipSpaces();
      if (this.text[this.position] !== '=') {
        // A bare attribute with no value is HTML, not XML.
        return {
          kind: 'rejected',
          reason: `The attribute ${attributeName} on <${name}> has no value.`,
        };
      }
      this.position += 1;
      this.skipSpaces();

      const value = this.readAttributeValue();
      if (value.kind === 'rejected') {
        return value;
      }
      attributes[attributeName.toLowerCase()] = value.value;
    }

    // Children and text.
    const children: XmlElement[] = [];
    let text = '';

    for (;;) {
      if (this.position >= this.text.length) {
        return { kind: 'rejected', reason: `The element <${name}> is not closed.` };
      }

      if (this.text.startsWith('</', this.position)) {
        this.position += 2;
        const closing = this.readName();
        this.skipSpaces();
        if (this.text[this.position] !== '>') {
          return { kind: 'rejected', reason: `The closing tag for <${name}> is malformed.` };
        }
        this.position += 1;
        if (closing === null || closing.toLowerCase() !== name.toLowerCase()) {
          return {
            kind: 'rejected',
            reason: `The element <${name}> is closed by </${closing ?? ''}>.`,
          };
        }
        return {
          kind: 'parsed',
          root: {
            name,
            attributes,
            children,
            text: text.trim().slice(0, XML_LIMITS.maxValueLength),
          },
        };
      }

      if (
        this.text.startsWith('<!--', this.position) ||
        this.text.startsWith('<![CDATA[', this.position)
      ) {
        this.skipWhitespaceAndComments();
        continue;
      }

      if (this.text[this.position] === '<') {
        const child = this.readElement(depth + 1);
        if (child.kind !== 'parsed') {
          return child;
        }
        children.push(child.root);
        continue;
      }

      // Text run, up to the next tag.
      const next = this.text.indexOf('<', this.position);
      const end = next < 0 ? this.text.length : next;
      const raw = this.text.slice(this.position, end);
      this.position = end;

      const decoded = decodeEntities(raw);
      if (decoded === null) {
        return {
          kind: 'rejected',
          reason: `The element <${name}> contains an entity reference DepGuard does not accept.`,
        };
      }
      // Bounded as it accumulates, so a document made of one enormous text run cannot
      // grow the string without limit.
      if (text.length < XML_LIMITS.maxValueLength) {
        text += decoded;
      }
    }
  }

  private skipSpaces(): void {
    while (this.position < this.text.length && /\s/.test(this.text[this.position] ?? '')) {
      this.position += 1;
    }
  }

  /** An element or attribute name. Namespace prefixes are kept as written. */
  private readName(): string | null {
    const start = this.position;
    while (this.position < this.text.length) {
      const character = this.text[this.position] ?? '';
      if (/[A-Za-z0-9_.:-]/.test(character)) {
        this.position += 1;
        continue;
      }
      break;
    }
    const name = this.text.slice(start, this.position);
    if (name.length === 0 || name.length > XML_LIMITS.maxNameLength) {
      return null;
    }
    return name;
  }

  private readAttributeValue():
    { kind: 'parsed'; value: string } | { kind: 'rejected'; reason: string } {
    const quote = this.text[this.position];
    if (quote !== '"' && quote !== "'") {
      return { kind: 'rejected', reason: 'An attribute value is not quoted.' };
    }
    this.position += 1;

    const end = this.text.indexOf(quote, this.position);
    if (end < 0) {
      return { kind: 'rejected', reason: 'An attribute value is not terminated.' };
    }

    const raw = this.text.slice(this.position, end);
    this.position = end + 1;

    if (raw.length > XML_LIMITS.maxValueLength) {
      return {
        kind: 'rejected',
        reason: `An attribute value is longer than ${XML_LIMITS.maxValueLength} characters.`,
      };
    }

    const decoded = decodeEntities(raw);
    if (decoded === null) {
      return {
        kind: 'rejected',
        reason: 'An attribute value contains an entity reference DepGuard does not accept.',
      };
    }
    return { kind: 'parsed', value: decoded };
  }
}

/**
 * Decodes the five built-in entities and numeric character references.
 *
 * Returns null for **any** other entity reference. Without a DOCTYPE a custom entity
 * cannot be declared, so one appearing in the document is either malformed or an attempt
 * at expansion — and since this never consults a DTD, there is nothing to expand it from.
 * Refusing is both correct and the safe default.
 */
function decodeEntities(raw: string): string | null {
  if (!raw.includes('&')) {
    return raw;
  }

  let output = '';
  let index = 0;

  while (index < raw.length) {
    const ampersand = raw.indexOf('&', index);
    if (ampersand < 0) {
      output += raw.slice(index);
      break;
    }

    output += raw.slice(index, ampersand);

    const semicolon = raw.indexOf(';', ampersand);
    // A reference longer than this is not a reference.
    if (semicolon < 0 || semicolon - ampersand > 12) {
      return null;
    }

    const reference = raw.slice(ampersand + 1, semicolon);

    if (reference.startsWith('#')) {
      const isHex = reference[1] === 'x' || reference[1] === 'X';
      const digits = isHex ? reference.slice(2) : reference.slice(1);
      if (digits.length === 0 || !(isHex ? /^[0-9a-fA-F]+$/ : /^[0-9]+$/).test(digits)) {
        return null;
      }
      const code = Number.parseInt(digits, isHex ? 16 : 10);
      // Valid Unicode scalar values only; surrogates and out-of-range are refused.
      if (
        !Number.isFinite(code) ||
        code <= 0 ||
        code > 0x10ffff ||
        (code >= 0xd800 && code <= 0xdfff)
      ) {
        return null;
      }
      output += String.fromCodePoint(code);
    } else {
      const replacement = Object.prototype.hasOwnProperty.call(BUILT_IN_ENTITIES, reference)
        ? BUILT_IN_ENTITIES[reference]
        : undefined;
      if (replacement === undefined) {
        return null;
      }
      output += replacement;
    }

    index = semicolon + 1;
  }

  return output;
}
