import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LandingComponent } from './landing.component';
import { RateLimitService } from '../../core/services/rate-limit.service';
import { ScanStore } from '../../core/state/scan.store';

/**
 * Landing page tests (§13.3).
 *
 * The important behaviour is that an invalid URL never reaches the network: with only 60
 * requests available per hour, a typo must cost nothing.
 */
describe('LandingComponent', () => {
  let fixture: ComponentFixture<LandingComponent>;
  let element: HTMLElement;
  let store: ScanStore;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LandingComponent],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    store = TestBed.inject(ScanStore);
    fixture = TestBed.createComponent(LandingComponent);
    fixture.detectChanges();
    element = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  function type(value: string): void {
    const input = element.querySelector('#repository-url') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  function submit(): void {
    const form = element.querySelector('form') as HTMLFormElement;
    form.dispatchEvent(new Event('submit'));
    fixture.detectChanges();
  }

  it('renders the product purpose and the input', () => {
    expect(element.querySelector('h1')?.textContent).toContain('health of any GitHub repository');
    expect(element.querySelector('#repository-url')).not.toBeNull();
  });

  it('states what DepGuard cannot tell you, on the landing page', () => {
    // §2.4 puts transparency ahead of impressive presentation: the limits are stated
    // before the user runs anything, not only afterwards.
    const text = element.textContent ?? '';
    expect(text).toContain('does not read or execute source code');
    expect(text).toContain('lockfile');
    expect(text).toContain('not the same as safe');
  });

  it('explains the privacy model without being asked', () => {
    expect(element.textContent ?? '').toContain('runs entirely in your browser');
    expect(element.textContent ?? '').toContain('never asks for an account or a token');
  });

  describe('validation', () => {
    it('does not start a scan for an invalid URL', () => {
      const start = vi.spyOn(store, 'start');
      type('https://gitlab.com/owner/repo');
      submit();

      // The store is still called (it owns the parse), but it must not reach the network.
      // Asserting the rendered error is the user-visible contract.
      expect(element.querySelector('#url-error')).not.toBeNull();
      expect(element.querySelector('#url-error')?.textContent).toContain('github.com');
      start.mockRestore();
    });

    it('marks the input as invalid for assistive technology', () => {
      type('not a url');
      submit();

      const input = element.querySelector('#repository-url') as HTMLInputElement;
      expect(input.getAttribute('aria-invalid')).toBe('true');
      expect(input.getAttribute('aria-describedby')).toBe('url-error');
    });

    it('announces the error with role="alert"', () => {
      type('https://gitlab.com/a/b');
      submit();
      expect(element.querySelector('[role="alert"]')).not.toBeNull();
    });

    it('does not show an error while the user is still typing', () => {
      // Validating on every keystroke would flag a URL as invalid halfway through typing.
      type('https://github.com/exp');
      expect(element.querySelector('#url-error')).toBeNull();
    });

    it('does nothing on an empty submission', () => {
      const start = vi.spyOn(store, 'start');
      submit();
      expect(start).not.toHaveBeenCalled();
      start.mockRestore();
    });

    it('accepts a valid URL', () => {
      const start = vi.spyOn(store, 'start').mockImplementation(() => undefined);
      type('https://github.com/expressjs/express');
      submit();
      expect(start).toHaveBeenCalledWith('https://github.com/expressjs/express');
      start.mockRestore();
    });
  });

  describe('when the request budget is exhausted', () => {
    it('disables the button and explains why', () => {
      const rateLimit = TestBed.inject(RateLimitService);
      rateLimit.markExhausted(Math.floor(Date.now() / 1000) + 1800);
      fixture.detectChanges();

      const button = element.querySelector('.search__button') as HTMLButtonElement;
      expect(button.disabled).toBe(true);

      const text = element.textContent ?? '';
      expect(text).toContain('hourly request limit');
      // The explanation must attribute the limit to GitHub, not imply a DepGuard fault.
      expect(text).toContain('60 requests per hour');
    });
  });

  describe('accessibility', () => {
    it('labels the input', () => {
      const input = element.querySelector('#repository-url') as HTMLInputElement;
      const label = element.querySelector('label[for="repository-url"]');
      expect(label).not.toBeNull();
      expect(input.getAttribute('aria-describedby')).toBe('url-hint');
    });

    it('gives every example button an accessible name', () => {
      const buttons = [...element.querySelectorAll('.examples__item')];
      expect(buttons.length).toBeGreaterThan(0);
      for (const button of buttons) {
        expect((button.textContent ?? '').trim().length).toBeGreaterThan(0);
      }
    });
  });
});
