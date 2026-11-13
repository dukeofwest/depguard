// Locates a Chrome or Chromium binary for the browser-driven tools.
//
// These tools originally hardcoded a Windows install path, which worked on the machine
// they were written on and failed the moment one of them ran in CI on Linux. The lesson
// is the usual one: a path is environment, not a constant.
//
// Resolution order puts the explicit override first, so a runner or a developer can point
// at a specific build without editing any tool.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Candidate locations, in the order they are tried. */
function candidates() {
  const fromEnvironment = [
    // GitHub's runner images set CHROME_PATH; Puppeteer and Lighthouse use CHROME_BIN.
    process.env['CHROME_PATH'],
    process.env['CHROME_BIN'],
    process.env['GOOGLE_CHROME_BIN'],
  ].filter((value) => typeof value === 'string' && value.length > 0);

  const platform = os.platform();

  if (platform === 'win32') {
    const programFiles = process.env['ProgramFiles'] ?? 'C:/Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] ?? 'C:/Program Files (x86)';
    const localAppData = process.env['LOCALAPPDATA'] ?? '';
    return [
      ...fromEnvironment,
      path.join(programFiles, 'Google/Chrome/Application/chrome.exe'),
      path.join(programFilesX86, 'Google/Chrome/Application/chrome.exe'),
      ...(localAppData ? [path.join(localAppData, 'Google/Chrome/Application/chrome.exe')] : []),
      path.join(programFiles, 'Microsoft/Edge/Application/msedge.exe'),
      path.join(programFilesX86, 'Microsoft/Edge/Application/msedge.exe'),
    ];
  }

  if (platform === 'darwin') {
    return [
      ...fromEnvironment,
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    ];
  }

  // Linux, including the GitHub ubuntu-latest runner images.
  return [
    ...fromEnvironment,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/opt/google/chrome/chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium',
  ];
}

/**
 * Returns the path to a usable browser binary.
 *
 * Throws with the full search list rather than a bare ENOENT, because "spawn
 * C:/Program Files/... ENOENT" on a Linux runner is a confusing way to learn that a path
 * was hardcoded.
 */
export function findChrome() {
  const tried = candidates();
  for (const candidate of tried) {
    try {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    } catch {
      // An unreadable candidate is simply not a candidate.
    }
  }

  throw new Error(
    'No Chrome or Chromium binary was found. Set CHROME_PATH to one, or install Chrome.\n' +
      `Searched:\n${tried.map((candidate) => `  ${candidate}`).join('\n')}`,
  );
}

/** Flags shared by every tool, so behaviour is identical across them. */
export function chromeArguments(port, extra = []) {
  return [
    '--headless=new',
    '--remote-debugging-port=' + port,
    '--no-first-run',
    '--no-default-browser-check',
    // Required on CI runners, which run as root in a container without a user namespace.
    // Only ever applied to a throwaway profile loading our own local build.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    ...extra,
    'about:blank',
  ];
}
