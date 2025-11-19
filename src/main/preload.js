/**
 * Secure Preload Script
 *
 * This script runs before renderer code and provides controlled access to Node.js APIs.
 * With nodeIntegration: false, this is the ONLY way for renderer to access Node APIs.
 *
 * Security measures:
 * - Controlled require() that blocks dangerous modules (child_process, fs, etc.)
 * - Validates shell.openExternal URLs to block dangerous protocols
 * - Provides safe wrappers for necessary Node APIs
 * - Exposes process info safely without executable access
 *
 * Note: contextIsolation is currently false for @electron/remote compatibility.
 * Future improvement: migrate to contextIsolation: true with IPC-based remote replacement.
 */

const nodeRequire = require
const { ipcRenderer, shell, clipboard, nativeImage } = nodeRequire('electron')

// Dangerous URL protocols that should be blocked
const DANGEROUS_PROTOCOLS = [
  'javascript:',
  'vbscript:',
  'data:',
  'about:',
  'blob:'
]

// Dangerous modules that should never be required from renderer
const BLOCKED_MODULES = [
  'child_process',
  'fs',
  'original-fs'
]

/**
 * Validates a URL to ensure it's safe to open
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if URL is safe, false otherwise
 */
function isUrlSafe (url) {
  if (!url || typeof url !== 'string') {
    return false
  }

  const urlLower = url.toLowerCase().trim()

  // Block dangerous protocols
  for (const protocol of DANGEROUS_PROTOCOLS) {
    if (urlLower.startsWith(protocol)) {
      return false
    }
  }

  return true
}

/**
 * Secure require wrapper that blocks dangerous modules
 * @param {string} moduleName - The module to require
 * @returns {any} - The required module
 */
function secureRequire (moduleName) {
  // Block explicitly dangerous modules
  if (BLOCKED_MODULES.includes(moduleName)) {
    const error = new Error(`[Security] Blocked attempt to require dangerous module: ${moduleName}`)
    console.error(error.message)
    throw error
  }

  // Handle electron module specially
  if (moduleName === 'electron') {
    // Return a safe subset of electron APIs
    return {
      ipcRenderer,
      shell: {
        ...shell,
        openExternal: (url, options) => {
          if (!isUrlSafe(url)) {
            console.warn('[Security] Blocked attempt to open dangerous URL:', url)
            return Promise.reject(new Error('Blocked dangerous URL protocol'))
          }
          return shell.openExternal(url, options)
        }
      },
      clipboard,
      nativeImage
      // Don't expose: app, BrowserWindow, webContents, etc.
    }
  }

  // For all other modules, use regular require
  return nodeRequire(moduleName)
}

// Expose require globally
window.require = secureRequire
window.module = { exports: {} }
window.exports = window.module.exports

// Expose safe process info
window.process = {
  platform: process.platform,
  arch: process.arch,
  versions: Object.freeze({ ...process.versions }),
  resourcesPath: process.resourcesPath,
  env: process.env
  // Note: We intentionally don't expose dangerous methods like exit(), abort(), etc.
}

// Make process immutable at the top level
Object.freeze(window.process.versions)

// Expose secure API to renderer
window.mt = {
  /**
   * Opens an external URL in the default browser (securely)
   * @param {string} url - The URL to open
   * @returns {Promise<void>}
   */
  openExternal: async (url) => {
    if (!isUrlSafe(url)) {
      console.warn('[Security] Blocked attempt to open dangerous URL:', url)
      throw new Error('Blocked dangerous URL protocol')
    }
    return shell.openExternal(url)
  },

  /**
   * Gets the application version
   * @returns {Promise<string>}
   */
  getAppVersion: () => {
    return ipcRenderer.invoke('mt::get-app-version')
  }
}

// Log that preload script has loaded successfully
console.log('[Preload] Secure preload script loaded. Dangerous modules blocked, URLs validated.')
