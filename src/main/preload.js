/**
 * Secure Preload Script
 * 
 * This script runs in an isolated context (contextIsolation: true) and uses
 * contextBridge to expose a minimal, validated API to the renderer process.
 * 
 * Security measures:
 * - No direct Node.js API access from renderer
 * - URL validation to block dangerous protocols (javascript:, vbscript:, data:)
 * - Minimal API surface to reduce attack vectors
 */

const { contextBridge, ipcRenderer, shell } = require('electron')

// Dangerous URL protocols that should be blocked
const DANGEROUS_PROTOCOLS = [
  'javascript:',
  'vbscript:',
  'data:',
  'about:',
  'blob:'
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

  // Only allow http(s), file, and mailto protocols
  const safeProtocols = ['http://', 'https://', 'file://', 'mailto:']
  const hasSafeProtocol = safeProtocols.some(protocol => urlLower.startsWith(protocol))
  
  if (!hasSafeProtocol) {
    // If no protocol specified, check if it looks like a valid URL
    // This allows relative URLs or URLs without explicit protocol
    return !urlLower.includes(':') || urlLower.startsWith('/')
  }

  return true
}

// Expose secure API to renderer via window.mt
contextBridge.exposeInMainWorld('mt', {
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
  },

  /**
   * Send a message to the main process
   * @param {string} channel - The IPC channel
   * @param {any} data - The data to send
   */
  send: (channel, data) => {
    // Whitelist allowed IPC channels to prevent abuse
    const allowedChannels = [
      'mt::window-close',
      'mt::window-minimize',
      'mt::window-maximize',
      'mt::request-file-open',
      'mt::save-file',
      'mt::export-file'
    ]
    
    if (allowedChannels.includes(channel)) {
      ipcRenderer.send(channel, data)
    } else {
      console.warn('[Security] Blocked IPC send to non-whitelisted channel:', channel)
    }
  },

  /**
   * Receive a message from the main process
   * @param {string} channel - The IPC channel
   * @param {Function} func - The callback function
   */
  on: (channel, func) => {
    // Whitelist allowed IPC channels
    const allowedChannels = [
      'mt::file-loaded',
      'mt::file-saved',
      'mt::menu-action'
    ]
    
    if (allowedChannels.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => func(...args))
    } else {
      console.warn('[Security] Blocked IPC listener for non-whitelisted channel:', channel)
    }
  }
})

// Log that preload script has loaded successfully
console.log('[Preload] Secure preload script loaded with contextBridge')
