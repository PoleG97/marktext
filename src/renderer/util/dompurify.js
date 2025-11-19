import runSanitize from 'muya/lib/utils/dompurify'

// Dangerous URL protocols that can lead to XSS or RCE
const DANGEROUS_PROTOCOLS = ['javascript:', 'vbscript:', 'data:', 'about:']

export const PREVIEW_DOMPURIFY_CONFIG = Object.freeze({
  FORBID_ATTR: ['style', 'contenteditable'],
  ALLOW_DATA_ATTR: false,
  USE_PROFILES: {
    html: true,
    svg: true,
    svgFilters: true,
    mathMl: false
  },
  RETURN_TRUSTED_TYPE: false
})

export const EXPORT_DOMPURIFY_CONFIG = Object.freeze({
  FORBID_ATTR: ['contenteditable'],
  ALLOW_DATA_ATTR: false,
  ADD_ATTR: ['data-align'],
  USE_PROFILES: {
    html: true,
    svg: true,
    svgFilters: true,
    mathMl: false
  },
  RETURN_TRUSTED_TYPE: false,
  // Allow "file" protocol to export images on Windows (#1997).
  ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp|file):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i // eslint-disable-line no-useless-escape
})

/**
 * Removes dangerous protocols from href and src attributes
 * @param {string} html - The HTML string to sanitize
 * @returns {string} - HTML with dangerous protocols removed
 */
function removeDangerousProtocols (html) {
  if (!html || typeof html !== 'string') {
    return html
  }

  // Create a temporary DOM element to parse HTML
  const tempDiv = document.createElement('div')
  tempDiv.innerHTML = html

  // Find all elements with href or src attributes
  const elementsWithUrls = tempDiv.querySelectorAll('[href], [src]')

  elementsWithUrls.forEach(element => {
    ['href', 'src'].forEach(attr => {
      const value = element.getAttribute(attr)
      if (value) {
        const lowerValue = value.toLowerCase().trim()
        // Check if URL starts with dangerous protocol
        const isDangerous = DANGEROUS_PROTOCOLS.some(protocol =>
          lowerValue.startsWith(protocol)
        )
        if (isDangerous) {
          // Remove the dangerous attribute
          element.removeAttribute(attr)
          console.warn(`[Security] Removed dangerous ${attr} attribute:`, value)
        }
      }
    })
  })

  return tempDiv.innerHTML
}

/**
 * Sanitizes HTML content using DOMPurify and removes dangerous protocols
 * @param {string} html - The HTML to sanitize
 * @param {Object} purifyOptions - DOMPurify configuration options
 * @returns {string} - Safe HTML string
 */
export const sanitize = (html, purifyOptions) => {
  // First pass: DOMPurify sanitization
  let sanitized = runSanitize(html, purifyOptions)

  // Second pass: Remove dangerous protocols from href/src attributes
  sanitized = removeDangerousProtocols(sanitized)

  return sanitized
}

/**
 * Enhanced HTML sanitization specifically for user content
 * Combines DOMPurify with additional protocol filtering
 * @param {string} html - The HTML to sanitize
 * @returns {string} - Safe HTML string
 */
export const sanitizeHtml = (html) => {
  return sanitize(html, PREVIEW_DOMPURIFY_CONFIG)
}
