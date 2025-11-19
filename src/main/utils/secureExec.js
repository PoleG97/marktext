/**
 * Secure Process Execution Wrapper
 * 
 * This module provides a secure wrapper for executing external processes
 * with strict whitelisting and validation to prevent command injection attacks.
 * 
 * Security features:
 * - Whitelist-based command execution
 * - Uses execFile instead of exec to prevent shell injection
 * - Validates all arguments
 * - Rejects non-whitelisted commands
 */

const { execFile } = require('child_process')
const { promisify } = require('util')
const path = require('path')

const execFileAsync = promisify(execFile)

// Whitelist of allowed commands
// Only these commands can be executed through this wrapper
const ALLOWED_COMMANDS = [
  'pandoc',
  'git',
  'code', // VS Code
  'xdg-open', // Linux
  'open', // macOS
  'start' // Windows
]

/**
 * Validates if a command is in the whitelist
 * @param {string} command - The command to validate
 * @returns {boolean} - True if command is allowed
 */
function isCommandAllowed (command) {
  if (!command || typeof command !== 'string') {
    return false
  }

  const baseCommand = path.basename(command).toLowerCase()
  
  // Check if command (or its basename) is in whitelist
  return ALLOWED_COMMANDS.some(allowed => {
    return baseCommand === allowed || 
           baseCommand === `${allowed}.exe` ||
           baseCommand === `${allowed}.cmd`
  })
}

/**
 * Validates command arguments to prevent injection
 * @param {Array<string>} args - The arguments to validate
 * @returns {boolean} - True if arguments are safe
 */
function areArgumentsSafe (args) {
  if (!Array.isArray(args)) {
    return false
  }

  // Check for suspicious patterns in arguments
  const dangerousPatterns = [
    /[;&|`$()]/,  // Shell operators
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

/**
 * Safely executes a whitelisted command
 * @param {string} command - The command to execute
 * @param {Array<string>} args - The command arguments
 * @param {Object} options - Execution options
 * @returns {Promise<{stdout: string, stderr: string}>}
 * @throws {Error} If command is not whitelisted or arguments are unsafe
 */
async function execSafe (command, args = [], options = {}) {
  // Validate command is whitelisted
  if (!isCommandAllowed(command)) {
    const error = new Error(`Command not whitelisted: ${command}`)
    error.code = 'COMMAND_NOT_ALLOWED'
    throw error
  }

  // Validate arguments are safe
  if (!areArgumentsSafe(args)) {
    const error = new Error('Unsafe command arguments detected')
    error.code = 'UNSAFE_ARGUMENTS'
    throw error
  }

  // Set safe execution options
  const safeOptions = {
    ...options,
    shell: false, // Never use shell to prevent injection
    timeout: options.timeout || 30000, // 30 second default timeout
    maxBuffer: options.maxBuffer || 1024 * 1024 // 1MB default buffer
  }

  try {
    return await execFileAsync(command, args, safeOptions)
  } catch (error) {
    // Enhance error with security context
    error.command = command
    error.args = args
    throw error
  }
}

/**
 * Checks if a command exists in the system
 * @param {string} command - The command to check
 * @returns {Promise<boolean>}
 */
async function commandExists (command) {
  if (!isCommandAllowed(command)) {
    return false
  }

  try {
    const checkCommand = process.platform === 'win32' ? 'where' : 'which'
    await execFileAsync(checkCommand, [command], { timeout: 5000 })
    return true
  } catch {
    return false
  }
}

module.exports = {
  execSafe,
  commandExists,
  isCommandAllowed,
  ALLOWED_COMMANDS
}
