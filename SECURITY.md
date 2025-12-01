# Security Policy

## Security Hardening (CVE-2023-2318 Mitigation)

This document describes the security hardening measures implemented to mitigate XSS to RCE vulnerabilities.

### Overview

MarkText has implemented comprehensive security measures to address CVE-2023-2318 and related XSS to RCE attack vectors. These changes significantly reduce the attack surface by preventing malicious code from executing arbitrary commands on the user's system.

### Security Measures Implemented

#### 1. Disabled Node Integration in Renderer (`nodeIntegration: false`)

**Critical Change**: The renderer process no longer has direct access to Node.js APIs.

- **Impact**: XSS vulnerabilities in the renderer cannot directly call `require('child_process')` or access filesystem APIs
- **Location**: `src/main/config.js`
- **Before**: `nodeIntegration: true` allowed full Node.js access from renderer
- **After**: `nodeIntegration: false` blocks all direct Node.js access

#### 2. Secure Preload Script with Controlled API Exposure

**New File**: `src/main/preload.js`

The preload script acts as a security gateway, providing controlled access to necessary functionality:

- **Module Whitelist**: Blocks dangerous modules (`child_process`, `fs`, `original-fs`)
- **URL Validation**: Validates and blocks dangerous URL protocols:
  - `javascript:` - Can execute arbitrary code
  - `vbscript:` - Can execute arbitrary code  
  - `data:` - Can contain embedded scripts
  - `about:` - Internal browser protocols
  - `blob:` - Can contain malicious content
- **Safe Process Exposure**: Exposes only informational `process` properties (platform, arch, versions) without dangerous methods (exit, kill, etc.)
- **Controlled require()**: Wraps `require()` to block dangerous modules while allowing safe ones

#### 3. Enhanced HTML Sanitization

**Modified File**: `src/renderer/util/dompurify.js`

Enhanced DOMPurify wrapper with additional protocol filtering:

- **Two-pass sanitization**:
  1. DOMPurify sanitization removes dangerous HTML/SVG
  2. Protocol filter removes dangerous `href`/`src` attributes
- **Dangerous Protocols Blocked**: javascript:, vbscript:, data:, about:
- **New Function**: `sanitizeHtml()` for convenient secure sanitization

#### 4. Secure Process Execution Wrapper

**New File**: `src/main/utils/secureExec.js`

Prevents command injection attacks in the main process:

- **Whitelist-based execution**: Only pre-approved commands can be executed
- **Uses `execFile` not `exec`**: Prevents shell injection
- **Argument validation**: Checks for suspicious patterns (shell operators, directory traversal)
- **Timeout protection**: Prevents runaway processes

**Allowed Commands**:
- `pandoc` - Document conversion
- `git` - Version control
- `code` - VS Code integration
- `xdg-open` / `open` / `start` - Opening files with default applications

#### 5. Enabled Web Security

**Changed**: `webSecurity: true` (was `false`)

- Enforces same-origin policy
- Enables CORS checks
- Validates SSL certificates
- Prevents loading of mixed content

### Testing

#### E2E Security Tests

**Modified File**: `test/e2e/xss.spec.js`

New tests verify security hardening:

1. **Dangerous Module Blocking**: Verifies `child_process` and `fs` cannot be required
2. **Dangerous Process Methods**: Confirms `process.exit()` and `process.kill()` are unavailable
3. **URL Protocol Validation**: Ensures dangerous URL protocols are rejected
4. **Secure API Exposure**: Confirms `window.mt` API is available

#### Running Tests

```bash
# Build the application
yarn run pack

# Run E2E tests
yarn run e2e
```

### Migration Notes for Developers

If you're working on MarkText, be aware of these security constraints:

#### What Changed

1. **Cannot use `require()` for dangerous modules**
   ```javascript
   // ❌ This will throw an error
   const { exec } = require('child_process')
   
   // ✅ Use IPC to request main process to do this
   ipcRenderer.send('request-command-execution', { command: 'pandoc', args: [...] })
   ```

2. **Cannot use dangerous URL protocols**
   ```javascript
   // ❌ This will be blocked
   shell.openExternal('javascript:alert(1)')
   
   // ✅ Use safe protocols
   shell.openExternal('https://example.com')
   ```

3. **Process object is limited**
   ```javascript
   // ✅ These work (read-only info)
   process.platform
   process.versions
   process.resourcesPath
   
   // ❌ These are not available (dangerous)
   process.exit()
   process.kill()
   process.chdir()
   ```

#### How to Request Secure Command Execution

Use the secure execution wrapper in the main process:

```javascript
// In main process
const { execSafe } = require('./utils/secureExec')

try {
  const { stdout } = await execSafe('pandoc', ['--version'])
  console.log(stdout)
} catch (error) {
  if (error.code === 'COMMAND_NOT_ALLOWED') {
    // Command not in whitelist
  }
}
```

### Future Improvements

#### Planned Security Enhancements

1. **Enable Context Isolation** (`contextIsolation: true`)
   - Requires refactoring `@electron/remote` usage throughout the application
   - Would provide stronger isolation between preload and renderer contexts
   - Prevents any form of prototype pollution attacks

2. **Content Security Policy (CSP)**
   - Define strict CSP headers for renderer content
   - Further restrict inline scripts and external resources

3. **Dependency Updates**
   - Regular updates of Electron and security-critical dependencies
   - Automated vulnerability scanning with `npm audit` and CodeQL

4. **Sandboxing**
   - Enable Electron's sandbox mode for additional OS-level isolation
   - Requires IPC-based architecture for all Node.js functionality

### Reporting Security Issues

If you discover a security vulnerability in MarkText, please report it via:

1. GitHub Security Advisories (preferred)
2. Email to security@marktext.org (if available)

Please do not open public issues for security vulnerabilities.

### Additional Resources

- [Electron Security Guidelines](https://www.electronjs.org/docs/latest/tutorial/security)
- [CVE-2023-2318 Details](https://nvd.nist.gov/vuln/detail/CVE-2023-2318)
- [DOMPurify Documentation](https://github.com/cure53/DOMPurify)

### Acknowledgments

This security hardening addresses vulnerabilities reported in:
- Issue #3618
- CVE-2023-2318
