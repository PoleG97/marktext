const { expect, test } = require('@playwright/test')
const { launchElectron } = require('./helpers')

test.describe('Test XSS Vulnerabilities', async () => {
  let app = null
  let page = null

  test.beforeAll(async () => {
    const { app: electronApp, page: firstPage } = await launchElectron(['test/e2e/data/xss.md'])
    app = electronApp
    page = firstPage

    // Wait to parse and render the document.
    await new Promise((resolve) => setTimeout(resolve, 3000))
  })

  test.afterAll(async () => {
    await app.close()
  })

  test('Load malicious document', async () => {
    const { isVisible, isCrashed } = await app.evaluate(async process => {
      const mainWindow = process.BrowserWindow.getAllWindows()[0]
      return {
        isVisible: mainWindow.isVisible(),
        isCrashed: mainWindow.webContents.isCrashed()
      }
    })

    expect(isVisible).toBeTruthy()
    expect(isCrashed).toBeFalsy()
  })

  test('Dangerous Node.js APIs should be blocked in renderer', async () => {
    // Verify that dangerous Node.js APIs are blocked by preload
    const nodeAccessTest = await page.evaluate(() => {
      let childProcessBlocked = false
      let fsBlocked = false
      
      // Try to require dangerous modules
      try {
        require('child_process')
      } catch (error) {
        childProcessBlocked = error.message.includes('Blocked')
      }
      
      try {
        require('fs')
      } catch (error) {
        fsBlocked = error.message.includes('Blocked')
      }
      
      return {
        // Check if require is available (it should be, but wrapped)
        hasRequire: typeof require !== 'undefined',
        // Check if process is available (limited version)
        hasProcess: typeof process !== 'undefined',
        // Check dangerous modules are blocked
        childProcessBlocked,
        fsBlocked,
        // Check process doesn't have dangerous methods
        hasProcessExit: typeof process?.exit === 'function',
        hasProcessKill: typeof process?.kill === 'function',
        // Check if our secure API is exposed
        hasMtApi: typeof window.mt !== 'undefined',
        hasOpenExternal: typeof window.mt?.openExternal === 'function'
      }
    })

    // Dangerous modules should be blocked
    expect(nodeAccessTest.childProcessBlocked).toBeTruthy()
    expect(nodeAccessTest.fsBlocked).toBeTruthy()
    
    // Dangerous process methods should not be available
    expect(nodeAccessTest.hasProcessExit).toBeFalsy()
    expect(nodeAccessTest.hasProcessKill).toBeFalsy()
    
    // Our secure API should be available
    expect(nodeAccessTest.hasMtApi).toBeTruthy()
    expect(nodeAccessTest.hasOpenExternal).toBeTruthy()
  })

  test('Dangerous URL protocols should be rejected', async () => {
    // Test that our secure API rejects dangerous URLs
    const urlTests = await page.evaluate(async () => {
      const results = {}
      
      // Test dangerous protocols
      const dangerousUrls = [
        'javascript:alert(1)',
        'vbscript:alert(1)',
        'data:text/html,<script>alert(1)</script>'
      ]
      
      for (const url of dangerousUrls) {
        try {
          await window.mt.openExternal(url)
          results[url] = 'allowed' // Should not reach here
        } catch (error) {
          results[url] = 'blocked'
        }
      }
      
      return results
    })

    // All dangerous URLs should be blocked
    Object.values(urlTests).forEach(result => {
      expect(result).toBe('blocked')
    })
  })
})
