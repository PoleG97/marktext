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

  test('Node.js access should be blocked in renderer', async () => {
    // Verify that Node.js APIs are not directly accessible from renderer
    const nodeAccessTest = await page.evaluate(() => {
      return {
        // Check if require is available (should be undefined with nodeIntegration: false)
        hasRequire: typeof require !== 'undefined',
        // Check if process is available with full Node.js APIs
        hasNodeProcess: typeof process !== 'undefined' && typeof process.versions?.node !== 'undefined',
        // Check if our secure API is exposed
        hasMtApi: typeof window.mt !== 'undefined',
        // Check if specific secure methods are available
        hasOpenExternal: typeof window.mt?.openExternal === 'function',
        hasGetAppVersion: typeof window.mt?.getAppVersion === 'function'
      }
    })

    // Node.js APIs should not be directly accessible
    expect(nodeAccessTest.hasRequire).toBeFalsy()
    expect(nodeAccessTest.hasNodeProcess).toBeFalsy()
    
    // Our secure API should be available
    expect(nodeAccessTest.hasMtApi).toBeTruthy()
    expect(nodeAccessTest.hasOpenExternal).toBeTruthy()
    expect(nodeAccessTest.hasGetAppVersion).toBeTruthy()
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
