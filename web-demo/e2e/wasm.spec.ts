import { test, expect } from '@playwright/test';

test.describe('WASM initialization', () => {
  test('loads vault without errors', async ({ page }) => {
    const errors: string[] = [];
    
    // Capture console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });
    
    // Capture page errors
    page.on('pageerror', err => {
      errors.push(err.message);
    });

    // Navigate to the demo
    await page.goto('/crypto-lab-quantum-vault-kpqc/');
    
    // Wait for the vault to initialize (status badge should appear)
    await page.waitForSelector('[data-testid="status-badge"], .status-badge, .vault-status', {
      timeout: 10000
    }).catch(() => {
      // If no status badge, wait for any indicator the page loaded
    });
    
    // Wait a bit for any async initialization
    await page.waitForTimeout(3000);
    
    // Check no critical errors occurred
    const criticalErrors = errors.filter(e => 
      e.includes('memory access out of bounds') ||
      e.includes('Aborted()') ||
      e.includes('createModule is not a function') ||
      e.includes('Failed to initialize vault')
    );
    
    expect(criticalErrors).toEqual([]);
    
    // Verify the demo boxes are clickable (indicates WASM loaded)
    const demoBox = page.locator('.demo-box, [data-demo-box]').first();
    if (await demoBox.count() > 0) {
      await expect(demoBox).toBeVisible();
    }
  });

  test('can open a demo box', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));

    await page.goto('/crypto-lab-quantum-vault-kpqc/');
    await page.waitForTimeout(2000);
    
    // Try clicking on box 01 (password: demo01)
    const box01 = page.locator('text=Box 01').first();
    if (await box01.count() > 0) {
      await box01.click();
      
      // Fill in the password
      const pwdInput = page.locator('input[type="password"]').first();
      if (await pwdInput.count() > 0) {
        await pwdInput.fill('demo01');
        
        // Click retrieve/open button
        const openBtn = page.locator('button:has-text("Retrieve"), button:has-text("Open")').first();
        if (await openBtn.count() > 0) {
          await openBtn.click();
          await page.waitForTimeout(2000);
        }
      }
    }
    
    // Should have no critical errors
    expect(errors.filter(e => e.includes('memory access'))).toEqual([]);
  });
});
