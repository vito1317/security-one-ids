1. **Sanitize `escapeshellarg` in `app/Services/WafSyncService.php` commands.**
   - In `app/Services/WafSyncService.php` around lines 1551, 1556, 1562, 1625, and 1629, user input from `dscl` output is directly interpolated into `exec()` commands.
   - Example vulnerability:
     ```php
     exec("sudo dscl . -create /Users/{$consoleUser} AuthenticationAuthority ';DisabledUser;' 2>&1", $output, $returnCode);
     ```
   - Change them to properly use `escapeshellarg()`:
     ```php
     $safeUser = escapeshellarg($consoleUser);
     exec("sudo dscl . -create /Users/{$safeUser} AuthenticationAuthority ';DisabledUser;' 2>&1", $output, $returnCode);
     ```
   - Similar updates for `$user` inside the loop around lines 1625-1629.
   - This prevents OS command injection if a maliciously named user account exists on a macOS system.
2. **Sanitize `app/Services/DesktopLogCollector.php` commands.**
   - Investigate log show commands in `app/Services/DesktopLogCollector.php`.
   - Around line 585: `shell_exec("log show --predicate '{$predicate}' --last {$minutes}m --style json 2>/dev/null | head -c 500000");` where `$predicate` is internal, but `$minutes` should be cast to integer or validated.
   - Wait, `minutes` is usually passed as int. Let's check `escapeshellarg`.
3. **Execute Pre-Commit Steps.**
   - Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
