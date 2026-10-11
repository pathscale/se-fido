# launchd user agent (template only)

`com.se-fido.device.plist.template` is not installed by any build step.

1. Finish DEPLOY.md (SIP/AMFI, codesign, manual `--run` works).
2. Copy the template to `~/Library/LaunchAgents/com.se-fido.device.plist`.
3. Replace:
   - `__SE_FIDO_DEVICE_BIN__`: absolute path to the signed `se-fido-device`
   - `__UV_POLICY__`: `none`, `presence` (default), or `biometry`
   - `__SE_FIDO_DIR__`: data directory (or omit the env entry to use the default)
   - `__LOG_DIR__`: directory for stdout/stderr logs
4. `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.se-fido.device.plist`

Do not commit a filled-in plist (machine-local paths).
