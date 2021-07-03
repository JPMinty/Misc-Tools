# Windows Defender Application Control Audit Events

- Note 1: Special thanks to [Matt Graeber](https://twitter.com/mattifestation/status/1366435525272481799) for this.
- Note 2: The policy here (SIPolicy.p7b) is based off of a [Windows Defender Application Control system integrity policy](https://gist.github.com/mgraeber-rc/7b9f4d497d75967afc58209df611508b) which has been converted on an enterprise system and can be used if you don't have access to create your own.

If you don't want to use it you will need to create your own:

On an enterprise system enable WDAC by creating a module load audit policy: https://twitter.com/mattifestation/status/1366435525272481799

	ConvertFrom-CIPolicy Non_Microsoft_UserMode_Load_Audit.xml C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
	
Store the converted policy on a Win10 system to be monitored at: Windows\System32\CodeIntegrity\SIPolicy.p7b

More information:
- https://gist.githubusercontent.com/mattifestation/de140831d47e15370ba35c1877f39082/raw/8db18ab36723cc9eaf9770c2cadafe46460ff80e/3076EventExtractor.ps1
- https://posts.specterops.io/threat-detection-using-windows-defender-application-control-device-guard-in-audit-mode-602b48cd1c11
- https://github.com/mattifestation/WDACTools