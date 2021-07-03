# Extract relevant properties from 3076 events
# Modified by Jai Minton @CyberRaiju, based from original work by Matt Graeber @mattifestation 

# On an enterprise system enable it by creating a module load audit policy: https://twitter.com/mattifestation/status/1366435525272481799
    # ConvertFrom-CIPolicy Non_Microsoft_UserMode_Load_Audit.xml C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
# Store the converted policy on a Win10 system to be monitored at: Windows\System32\CodeIntegrity\SIPolicy.p7b

# More information:
# https://gist.githubusercontent.com/mattifestation/de140831d47e15370ba35c1877f39082/raw/8db18ab36723cc9eaf9770c2cadafe46460ff80e/3076EventExtractor.ps1
# https://posts.specterops.io/threat-detection-using-windows-defender-application-control-device-guard-in-audit-mode-602b48cd1c11

# Obtained from ntddk.h and the Microsoft-Windows-CodeIntegrity ETW manifest
$SigningLevelMapping = @{
    [Byte] 0 = 'Unchecked'
    [Byte] 1 = 'Unsigned'
    [Byte] 2 = 'Enterprise'
    [Byte] 3 = 'Custom1'
    [Byte] 4 = 'Authenticode'
    [Byte] 5 = 'Custom2'
    [Byte] 6 = 'Store'
    [Byte] 7 = 'Antimalware'
    [Byte] 8 = 'Microsoft'
    [Byte] 9 = 'Custom4'
    [Byte] 0xA = 'Custom5'
    [Byte] 0xB = 'DynamicCodegen'
    [Byte] 0xC = 'Windows'
    [Byte] 0xD = 'WindowsProtectedProcessLight'
    [Byte] 0xE = 'WindowsTcb'
    [Byte] 0xF = 'Custom6'
}

$CIEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3076} | ForEach-Object {
    $ScenarioValue = $_.Properties[16].Value.ToString()
    $Scenario = $ScenarioValue
        switch ($Scenario) {
        '0' { $Scenario = 'Kernel-Mode' }
        '1' { $Scenario = 'User-Mode' }
    }
    [PSCustomObject] @{
        TimeCreated = $_.TimeCreated
        MachineName = $_.MachineName
        UserId = $_.UserId
        FileName = $_.Properties[1].Value
        ProcessName = $_.Properties[3].Value
        CertificateSHA1AuthentiCodeHash = [BitConverter]::ToString($_.Properties[8].Value).Replace('-', '')
        CertificateSHA256AuthentiCodeHash = [BitConverter]::ToString($_.Properties[10].Value).Replace('-', '')
        ModuleSHA1Hash = [BitConverter]::ToString($_.Properties[12].Value).Replace('-', '')
        ModuleSHA256Hash = [BitConverter]::ToString($_.Properties[14].Value).Replace('-', '')
        OriginalFileName = $_.Properties[24].Value
        InternalName = $_.Properties[26].Value
        FileDescription = $_.Properties[28].Value
        ProductName = $_.Properties[30].Value
        FileVersion = $_.Properties[31].Value
        SISigningScenario = $Scenario
        RequestedSigningLevel = $SigningLevelMapping[$_.Properties[4].Value]
        ValidatedSigningLevel = $SigningLevelMapping[$_.Properties[5].Value]
        PolicyHash = [BitConverter]::ToString($_.Properties[22].Value).Replace('-', '')
    }
}
$CIEvents