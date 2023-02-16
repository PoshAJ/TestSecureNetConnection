@{

    RootModule        = "TestSecureNetConnection.psm1"

    ModuleVersion     = "1.0.0"

    # CompatiblePSEditions = @()

    GUID              = "98ee8673-0bf0-43f0-b3b5-23eed8323344"

    Author            = "Anthony J. Raymond"

    # CompanyName = ""

    Copyright         = "(c) 2022 Anthony J. Raymond"

    Description       = "Displays diagnostic information for a secure connection."

    # PowerShellVersion = ""

    # PowerShellHostName = ""

    # PowerShellHostVersion = ""

    # DotNetFrameworkVersion = ""

    # CLRVersion = ""

    # ProcessorArchitecture = ""

    # RequiredModules = @()

    # RequiredAssemblies = @()

    # ScriptsToProcess = @()

    # TypesToProcess = @()

    # FormatsToProcess = @()

    # NestedModules = @()

    FunctionsToExport = @(
        "Test-SecureNetConnection"
    )

    CmdletsToExport   = @()

    VariablesToExport = ""

    AliasesToExport   = @(
        "TSNC"
    )

    # DscResourcesToExport = @()

    # ModuleList = @()

    # FileList = @()

    PrivateData       = @{

        PSData = @{

            Tags         = @(
                "test"
                "secure"
                "connection"
                "tcp"
                "ssl"
                "tls"
            )

            LicenseUri   = "https://github.com/CodeAJGit/posh/blob/master/LICENSE"

            ProjectUri   = "https://github.com/CodeAJGit/posh"

            # IconUri = ""

            ReleaseNotes =
            @"
    20220518-AJR: 1.0.0 - Initial Release
"@

        }

    }

    # HelpInfoURI = ""

    # DefaultCommandPrefix = ""

}
