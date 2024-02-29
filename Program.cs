using System;
using System.Management.Automation;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace AutoEnum
{
    class Program
    {
        static void Main(string[] args)
        {
            var commands = new Dictionary<string, string>
            {
                ["Enumerating Network and Mapped Shares"] = "net share; get-smbmapping",
                ["Listing Specific File Types in C:\\Users"] = "Get-ChildItem -Path C:\\Users -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.conf,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue",
                ["Listing Folders in C:\\Program Files, C:\\ProgramData, and C:\\Program Files (x86)"] = "Get-ChildItem -Path 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData' -Directory",
                ["Listing All Folders in C:\\"] = "Get-ChildItem -Path 'C:\\' -Directory",
                ["Enumerating Open Ports and Services"] = @"Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object LocalAddress, LocalPort, OwningProcess | ForEach-Object {
                    $processName = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName
                    ""$($_.LocalAddress):$($_.LocalPort) is being listened on by $processName""
                }",
                ["Checking Write Permissions for C:\\inetpub\\wwwroot"] = @"if (Test-Path 'C:\inetpub\wwwroot') {
                    $hasWriteAccess = $false
                    try {
                        [IO.File]::WriteAllText('C:\inetpub\wwwroot\test.txt', 'test')
                        Remove-Item 'C:\inetpub\wwwroot\test.txt'
                        $hasWriteAccess = $true
                    } catch {
                        $hasWriteAccess = $false
                    }
                    if ($hasWriteAccess) {
                        ""You have write access to C:\inetpub\wwwroot. Consider writing an ASPX shell to escalate privileges as IISSVC using SeImpersonate.""
                    } else {
                        ""You don't have write access to C:\inetpub\wwwroot.""
                    }
                } else {
                    ""C:\inetpub\wwwroot does not exist.""
                }",
                ["Checking Sticky Notes and PowerShell History"] = @"$stickyNotesPath = 'C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\*'; $stickyFiles = Get-ChildItem -Path $stickyNotesPath -File -ErrorAction SilentlyContinue; if ($stickyFiles) {
                    ""Found Sticky Notes. You should manually check these for sensitive info:""
                    $stickyFiles.FullName
                } else {
                    ""No Sticky Notes found.""
                };
                $psHistoryPath = 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'; $psHistoryFiles = Get-ChildItem -Path $psHistoryPath -File -ErrorAction SilentlyContinue; if ($psHistoryFiles) {
                    ""Found PowerShell history. You might want to sift through these for juicy details:""
                    $psHistoryFiles.FullName
                } else {
                    ""No PowerShell history found.""
                }",
                ["Listing Services by Searching for a Specific Binary Name"] = "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services /s /f \"Service.exe\" /t REG_EXPAND_SZ; reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CustomService",
                ["Checking for Unquoted Service Path"] = "Get-WmiObject -Class win32_service | Where-Object {$_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith(\"`\"\")) -and (-not $_.pathname.StartsWith(\"'\")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*' }",
                ["Enumerating Applocker / Constrained Language Mode"] = "$ExecutionContext.SessionState.LanguageMode",
                ["Searching for flag files on the machine"] = "Get-ChildItem -Path C:\\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue",
                ["IP Information"] = "ipconfig",
                ["Hostname"] = "hostname",

            };

            using (PowerShell powerShell = PowerShell.Create())
            {
                foreach (var command in commands)
                {
                    Console.WriteLine($"{command.Key}:\n");
                    powerShell.AddScript(command.Value);
                    Collection<PSObject> results = powerShell.Invoke();

                    if (results.Count > 0)
                    {
                        foreach (PSObject result in results)
                        {
                            Console.WriteLine(result.ToString());
                        }
                    }
                    else if (powerShell.Streams.Error.Count > 0)
                    {
                        Console.WriteLine("An error occurred.");
                        foreach (var error in powerShell.Streams.Error)
                        {
                            Console.WriteLine(error.ToString());
                        }
                    }
                    else
                    {
                        Console.WriteLine("No output or error.");
                    }

                    Console.WriteLine("--------------------------------------------------\n");

                    powerShell.Commands.Clear(); // Clear previous commands
                    powerShell.Streams.Error.Clear(); // Clear error stream for the next iteration
                }
            }
        }
    }
}
