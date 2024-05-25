using System;
using System.Management.Automation;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Text; 

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


                ["Checking for Unquoted Service Path"] = "gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike \"C:\\Windows*\" -and $_.PathName -notlike '\"*' -and $_.PathName -notlike ''} | select PathName,DisplayName,Name",


                ["Enumerating Applocker / Constrained Language Mode"] = "$ExecutionContext.SessionState.LanguageMode",


                ["Checking for folders with RWX permissions"] = "if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Get-ChildItem -Path C:\\ -Directory -Recurse | ForEach-Object {$path = $_.FullName; $acl = Get-Acl -Path $path; $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $hasRWX = $false; foreach ($access in $acl.Access) {if ($access.IdentityReference -eq $currentUser) {$rights = $access.FileSystemRights; $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read; $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write; $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile; if ($hasRead -and $hasWrite -and $hasExecute) {$hasRWX = $true; break;}}}; if ($hasRWX) {Write-Output $path;}} } else { Write-Output 'User has admin/system privileges, skipping RWX permissions check.' }",

                ["Searching for flag files on the machine"] = @"Get-ChildItem -Path C:\ -Include flag.txt,root.txt,local.txt,proof.txt,secret.txt -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                                                                    Write-Output $_.FullName
                                                                    Get-Content $_.FullName
                                                                    Write-Output ""------------------------------------------------""
                                                                    }",


                ["IP Information"] = "ipconfig",


                ["Hostname"] = "hostname",

            };


            List<Task> tasks = new List<Task>();

            foreach (var command in commands)
            {
                tasks.Add(Task.Run(() =>
                {
                    using (PowerShell powerShell = PowerShell.Create())
                    {
                        StringBuilder outputBuilder = new StringBuilder();
                        outputBuilder.AppendLine($"{command.Key}:\n");
                        powerShell.AddScript(command.Value);
                        Collection<PSObject> results = powerShell.Invoke();

                        if (results.Count > 0)
                        {
                            foreach (PSObject result in results)
                            {
                                outputBuilder.AppendLine(result.ToString());
                            }
                        }
                        else if (powerShell.Streams.Error.Count > 0)
                        {
                            outputBuilder.AppendLine("An error occurred.");
                            foreach (var error in powerShell.Streams.Error)
                            {
                                outputBuilder.AppendLine(error.ToString());
                            }
                        }
                        else
                        {
                            outputBuilder.AppendLine("No output or error.");
                        }
                        outputBuilder.AppendLine("--------------------------------------------------\n");

                        lock (Console.Out)
                        {
                            Console.Write(outputBuilder.ToString());
                        }
                    }
                }));
            }

            Task.WaitAll(tasks.ToArray()); 
        }
    }
}