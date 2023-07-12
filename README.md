A PowerShell module with helpful cmdlets for managing devices on VMWare Workspace ONE.

To install, create a subdirectory under the $env:PSModulePath directory named WorkSpaceOne.PSHelper and copy the WorkSpaceOne.PsHelper.psm1 file into that directory. Then create a shortcut to open a WorkSpace ONE Powershell window with the command line:

powershell.exe -noExit -Command "& {Import-module WorkSpaceOne.PSHelper.psm1}"
