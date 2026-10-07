using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace VaultSentry.Client.Services;

/// <summary>
/// Hardens the physical VQS DropZone directory with explicit execution denial ACLs.
/// </summary>
public static class VqsSecurityDescriptor
{
    public static void InitializeAndHardenDirectory(string directoryPath)
    {
        var dirInfo = new DirectoryInfo(directoryPath);
        if (!dirInfo.Exists)
        {
            dirInfo.Create();
        }

        try
        {
            DirectorySecurity security = dirInfo.GetAccessControl();

            // Disable inheritance and preserve existing rules as explicit rules
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);

            var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            // Explicitly DENY File Execution and Traverse rights to Everyone
            var denyExecuteRule = new FileSystemAccessRule(
                everyoneSid,
                FileSystemRights.ExecuteFile | FileSystemRights.Traverse,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Deny
            );

            // Allow standard Read, Write, and Delete so browsers can stage files
            var allowStagingRule = new FileSystemAccessRule(
                everyoneSid,
                FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.CreateFiles | 
                FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow
            );

            security.AddAccessRule(denyExecuteRule);
            security.AddAccessRule(allowStagingRule);

            dirInfo.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            // Fallback for non-elevated developer execution
            System.Diagnostics.Debug.WriteLine($"[VQS ACL Warning] Could not apply strict execute-deny DACL: {ex.Message}");
        }
    }
}