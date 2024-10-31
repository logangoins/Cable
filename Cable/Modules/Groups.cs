using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;

namespace Cable.Modules
{
    public class Groups
    {
        public static void GetGroupMembers(string group)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
            GroupPrincipal groupPrincipal = GroupPrincipal.FindByIdentity(ctx, group);
            UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, group);

            if (groupPrincipal == null)
            {
                Console.WriteLine("[!] Cannot find group: " + group);
                return;
            }

            PrincipalCollection gcollection = groupPrincipal.Members;

            if(gcollection.Count == 0)
            {
                Console.WriteLine("[!] No members found");
                return;
            }

            Console.WriteLine("[+] Members in group: " + group);

            foreach (Principal member in gcollection)
            {
                Console.WriteLine("\t|__ samAccountName: " + member.SamAccountName);
            }
        }

        public static void AddToGroup(string user, string group)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
            GroupPrincipal groupPrincipal = GroupPrincipal.FindByIdentity(ctx, group);

            if (groupPrincipal == null)
            {
                Console.WriteLine("[!] Cannot find group: " + group);
                return;
            }

            Console.WriteLine("[+] Adding user " + user + " to group " + group);

            try
            {
                groupPrincipal.Members.Add(ctx, IdentityType.SamAccountName, user);
                groupPrincipal.Save();

                Console.WriteLine("[+] Successfully added");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not add user to group: " + ex.Message);
            }

        }

        public static void RemoveFromGroup(string user, string group)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
            GroupPrincipal groupPrincipal = GroupPrincipal.FindByIdentity(ctx, group);

            if (groupPrincipal == null)
            {
                Console.WriteLine("[!] Cannot find group: " + group);
                return;
            }

            Console.WriteLine("[+] Removing user " + user + " from group " + group);

            try
            {
                groupPrincipal.Members.Remove(ctx, IdentityType.SamAccountName, user);
                groupPrincipal.Save();

                Console.WriteLine("[+] Successfully removed");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not remove user from group: " + ex.Message);
            }
        }

    }
}
