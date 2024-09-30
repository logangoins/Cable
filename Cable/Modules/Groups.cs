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

            Console.WriteLine("[+] Members in group: " + group + "\n");

            foreach (Principal member in gcollection)
            {
                Console.WriteLine("samAccountName: " + member.SamAccountName);
                Console.WriteLine("ObjectSid: " + member.Sid);
                Console.WriteLine("distinguishedName: " + member.DistinguishedName);
                Console.Write("\n");

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

            groupPrincipal.Members.Add(ctx, IdentityType.SamAccountName, user);
            groupPrincipal.Save();

            Console.WriteLine("[+] Successfully added");

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

            groupPrincipal.Members.Remove(ctx, IdentityType.SamAccountName, user);
            groupPrincipal.Save();

            Console.WriteLine("[+] Successfully removed");
        }

    }
}
