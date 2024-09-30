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
                Console.WriteLine("[!] Cannot find group");
                return;
            }

            PrincipalCollection gcollection = groupPrincipal.Members;

            Console.WriteLine("[+] Members in group: " + group + "\n");

            foreach (Principal member in gcollection)
            {
                Console.WriteLine("samAccountName: " + member.SamAccountName);
                Console.WriteLine("ObjectSid: " + member.Sid);
                Console.WriteLine("distinguishedName: " + member.DistinguishedName);
                Console.Write("\n");

            }
        }
    }
}
