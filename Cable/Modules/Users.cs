using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class Users
    {
        public static void setSPN(string spn, string user)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + user + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find account");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    mde.Properties["serviceprincipalname"].Add(spn);
                    mde.CommitChanges();
                    Console.WriteLine("[+] SPN added to " + user);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to write servicePrincipalName attrbute: " + ex.Message);
            }
        }

        public static void removeSPN(string spn, string user)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + user + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find account");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    mde.Properties["serviceprincipalname"].Remove(spn);
                    mde.CommitChanges();
                    Console.WriteLine("[+] SPN removed from " + user);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to remove servicePrincipalName attrbute: " + ex.Message);
            }
        }

        public static void changePassword(string user, string password)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + user + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find account");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[+] Setting account password");
                    mde.Invoke("SetPassword", new object[] { password });
                    Console.WriteLine("[+] Password successfully set");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to change users password: " + ex.Message);
            }
        }
        public static void getGroups(string user)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
            UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(ctx, user);

            if (userPrincipal == null)
            {
                Console.WriteLine("[!] Cannot find user: " + user);
                return;
            }

            PrincipalSearchResult<Principal> gcollection = userPrincipal.GetAuthorizationGroups();

            if (gcollection.Count() == 0)
            {
                Console.WriteLine("[!] No groups found");
                return;
            }

            Console.WriteLine("[+] Membership of user: " + user);

            foreach (Principal group in gcollection)
            {
                Console.WriteLine("\t|__ samAccountName: " + group.SamAccountName);
            }
        }
    }
}
