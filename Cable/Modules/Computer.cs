using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class Computer
    {
        public static void AddComputer(string name, string password)
        {
            try
            {
                Domain domain = Domain.GetComputerDomain();
                String domainName = domain.Name;

                String dn = "LDAP://CN=Computers";
                foreach (String part in domainName.ToLower().Split('.'))
                {
                    dn += ",DC=" + part;
                }

                DirectoryEntry de = new DirectoryEntry(dn);
                Console.WriteLine("[+] Adding Computer object");
                DirectoryEntry deComp = de.Children.Add("CN=" + name, "computer");
                Console.WriteLine("[+] Adding default attributes");
                deComp.Properties["sAMAccountName"].Value = name.ToUpper() + "$";
                deComp.Properties["userAccountControl"].Value = 0x1020;
                deComp.Properties["DnsHostname"].Value = name + "." + domainName;
                deComp.Properties["servicePrincipalName"].Add("HOST/" + name);
                deComp.Properties["servicePrincipalName"].Add("HOST/" + name + "." + domainName);
                deComp.Properties["servicePrincipalName"].Add("RestrictedKrbHost/" + name);
                deComp.Properties["servicePrincipalName"].Add("RestrictedKrbHost/" + name + "." + domainName);
                deComp.CommitChanges();

                Console.WriteLine("[+] Setting Computer account password");
                deComp.Invoke("SetPassword", new object[] { password });
                Console.WriteLine("[+] Successfully added Computer account " + name + " with password " + password);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not add Computer account");
                Console.WriteLine("[!] Error: " + ex.Message);
            }
        }

        public static void RemoveComputer(string name)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                ds.Filter = "(samaccountname=" + name + "$)";
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find account");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    sr.GetDirectoryEntry().DeleteTree();
                    Console.WriteLine("[+] Successfully removed Computer account");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Cannot remove Computer account");
                Console.WriteLine("[!] Error: " + ex.Message);
            }
        }
    }
}
