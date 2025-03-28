using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IdentityModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class Computer
    {
        // Adapted from https://github.com/FuzzySecurity/StandIn/blob/main/StandIn/StandIn/Program.cs#L1488
        // Can't use DirectoryEntry because pain
        public static void AddComputer(string name, string password)
        {
            Console.WriteLine("[+] Checking MachineAccountQuota");
            object maq = EnumMAQ();
            if (maq == null)
            {
                Console.WriteLine("[!] Could not retrieve MachineAccountQuota");
                return;
            }
            Console.WriteLine("[+] MachineAccountQuota: " + maq);
            if(Int32.Parse(maq.ToString()) <= 0)
            {
                Console.WriteLine("[!] MachineAccountQuota is 0, cannot create new computer account");
                return;
            }
            try
            {
                Domain domain = Domain.GetComputerDomain();
                string dc = domain.PdcRoleOwner.Name;
                string domainName = domain.Name;
                string dn = "CN=" + name + ",CN=Computers";

                foreach (String part in domainName.ToLower().Split('.'))
                {
                    dn += ",DC=" + part;
                }

                LdapDirectoryIdentifier ldapId = new LdapDirectoryIdentifier(dc, 389);
                LdapConnection connection = new LdapConnection(ldapId);

                connection.SessionOptions.Sealing = true; 
                connection.SessionOptions.Signing = true;
                connection.Bind();

                AddRequest req = new AddRequest();
                req.DistinguishedName = dn;
                req.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                req.Attributes.Add(new DirectoryAttribute("SamAccountName", name + "$"));
                req.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                req.Attributes.Add(new DirectoryAttribute("DnsHostName", name + "." + domainName));
                req.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", new String[] { "HOST/" + name + "." + domainName, "RestrictedKrbHost/" + name + "." + domainName, "HOST/" + name, "RestrictedKrbHost/" + name}));

                req.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes('"' + password + '"')));
                Console.WriteLine("[+] Adding computer object");
                connection.SendRequest(req);
                Console.WriteLine("[+] Successfully added computer account " + name + " with password " + password);
                

            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not add computer account");
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

        public static object EnumMAQ()
        {
            object maq = null;
            try
            {
                DirectoryEntry de = new DirectoryEntry();
                maq = de.Properties["ms-DS-MachineAccountQuota"].Value;
                return maq;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: " + ex.Message);
            }
            return maq;
        }
    }
}
