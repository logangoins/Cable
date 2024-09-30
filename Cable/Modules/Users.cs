using System;
using System.Collections.Generic;
using System.DirectoryServices;
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
    }
}
