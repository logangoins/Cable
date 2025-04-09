using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class DACL
    {
        // From https://github.com/FuzzySecurity/StandIn/blob/main/StandIn/StandIn/hStandIn.cs#L561
        public static String BuildFilterOctetString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.AppendFormat("\\{0}", bytes[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public static String schemaGuidLookup(Guid schemaGuid)
        {
            DirectoryEntry rootdse = new DirectoryEntry("LDAP://RootDSE");
            DirectoryEntry schema = new DirectoryEntry("LDAP://" + rootdse.Properties["schemaNamingContext"].Value.ToString());

            DirectorySearcher ds = new DirectorySearcher(schema);
            ds.SearchScope = System.DirectoryServices.SearchScope.OneLevel;
            ds.PropertiesToLoad.Add("ldapDisplayName");
            ds.Filter = $"(schemaIDGUID={BuildFilterOctetString(schemaGuid.ToByteArray())})";
            SearchResult sr = ds.FindOne();

            if (sr != null)
            {
                return sr.Properties["ldapDisplayName"][0].ToString();
            }
            else
            {
                return null;
            }
        }

        public static String rightsGuidLookup(Guid rightsGuid)
        {
            DirectoryEntry rootdse = new DirectoryEntry("LDAP://RootDSE");
            DirectoryEntry rights = new DirectoryEntry("LDAP://CN=Extended-Rights," + rootdse.Properties["configurationNamingContext"].Value.ToString());
            DirectorySearcher ds = new DirectorySearcher(rights);
            ds.SearchScope = System.DirectoryServices.SearchScope.OneLevel;
            ds.PropertiesToLoad.Add("cn");

            ds.Filter = $"(rightsGuid={rightsGuid.ToString("D")})";
            SearchResult sr = ds.FindOne();

            if (sr != null)
            {
                return sr.Properties["cn"][0].ToString();
            }
            else
            {
                return String.Empty;
            }

        }

        // Inspired by https://github.com/FuzzySecurity/StandIn/blob/main/StandIn/StandIn/Program.cs#L1713
        public static void getAce(string obj, string account)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + obj + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find object");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[+] Ownership for " + obj);
                    Console.WriteLine("\t|__ Owner: " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());
                    Console.WriteLine("\t|__ Group: " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());

                    AuthorizationRuleCollection arc = mde.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));
                    Console.WriteLine("[+] Access control entries: ");
                    foreach (ActiveDirectoryAccessRule ar in arc)
                    {
                        if (ar.IdentityReference.Value == account || String.IsNullOrEmpty(account))
                        {
                            Console.WriteLine("\t|__ Identity: " + ar.IdentityReference.Value);
                            Console.WriteLine("\t|    |__ Type: " + ar.AccessControlType.ToString());
                            Console.WriteLine("\t|    |__ Permission: " + ar.ActiveDirectoryRights.ToString());
                            if (ar.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000")
                            {
                                Console.WriteLine("\t|    |__ Object: ANY");
                            }
                            else
                            {
                                String rights = rightsGuidLookup(ar.ObjectType);
                                if (String.IsNullOrEmpty(rights))
                                {
                                    String schema = schemaGuidLookup(ar.ObjectType);
                                    if (String.IsNullOrEmpty(schema))
                                    {
                                        Console.WriteLine("\t|    |__ Object: " + ar.ObjectType.ToString());
                                    }
                                    else
                                    {
                                        Console.WriteLine("\t|    |__ Attribute: " + schema);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("\t|    |__ Object: " + rights);
                                }

                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to get access control entry for " + obj);
                Console.WriteLine("[!] Error: " + ex.Message);
            }
        }

        // Inspired by https://github.com/FuzzySecurity/StandIn/blob/main/StandIn/StandIn/Program.cs#L1811

        public static void setAce(string obj, string account, string permission, string guid)
        {
            try
            {
                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + obj + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find object");
                    return;
                }

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    IdentityReference ir = new NTAccount(account);

                    if (permission == "genericall")
                    {
                        ActiveDirectoryAccessRule adar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.GenericAll, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                        mde.ObjectSecurity.AddAccessRule(adar);
                    }
                    else if (permission == "genericwrite")
                    {
                        ActiveDirectoryAccessRule adar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.GenericWrite, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                        mde.ObjectSecurity.AddAccessRule(adar);
                    }
                    else if (permission == "resetpassword")
                    {
                        Guid rightGuid = new Guid("00299570-246d-11d0-a768-00aa006e0529");
                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                        mde.ObjectSecurity.AddAccessRule(ar);
                    }
                    else if (permission == "writemember")
                    {
                        Guid rightGuid = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                        mde.ObjectSecurity.AddAccessRule(ar);
                    }
                    else if (guid != null)
                    {
                        Guid rightGuid = new Guid(guid);
                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                        mde.ObjectSecurity.AddAccessRule(ar);
                    }
                    else
                    {
                        Console.WriteLine("[!] Please specify a valid permission or GUID");
                    }

                    mde.CommitChanges();
                    if (!String.IsNullOrEmpty(permission))
                    {
                        Console.WriteLine("[+] Successfully added " + permission + " onto " + obj);
                    }
                    else
                    {
                        Guid rightGuid = new Guid(guid);
                        string right = rightsGuidLookup(rightGuid);
                        Console.WriteLine("[+] Successfully added " + right + " onto " + obj);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to write access control entry for " + obj);
                Console.WriteLine("[!] Error: " + ex.Message);
            }

        }
        public static string GetDomainSID()
        {
            try
            {
                // Get the root domain entry
                DirectoryEntry domainEntry = new DirectoryEntry("LDAP://RootDSE");
                string domainDN = domainEntry.Properties["defaultNamingContext"].Value.ToString();

                // Get the domain object
                DirectoryEntry domainObject = new DirectoryEntry($"LDAP://{domainDN}");

                // Retrieve the objectSid property
                byte[] sidBytes = (byte[])domainObject.Properties["objectSid"].Value;
                SecurityIdentifier domainSid = new SecurityIdentifier(sidBytes, 0);

                return domainSid.Value;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving domain SID: {ex.Message}");
                return null;
            }
        }

        public static void FindACEs()
        {

            Domain domain = Domain.GetComputerDomain();
            String domainName = domain.Name;
            string domainSID = GetDomainSID();

            try
            {
                DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry());
                searcher.Filter = "(|(objectClass=user)(objectClass=group))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("objectSid");

                string pattern = domainSID + @"-[\d]{4,10}|" + RBCD.accountToSidLookup("Domain Users") + "|" + RBCD.accountToSidLookup("Domain Computers");

                foreach (SearchResult result in searcher.FindAll())
                {
                    string objectDN = result.Properties["distinguishedName"][0].ToString();
                    SecurityIdentifier objectSID = new SecurityIdentifier((byte[])result.Properties["objectSid"][0], 0);

                    DirectoryEntry computerEntry = result.GetDirectoryEntry();
                    ActiveDirectorySecurity security = computerEntry.ObjectSecurity;
                    AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));

                    foreach (ActiveDirectoryAccessRule rule in rules)
                    {
                        SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference;
                        if (System.Text.RegularExpressions.Regex.IsMatch(sid.Value, pattern))
                        {

                            Console.WriteLine("[+] Found Potentially Vulnerable ACE:");
                            Console.WriteLine($"\t|__ Target Object: {RBCD.sidToAccountLookup(objectSID.Value)}");
                            Console.WriteLine($"\t|__ Source Object: {RBCD.sidToAccountLookup(sid.Value)}");
                            Console.WriteLine($"\t|__ Active Directory Rights: {rule.ActiveDirectoryRights.ToString()}");
                            if (rule.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000")
                            {
                                Console.WriteLine("\t|   |__ Properties: ANY");
                            }
                            else
                            {
                                String rights = rightsGuidLookup(rule.ObjectType);
                                if (String.IsNullOrEmpty(rights))
                                {
                                    String schema = schemaGuidLookup(rule.ObjectType);
                                    if (String.IsNullOrEmpty(schema))
                                    {
                                        Console.WriteLine("\t|   |__ Schema: " + rule.ObjectType.ToString());
                                    }
                                    else
                                    {
                                        Console.WriteLine("\t|   |__ Attribute: " + schema);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("\t|   |__ ExtendedRights: " + rights);
                                }
                            }
                            Console.WriteLine($"\t|__ Object ACE Type: {rule.AccessControlType}");
                            
                            Console.Write("\n");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

    }
}
