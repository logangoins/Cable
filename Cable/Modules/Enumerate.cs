using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class Enumerate
    {
        public static void Enum(string type, string query, List<string> attributes)
        {
            SearchResultCollection results;

            Dictionary<string, string> queries = new Dictionary<string, string>();
            queries.Add("--users", "(&(ObjectCategory=person)(ObjectClass=user))");
            queries.Add("--computers", "(ObjectClass=computer)");
            queries.Add("--groups", "(ObjectCategory=group)");
            queries.Add("--gpos", "(ObjectClass=groupPolicyContainer)");
            queries.Add("--ous", "(ObjectClass=organizationalUnit)");
            queries.Add("--spns", "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))");
            queries.Add("--asrep", "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))");
            queries.Add("--admins", "(&(admincount=1)(objectClass=user))");
            queries.Add("--unconstrained", "(userAccountControl:1.2.840.113556.1.4.803:=524288)");
            queries.Add("--constrained", "(msds-allowedtodelegateto=*)");
            queries.Add("--rbcd", "(msds-allowedtoactonbehalfofotheridentity=*)");

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);
            string q = "";
            if (type == "query")
            {
                q = query;
            }
            else
            {
                bool t = queries.TryGetValue(type, out q);
                if (!t)
                {
                    Console.WriteLine("[!] Command not recognized\n");
                    return;
                }
            }
            ds.Filter = q;
            results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[!] No objects found");
                return;
            }

            foreach (SearchResult sr in results)
            {
                Console.WriteLine("[+] Found object: " + sr.Properties["name"][0]);

                // Check if the type is --gpos and print the GPO specific attributes
                if (type == "--gpos")
                {
                    if (sr.Properties.Contains("displayName"))
                    {
                        Console.WriteLine("\t|__ GPO Name: " + sr.Properties["displayName"][0]);
                    }
                    if (sr.Properties.Contains("gPCFileSysPath"))
                    {
                        Console.WriteLine("\t|__ GPC File System Path: " + sr.Properties["gPCFileSysPath"][0]);
                    }
                }

                if (type == "--ous")
                {

                    if (sr.Properties.Contains("gplink"))
                    {
                        Console.WriteLine("\t|__ Linked GPOs:");
                        foreach (var link in sr.Properties["gplink"])
                        {
                            // Normally the gpLink looks like [LDAP://CN={GUID},CN=Policies,CN=System,DC=testlab,DC=local;0]
                            string[] DNsplit = link.ToString().Split(new[] { "[", "]" }, StringSplitOptions.RemoveEmptyEntries);

                            foreach (var gpoLink in DNsplit) // Process each gpLink
                            {
                                // Extract GUID from the DN
                                string GUID = gpoLink.Split(new[] { "{", "}" }, StringSplitOptions.RemoveEmptyEntries)[1];
                                //Console.WriteLine($"\t|    [DEBUG] Parsed GUID: {GUID}"); // DEBUG

                                // Construct LDAP query
                                string ldapQuery = $"(&(ObjectClass=groupPolicyContainer)(cn={{{GUID}}}))"; // Need to add extra { } for the query itself since I split using it
                                                                                                            // Console.WriteLine($"\t|    [DEBUG] LDAP Query: {ldapQuery}"); // DEBUG

                                // Perform LDAP query
                                DirectoryEntry gpoDe = new DirectoryEntry("LDAP://DC=testlab,DC=local");
                                DirectorySearcher gpoDs = new DirectorySearcher(gpoDe)
                                {
                                    Filter = ldapQuery,
                                    SearchScope = SearchScope.Subtree
                                };
                                gpoDs.PropertiesToLoad.Add("displayName");

                                SearchResultCollection gpoResults = gpoDs.FindAll();
                                if (gpoResults.Count > 0)
                                {
                                    foreach (SearchResult gpoResult in gpoResults)
                                    {
                                        if (gpoResult.Properties.Contains("displayName"))
                                        {
                                            Console.WriteLine($"\t|    |__ GPO Name: {gpoResult.Properties["displayName"][0]}");
                                        }
                                        else
                                        {
                                            Console.WriteLine("\t|    |__ GPO Name: Not Found");
                                        }
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"\t|    |__ No GPO found for GUID: {GUID}");
                                }

                                // Optional: Extract and print the GPO DN
                                string gpoLinkDN = gpoLink.Remove(gpoLink.Length - 2).Remove(0, 10); // Remove 'LDAP://cn=' and ';0'
                                Console.WriteLine($"\t|    |__ GPO DN: {gpoLinkDN}");
                            }
                        }
                    }
                }

                foreach (string attribute in attributes)
                {
                    if (sr.Properties.Contains(attribute))
                    {
                        if (attribute == "objectsid")
                        {
                            SecurityIdentifier sid = new SecurityIdentifier(sr.Properties[attribute][0] as byte[], 0);
                            Console.WriteLine("\t|__ objectSid:\n " + "\t|    |__ " + sid.Value);
                        }
                        else if (attribute == "msds-allowedtoactonbehalfofotheridentity")
                        {
                            Console.Write("\t|__ msds-allowedtoactonbehalfofotheridentity:\n ");
                            RawSecurityDescriptor rsd = new RawSecurityDescriptor((byte[])sr.Properties[attribute][0], 0);
                            foreach (CommonAce ace in rsd.DiscretionaryAcl)
                            {
                                Console.WriteLine("\t|    |__ " + RBCD.sidToAccountLookup(ace.SecurityIdentifier.ToString()));
                            }
                        }
                        else if (attribute == "useraccountcontrol")
                        {
                            Console.Write("\t|__ userAccountControl:\n ");
                            Console.WriteLine("\t|    |__ " + (hCable.USER_ACCOUNT_CONTROL)Convert.ToInt32(sr.Properties[attribute][0].ToString()));
                        }
                        else
                        {
                            Console.Write("\t|__ " + attribute + ":\n");
                            foreach (var value in sr.Properties[attribute])
                            {
                                Console.WriteLine("\t|    |__ " + value.ToString());
                            }
                        }
                    }
                }
                    Console.Write("\n");
                }

            }

        public static void Dclist()
        {
            Domain domain = Domain.GetCurrentDomain();
            DomainControllerCollection dcs = domain.FindAllDiscoverableDomainControllers();
            foreach (DomainController controller in dcs)
            {
                Console.WriteLine("[+] DC Found: " + controller.Name);
                Console.WriteLine("\t|__ Forest: " + controller.Forest);
                Console.WriteLine("\t|__ IP: " + controller.IPAddress);
                Console.WriteLine("\t|__ Version: " + controller.OSVersion + "\n");
            }
        }

        public static void enumTrusts()
        {
            Forest forest = Forest.GetCurrentForest();
            TrustRelationshipInformationCollection ftrusts = forest.GetAllTrustRelationships();

            Console.WriteLine("[+] Enumerating Forest trusts");
            if (ftrusts.Count > 0)
            {

                foreach (TrustRelationshipInformation trust in ftrusts)
                {
                    Console.WriteLine("[+] Found Trust: ");
                    Console.WriteLine("\t|__ Source: " + trust.SourceName);
                    Console.WriteLine("\t|__ Target: " + trust.TargetName);
                    Console.WriteLine("\t|__ Direction: " + trust.TrustDirection);
                    Console.WriteLine("\t|__ Trust Type: " + trust.TrustType + "\n");
                }
            }
            else
            {
                Console.WriteLine("[!] No Forest trusts found");
            }

            Domain domain = Domain.GetCurrentDomain();
            TrustRelationshipInformationCollection dtrusts = domain.GetAllTrustRelationships();

            Console.WriteLine("[+] Enumerating Domain trusts");
            if (dtrusts.Count > 0)
            {
                foreach (TrustRelationshipInformation trust in dtrusts)
                {
                    Console.WriteLine("[+] Found Trust: ");
                    Console.WriteLine("\t|__ Source: " + trust.SourceName);
                    Console.WriteLine("\t|__ Target: " + trust.TargetName);
                    Console.WriteLine("\t|__ Direction: " + trust.TrustDirection);
                    Console.WriteLine("\t|__ Trust Type: " + trust.TrustType + "\n");

                }
            }
            else
            {
                Console.WriteLine("[!] No Domain trusts found");
            }

        }

    }
}