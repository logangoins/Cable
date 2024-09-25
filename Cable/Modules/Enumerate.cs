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
        public static void Enum(string type, string[] args)
        {
            SearchResultCollection results;

            Dictionary<string, string> queries = new Dictionary<string, string>();
            queries.Add("--users", "(&(ObjectCategory=person)(ObjectClass=user))");
            queries.Add("--computers", "(ObjectClass=computer)");
            queries.Add("--groups", "(ObjectCategory=group)");
            queries.Add("--gpos", "(ObjectClass=groupPolicyContainer)");
            queries.Add("--spns", "(&(serviceprincipalname=*)(!useraccountcontrol:1.2.840.113556.1.4.803:=2))");
            queries.Add("--asrep", "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))");
            queries.Add("--admins", "(&(admincount=1)(objectClass=user))");
            queries.Add("--unconstrained", "(userAccountControl:1.2.840.113556.1.4.803:=524288)");
            queries.Add("--constrained", "(msds-allowedtodelegateto=*)");
            queries.Add("--rbcd", "(msds-allowedtoactonbehalfofotheridentity=*)");

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);
            string query = "";
            if (type == "--filter")
            {
                query = args[2];
            }
            else
            {
                bool t = queries.TryGetValue(type, out query);
                if (!t)
                {
                    Console.WriteLine("[!] Command not recognized\n");
                    Program.Help();
                    System.Environment.Exit(1);
                }
            }
            ds.Filter = query;
            results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[!] No objects found");
                System.Environment.Exit(0);
            }

            foreach (SearchResult sr in results)
            {

                if (sr.Properties.Contains("samaccountname"))
                {
                    Console.WriteLine("\nsamAccountName: " + sr.Properties["samaccountname"][0].ToString());
                }
                if (sr.Properties.Contains("objectSid"))
                {
                    SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                    Console.WriteLine("objectSid: " + sid.Value);
                }
                if (sr.Properties.Contains("distinguishedname"))
                {
                    Console.WriteLine("distinguishedName: " + sr.Properties["distinguishedname"][0].ToString());
                }
                if (sr.Properties.Contains("serviceprincipalname"))
                {
                    Console.WriteLine("servicePrincipalName: " + sr.Properties["serviceprincipalname"][0].ToString());
                }
                if (sr.Properties.Contains("msds-allowedtodelegateto"))
                {
                    Console.WriteLine("msDs-AllowedToDelegateTo: " + sr.Properties["msds-allowedtodelegateto"][0].ToString());
                }
                if (sr.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                {
                    Console.Write("msDs-AllowedToActOnBehalfOfOtherIdentity: ");
                    RawSecurityDescriptor rsd = new RawSecurityDescriptor((byte[])sr.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0], 0);
                    foreach (CommonAce ace in rsd.DiscretionaryAcl)
                    {
                        Console.WriteLine(RBCD.sidToAccountLookup(ace.SecurityIdentifier.ToString()));
                    }

                }

            }

        }

        public static void Dclist()
        {
            Domain domain = Domain.GetCurrentDomain();
            DomainControllerCollection dcs = domain.FindAllDomainControllers();
            foreach (DomainController controller in dcs)
            {
                Console.WriteLine("\n" + controller.Name + "\n===================");
                Console.WriteLine("Forest: " + controller.Forest);
                Console.WriteLine("IP: " + controller.IPAddress);
                Console.WriteLine("Version: " + controller.OSVersion + "\n");
            }
        }

        public static void enumTrusts()
        {
            Forest forest = Forest.GetCurrentForest();
            TrustRelationshipInformationCollection trusts = forest.GetAllTrustRelationships();

            if (trusts.Count > 0)
            {

                foreach (TrustRelationshipInformation trust in trusts)
                {
                    Console.WriteLine("Source: " + trust.SourceName);
                    Console.WriteLine("Target: " + trust.TargetName);
                    Console.WriteLine("Direction: " + trust.TrustDirection);
                    Console.WriteLine("Trust Type: " + trust.TrustType);

                }
            }
            else
            {
                Console.WriteLine("[!] No Domain Trusts found");
            }

        }

    }
}
