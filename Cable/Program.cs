using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Cable.Modules;

namespace Cable
{
    internal class Program
    {

        static void Help(string help)
        {
            string modhelptext =
                "Cable.exe [Module]\n" +
                "Modules:\n" +
                "\tenum [options] - Enumerate LDAP\n" +
                "\tkerberoast <account> - Kerberoast a potentially supplied account, or everything\n" +
                "\tdclist - List Domain Controllers in the current Domain\n" +
                "\trbcd [options] - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute\n" +
                "\ttrusts - Enumerate Active Directory Domain Trusts in the current Forest\n" +
                "\ttemplates - Enumerate Active Directory Certificate Services (ADCS) Templates";

            string enumhelptext =
                "Options:\n" +
                "\t--users - Enumerate user objects\n" +
                "\t--computers - Enumerate computer objects\n" +
                "\t--groups - Enumerate group objects\n" +
                "\t--gpos - Enumerate Group Policy objects\n" +
                "\t--spns - Enumerate objects with servicePrincipalName set\n" +
                "\t--dclist - Enumerate domain controller objects\n" +
                "\t--admins - Enumerate accounts with adminCount set to 1\n" +
                "\t--constrained - Enumerate accounts with msDs-AllowedToDelegateTo set\n" +
                "\t--unconstrained - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set\n" +
                "\t--rbcd - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set";

            string rbcdhelptext =
                "Options:\n" +
                "\t--write - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity\n" +
                "\t--delegate-to <account> - Target account to delegate access to\n" +
                "\t--delegate-from <account> - Controller account to delegate from\n" +
                "\t--flush <account> - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account";

            switch (help)
            {
                case "mod":
                    Console.WriteLine(modhelptext);
                    break;
                case "enum":
                    Console.WriteLine(enumhelptext);
                    break;
                case "rbcd":
                    Console.WriteLine(rbcdhelptext);
                    break;
            }

        }

        static void Enum(string type, string[] args)
        {
            SearchResultCollection results;

            Dictionary<string, string> queries = new Dictionary<string, string>();
            queries.Add("--users", "(&(ObjectCategory=person)(ObjectClass=user))");
            queries.Add("--computers", "(ObjectClass=computer)");
            queries.Add("--groups", "(ObjectCategory=group)");
            queries.Add("--gpos", "(ObjectClass=groupPolicyContainer)");
            queries.Add("--spns", "(&(serviceprincipalname=*)(!useraccountcontrol:1.2.840.113556.1.4.803:=2))");
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
                    Help("enum");
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

        static void dclist()
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

        static void enumTrusts()
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

        static void Main(string[] args)
        {

            try
            {
                if (args.Length > 0)
                {
                    if (args[0] == "kerberoast")
                    {
                        if (args.Length > 1)
                        {
                            string[] spn = { args[1] };
                            Kerberoast.Roast(spn);
                        }
                        else
                        {
                            string[] spns = Kerberoast.GetSPNs();
                            Kerberoast.Roast(spns);
                        }

                    }

                    else if (args[0] == "templates")
                    {
                        ADCS.templateLookup();
                    }

                    else if (args[0] == "rbcd")
                    {
                        string delegate_from = "";
                        string delegate_to = "";
                        string operation = "";
                        string account = "";

                        for (int i = 0; i < args.Length; i++)
                        {
                            switch (args[i])
                            {
                                case "--delegate-to":
                                    delegate_to = args[i + 1];
                                    break;
                                case "--delegate-from":
                                    delegate_from = args[i + 1];
                                    break;
                                case "--write":
                                    operation = "write";
                                    break;
                                case "--flush":
                                    operation = "flush";
                                    if (delegate_to == "" && delegate_from == "")
                                    {
                                        if (args.Length > 2)
                                        {
                                            account = args[i + 1];
                                        }
                                        else
                                        {
                                            Console.WriteLine("[!] Error: please supply an account to flush");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] Error: supplied delegate_from or delegate_to with --flush option");
                                        return;
                                    }
                                    break;
                            }
                        }
                                                
                        if (operation == "write")
                        {
                            if (delegate_from == "" || delegate_to == "" || operation == "")
                            {
                                Console.WriteLine("[!] You must specify all the parameters required for an RBCD write\n ");
                                Help("rbcd");
                            }
                            else
                            {
                                RBCD.WriteRBCD(delegate_to, delegate_from);
                            }
                        }
                        else if (operation == "flush"){
                            if (account == "" || operation == "")
                            {
                                Console.WriteLine("[!] You must specify all the parameters required for an RBCD flush\n ");
                                Help("rbcd");
                            }
                            else
                            {
                                RBCD.FlushRBCD(account);
                            }
                        }
                        else
                        {
                            Console.WriteLine("[!] Please specify all parameters");
                            Help("rbcd");
                        }
                        
                    }

                    else if (args[0] == "enum")
                    {
                        if (args.Length > 1)
                        {
                            Enum(args[1], args);
                        }
                        else
                        {
                            Console.WriteLine("Usage: Cable.exe enum [Options]");
                            Help("enum");
                        }
                    }

                    else if (args[0] == "dclist")
                    {
                        dclist();
                    }

                    else if (args[0] == "trusts")
                    {
                        enumTrusts();
                    }

                    else
                    {
                        Console.WriteLine("[!] Command not recognized\n");
                        Help("mod");
                    }
                }
                else
                {
                    Help("mod");
                }
            }


            catch (Exception e)
            {
                Console.WriteLine("[!] Exception: " + e.ToString());
            }

        }
    }
}
