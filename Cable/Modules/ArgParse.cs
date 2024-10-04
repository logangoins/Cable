using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;


namespace Cable.Modules
{

    public class ArgParse
    {

        public static void Help()
        {
            string help =
                "Cable.exe [Module]\n" +
                "Modules:\n" +
                "\tenum [Options]            - Enumerate LDAP\n" +
                "\tkerberoast <account>      - Kerberoast a potentially supplied account, or everything\n" +
                "\tdclist                    - List Domain Controllers in the current Domain\n" +
                "\trbcd [Options]            - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute\n" +
                "\ttrusts                    - Enumerate Active Directory Domain Trusts in the current Forest\n" +
                "\ttemplates                 - Enumerate Active Directory Certificate Services (ADCS) Templates\n" +
                "\tuser [Options]            - Preform general operations on user accounts\n" +
                "\tgroup [Options]           - Enumerate group membership, add, and remove users from groups\n\n" +

                "Module Options\n" +
                "enum:\n" +
                "\t--users                   - Enumerate user objects\n" +
                "\t--computers               - Enumerate computer objects\n" +
                "\t--groups                  - Enumerate group objects\n" +
                "\t--gpos                    - Enumerate Group Policy objects\n" +
                "\t--spns                    - Enumerate objects with servicePrincipalName set\n" +
                "\t--asrep                   - Enumerate accounts that do not require Kerberos pre-authentication\n" +
                "\t--admins                  - Enumerate accounts with adminCount set to 1\n" +
                "\t--constrained             - Enumerate accounts with msDs-AllowedToDelegateTo set\n" +
                "\t--unconstrained           - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set\n" +
                "\t--rbcd                    - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set\n" +
                "\t--query <query>           - Enumerate objects with a custom query\n\n" +

                "rbcd:\n" +
                "\t--write                   - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity\n" +
                "\t--delegate-to <account>   - Target account to delegate access to\n" +
                "\t--delegate-from <account> - Controlled account to delegate from\n" +
                "\t--flush <account>         - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account\n\n" +
                
                "user:\n" +
                "\t--spn <value>             - Write to an objects servicePrincipalName attribute\n" +
                "\t--user <account>          - Specify user account to preform operations on\n" +
                "\t--password <password>     - Change an accounts password\n\n" +

                "group:\n" +
                "\t--getmembership           - Operation to get Active Directory group membership\n" +
                "\t--group <group>           - The group used for an operation specified\n" +
                "\t--add <account>           - Add a specified account to the group selected\n" +
                "\t--remove <account>        - Remove a specified account from the group selected\n";

            Console.WriteLine(help);

        }

        static List<string> sMods = new List<string> 
        { 
            "enum",
            "kerberoast",
            "dclist",
            "rbcd",
            "trusts",
            "templates",
            "group",
            "user"
        };

        public static Dictionary<string, string> Parse(string[] args, string[] flags, string[] options)
        {
            Dictionary<string, string> cmd = new Dictionary<string, string>();

            foreach (string flag in flags)
            {
                if (args.Contains(flag))
                {
                    try
                    {
                        cmd.Add(flag, args[Array.IndexOf(args, flag) + 1]);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Please supply all the valid options, use \"Cable.exe -h\" for more information");
                        System.Environment.Exit(1);
                    }
                }
            }

            foreach (string option in options)
            {
                if (args.Contains(option))
                {
                    cmd.Add(option, "True");
                }
                else
                {
                    cmd.Add(option, "False");
                }
            }

            return cmd;
        }

        public static void Execute(string[] args)
        {
            if(args.Contains("--help") || args.Contains("-h") || args.Length == 0)
            {
                Help();
            }
            else if (sMods.Contains(args.First()))
            {
                try
                {
                    switch (args.First().ToLower())
                    {
                        case "enum":
                            if (args.Length > 1)
                            {
                                Enumerate.Enum(args[1], args);
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "kerberoast":
                            if (args.Length > 1)
                            {
                                string[] kspn = { args[1] };
                                Kerberoast.Roast(kspn);
                            }
                            else
                            {
                                string[] spns = Kerberoast.GetSPNs();
                                Kerberoast.Roast(spns);
                            }
                            break;
                        case "dclist":
                            Enumerate.Dclist();
                            break;
                        case "rbcd":
                            string delegate_from = null;
                            string delegate_to = null;
                            string account = null;
                            string write = null;

                            string[] flags = { "--delegate-from", "--delegate-to", "--flush" };
                            string[] options = { "--write" };

                            Dictionary<string, string> cmd = Parse(args, flags, options);
                            cmd.TryGetValue("--delegate-from", out delegate_from);
                            cmd.TryGetValue("--delegate-to", out delegate_to);
                            cmd.TryGetValue("--flush", out account);
                            cmd.TryGetValue("--write", out write);

                            if (write == "True")
                            {
                                if (delegate_from == null || delegate_to == null)
                                {
                                    Console.WriteLine("[!] You must specify all the parameters required for an RBCD write ");
                                }
                                else
                                {
                                    RBCD.WriteRBCD(delegate_to, delegate_from);
                                }
                            }
                            else if (write == "False")
                            {
                                if (account == null)
                                {
                                    Console.WriteLine("[!] You must specify all the parameters required for an RBCD flush");

                                }
                                else
                                {
                                    RBCD.FlushRBCD(account);
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "trusts":
                            Enumerate.enumTrusts();
                            break;
                        case "templates":
                            ADCS.templateLookup();
                            break;
                        case "user":
                            string useroperation = "";
                            string user = "";
                            string spn = "";
                            string password = "";
                            for (int i = 0; i < args.Length; i++)
                            {
                                switch (args[i])
                                {
                                    case "--spn":
                                        spn = args[i + 1];
                                        useroperation = "setspn";
                                        break;
                                    case "--user":
                                        user = args[i + 1];
                                        break;
                                    case "--password":
                                        password = args[i + 1];
                                        useroperation = "changepw";
                                        break;
                                }
                            }
                            if (useroperation == "setspn")
                            {
                                if(spn == "" || user == "")
                                {
                                    Console.WriteLine("[!] Please supply a value for the SPN and user account");
                                    return;
                                }
                                Users.setSPN(spn, user);
                            }
                            else if (useroperation == "changepw")
                            {
                                if(user == "" || password == "")
                                {
                                    Console.WriteLine("[!] Please supply a value for the user and password");
                                    return;
                                }
                                Users.changePassword(user, password);
                            }
                            break;
                        case "group":
                            string group = "";
                            string groupoperation = "";
                            string groupuser = "";
                            for (int i = 0; i < args.Length; i++)
                            {
                                switch (args[i])
                                {
                                    case "--getmembership":
                                        groupoperation = "getmem";
                                        break;
                                    case "--group":
                                        group = args[i + 1];
                                        break;
                                    case "--add":
                                        groupoperation = "add";
                                        groupuser = args[i + 1];
                                        break;
                                    case "--remove":
                                        groupoperation = "remove";
                                        groupuser = args[i + 1];
                                        break;
                                }
                            }
                            if(groupoperation == "add")
                            {
                                if (group == "")
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.AddToGroup(groupuser, group);
                            }
                            else if (groupoperation == "remove")
                            {
                                if (group == "")
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.RemoveFromGroup(groupuser, group);
                            }
                            else if (groupoperation == "getmem")
                            {
                                if(group == "")
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.GetGroupMembers(group);
                            }
                            break;

                        default:
                            Help();
                            break;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine("[!] Command invalid: use \"Cable.exe -h\" for more details");
                    
                }
            }
            else
            {
                Console.WriteLine("[!] Cannot find module");
            }
        }
    }
}
