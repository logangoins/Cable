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
                "\tldap [Options]            - Enumerate LDAP\n" +
                "\tdclist                    - List Domain Controllers in the current Domain\n" +
                "\trbcd [Options]            - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute\n" +
                "\tdacl [Options]            - Read or write Access Control Entries (ACE)s on an object\n" +
                "\ttrusts                    - Enumerate Active Directory Domain and Forest Trusts\n" +
                "\tca                        - Enumerate any active Active Directory Certifcate Services (ADCS) CA's\n" +
                "\ttemplates                 - Enumerate Active Directory Certificate Services (ADCS) Templates\n" +
                "\tuser [Options]            - Preform general operations on user accounts\n" +
                "\tcomputer [Options]        - Add and remove computer accounts from the domain\n" +
                "\tgroup [Options]           - Enumerate group membership, add, and remove users from groups\n\n" +

                "Module Options\n" +
                "ldap:\n" +
                "\t/users                    - Enumerate user objects\n" +
                "\t/computers                - Enumerate computer objects\n" +
                "\t/groups                   - Enumerate group objects\n" +
                "\t/spns                     - Enumerate objects with servicePrincipalName set\n" +
                "\t/asrep                    - Enumerate accounts that do not require Kerberos pre-authentication\n" +
                "\t/admins                   - Enumerate accounts with adminCount set to 1\n" +
                "\t/constrained              - Enumerate accounts with msDs-AllowedToDelegateTo set\n" +
                "\t/unconstrained            - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set\n" +
                "\t/rbcd                     - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set\n" +
                "\t/query:<query>            - Enumerate objects with a custom query\n" +
                "\t/filter:\"<attr, attr>\"    - Enumerate objects for specific attributes\n\n" +

                "rbcd:\n" +
                "\t/write                    - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity\n" +
                "\t/delegate-to:<account>    - Target account to delegate access to\n" +
                "\t/delegate-from:<account>  - Controlled account to delegate from\n" +
                "\t/flush:<account>          - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account\n\n" +
                
                "dacl:\n" +
                "\t/find                     - Find potentially vulnerable ACEs\n" +
                "\t/object:<object>          - Object to perform DACL operations on\n" +
                "\t/read                     - Operation to read the objects Access Control Entries (ACE)s\n" +
                "\t/write:<permission>       - Write a ACE on the selected object, built in permissions are: GenericAll,GenericWrite,User-Force-Reset-Password,Self-Membership\n" +
                "\t/guid:<guid>              - Specify custom GUID for permission or extended right to write on the object, alternative for \"--write\"\n" +
                "\t/account:<account>        - Display access an account has on the target object, or set access to this account on the target object. Example: CORP\\jdoe\n\n" +

                "user:\n" +
                "\t/setspn:<value>           - Write to an objects servicePrincipalName attribute\n" +
                "\t/removespn:<value>        - Remove a specified value off the servicePrincipalName attribute\n" +
                "\t/setasrep                 - Operation to set the DONT_REQ_PREAUTH flag on an objects userAccountControl attribute\n" +
                "\t/removeasrep              - Operation to remove the DONT_REQ_PREAUTH flag on an objects userAccountControl attribute\n" +
                "\t/user:<account>           - Specify user account to preform operations on\n" +
                "\t/password:<password>      - Change an accounts password\n" +
                "\t/getgroups                - Operation to enumerate a users current group membership\n\n" +

                "computer:\n" +
                "\t/add                      - Operation to add a computer account object\n" +
                "\t/remove                   - Operation to delete a computer account object\n" +
                "\t/name:<name>              - Computer name to add or remove\n" +
                "\t/password:<passwd>        - Computer account password\n\n" +

                "group:\n" +
                "\t/group:<group>            - The group used for an operation specified\n" +
                "\t/add:<account>            - Add a specified account to the group selected\n" +
                "\t/remove:<account>         - Remove a specified account from the group selected\n" +
                "\t/getusers                 - Operation to enumerate current users in a group\n";

            Console.WriteLine(help);

        }

        static List<string> sMods = new List<string> 
        { 
            "ldap",
            "kerberoast",
            "dclist",
            "rbcd",
            "dacl",
            "trusts",
            "templates",
            "ca",
            "group",
            "user",
            "computer"
        };

        // Adapted from Certify https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Domain/ArgumentParser.cs#L8
        public static Dictionary<string, string> Parse(IEnumerable<string> args)
        {
            var arguments = new Dictionary<string, string>();
            try
            {
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        idx = argument.IndexOf('=');
                        if (idx > 0)
                        {
                            arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                        }
                        else
                        {
                            arguments[argument] = string.Empty;
                        }
                    }
                }

                return arguments;
            }
            catch
            {
                Console.WriteLine("[!] Error parsing arguments");
                return null;
            }
        }

        public static void Execute(string[] args)
        {

            if(args.Contains("/help") || args.Contains("/h") || args.Length == 0)
            {
                Help();
            }
            else if (sMods.Contains(args.First()))
            {
                try
                {
                    switch (args.First().ToLower())
                    {
                        case "ldap":
                            if (args.Length > 1)
                            {
                                string query = null;
                                string filter = null;
                                string type = null;
                                List<string> attributes = new List<string>() { "samaccountname", "objectsid", "distinguishedname" };
                                string[] enumOptions = { "/users", "/computers", "/groups", "/spns", "/asrep", "/admins", "/unconstrained", "/constrained", "/rbcd"};

                                Dictionary<string, string> enumcmd = Parse(args);
                                if(enumcmd == null)
                                {
                                    return;
                                }
                                bool valid = false;
                                enumcmd.TryGetValue("/query", out query);
                                enumcmd.TryGetValue("/filter", out filter);
                                if(filter != null)
                                {
                                    attributes = filter.Split(',').Select(a => a.Trim()).Select(a => a.ToLower()).ToList();
                                }
                                if (query != null)
                                {
                                    type = "query";
                                    valid = true;
                                    Enumerate.Enum(type, query, attributes);
                                }

                                foreach (string option in enumOptions)
                                {
                                    if (args.Contains(option))
                                    {
                                        valid = true;
                                        type = option;
                                        Enumerate.Enum(type, query, attributes);
                                    }
                                }

                                if (!valid)
                                {
                                    Console.WriteLine("[!] Please specify an action");
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "dclist":
                            Enumerate.Dclist();
                            break;
                        case "rbcd":
                            if (args.Length > 1)
                            {
                                string delegate_from = null;
                                string delegate_to = null;
                                string account = null;

                                Dictionary<string, string> rbcdcmd = Parse(args);
                                if (rbcdcmd == null)
                                {
                                    return;
                                }
                                rbcdcmd.TryGetValue("/delegate-from", out delegate_from);
                                rbcdcmd.TryGetValue("/delegate-to", out delegate_to);
                                rbcdcmd.TryGetValue("/flush", out account);

                                if (args.Contains("/write"))
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
                                else if (account != null)
                                {


                                    RBCD.FlushRBCD(account);

                                }
                                else
                                {
                                    Console.WriteLine("[!] Please specify an action");
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "dacl":
                            if (args.Length > 1)
                            {
                                string obj = null;
                                string daclwrite = null;
                                string daclaccount = null;
                                string guid = null;

                                Dictionary<string, string> daclcmd = Parse(args);
                                if (daclcmd == null)
                                {
                                    return;
                                }
                                daclcmd.TryGetValue("/object", out obj);
                                daclcmd.TryGetValue("/account", out daclaccount);
                                daclcmd.TryGetValue("/write", out daclwrite);
                                daclcmd.TryGetValue("/guid", out guid);


                                if (args.Contains("/find"))
                                {
                                    DACL.FindACEs();
                                }
                                else if (args.Contains("/read"))
                                {
                                    if (obj == null)
                                    {
                                        Console.WriteLine("[!] Please specify an object to conduct an operation on");
                                    }
                                    else
                                    {
                                        DACL.getAce(obj, daclaccount);
                                    }
                                }
                                else if (daclwrite != null || guid != null)
                                {
                                    if (obj == null || daclaccount == null)
                                    {
                                        Console.WriteLine("[!] Please specify both an account to grant access from and an object to conduct an operation on");
                                    }
                                    else
                                    {
                                        if (!String.IsNullOrEmpty(daclwrite))
                                        {
                                            daclwrite = daclwrite.ToLower();
                                        }
                                        DACL.setAce(obj, daclaccount, daclwrite, guid);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[!] Please specify an action");
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
                        case "ca":
                            ADCS.caLookup();
                            break;
                        case "user":
                            if (args.Length > 1)
                            {
                                string user = null;
                                string aspn = null;
                                string rspn = null;
                                string password = null;

                                Dictionary<string, string> usercmd = Parse(args);
                                if (usercmd == null)
                                {
                                    return;
                                }
                                usercmd.TryGetValue("/setspn", out aspn);
                                usercmd.TryGetValue("/removespn", out rspn);
                                usercmd.TryGetValue("/user", out user);
                                usercmd.TryGetValue("/password", out password);

                                if (aspn != null || rspn != null)
                                {
                                    if (user == null)
                                    {
                                        Console.WriteLine("[!] Please supply a value for the SPN and user account");
                                        return;
                                    }
                                    if (aspn != null && rspn != null)
                                    {
                                        Console.WriteLine("[!] Cannot add and remove SPN at the same time");
                                        return;
                                    }
                                    if (aspn != null)
                                    {
                                        Users.setSPN(aspn, user);
                                    }
                                    else if (rspn != null)
                                    {
                                        Users.removeSPN(rspn, user);
                                    }
                                }
                                else if (password != null)
                                {
                                    if (user == null)
                                    {
                                        Console.WriteLine("[!] Please supply a value for the user and password");
                                        return;
                                    }
                                    Users.changePassword(user, password);
                                }
                                else if (args.Contains("/getgroups"))
                                {
                                    if (user == null)
                                    {
                                        Console.WriteLine("[!] Please supply a value for the user");
                                        return;
                                    }
                                    Users.getGroups(user);
                                }
                                else if (args.Contains("/setasrep"))
                                {
                                    if (user == null)
                                    {
                                        Console.WriteLine("[!] Please supply a value for the user");
                                        return;
                                    }
                                    Users.Asrep(user, "add");
                                }
                                else if (args.Contains("/removeasrep"))
                                {
                                    if (user == null)
                                    {
                                        Console.WriteLine("[!] Please supply a value for the user");
                                        return;
                                    }
                                    Users.Asrep(user, "remove");
                                }
                                else
                                {
                                    Console.WriteLine("[!] Please specify an action");
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "computer":
                            if (args.Length > 1)
                            {
                                string compname = null;
                                string compassword = null;

                                Dictionary<string, string> compcmd = Parse(args);
                                if (compcmd == null)
                                {
                                    return;
                                }

                                compcmd.TryGetValue("/name", out compname);
                                compcmd.TryGetValue("/password", out compassword);

                                if (args.Contains("/add"))
                                {
                                    if (compname == null || compassword == null)
                                    {
                                        Console.WriteLine("[!] Please specify a computer name and password");
                                    }
                                    else
                                    {
                                        Computer.AddComputer(compname, compassword);
                                    }
                                }
                                else if (args.Contains("/remove"))
                                {
                                    if (compname == null)
                                    {
                                        Console.WriteLine("[!] Please specify a computer name to remove");
                                    }
                                    else
                                    {
                                        Computer.RemoveComputer(compname);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[!] Please specify an action");
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "group":
                            if (args.Length > 1)
                            {
                                string group = null;
                                string add = null;
                                string remove = null;

                                Dictionary<string, string> groupcmd = Parse(args);
                                if (groupcmd == null)
                                {
                                    return;
                                }
                                groupcmd.TryGetValue("/group", out group);
                                groupcmd.TryGetValue("/add", out add);
                                groupcmd.TryGetValue("/remove", out remove);

                                if (add != null)
                                {
                                    if (group == null)
                                    {
                                        Console.WriteLine("[!] Please supply a group");
                                        return;
                                    }
                                    Groups.AddToGroup(add, group);
                                }
                                else if (remove != null)
                                {
                                    if (group == null)
                                    {
                                        Console.WriteLine("[!] Please supply a group");
                                        return;
                                    }
                                    Groups.RemoveFromGroup(remove, group);
                                }
                                else if (args.Contains("/getusers"))
                                {
                                    if (group == null)
                                    {
                                        Console.WriteLine("[!] Please supply a group");
                                        return;
                                    }
                                    Groups.GetGroupMembers(group);
                                }
                                else
                                {
                                    Console.WriteLine("[!] Please specify an action");
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        default:
                            Help();
                            break;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine("[!] Command invalid: use \"Cable.exe /h\" for more details");
                }
            }
            else
            {
                Console.WriteLine("[!] Please specify a module: use \"Cable.exe /h\" for more details");
            }
        }
    }
}
