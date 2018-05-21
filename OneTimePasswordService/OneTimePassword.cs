using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.DirectoryServices;

namespace OneTimePasswordService
{
    

    //Todo:
    // stop gracefully on the last remaining password
    // test timing attack (is the event coming in quick enough?)
    // whitelist IPs from where the one time password doesn't apply
    
    public partial class OneTimePassword : ServiceBase
    {
        private string username = "user";
        private string domain = "DOMAIN";

        private EventLog securityLog = null;
        private List<string> passwordList = new List<string>();

        public OneTimePassword()
        {
            InitializeComponent();
        }

        private string PopPassword()
        {
            string pass = passwordList[1]; //this way I get to see the current password in plaintext on top of file 
            passwordList.RemoveAt(0);
            Serialize();

            return pass;
            
        }

        private void Serialize()
        {
            try
            {
                File.Delete(@"c:\data\p.txt");
            }
            catch (Exception)
            {

            }

            StreamWriter writer;
            writer = File.CreateText(@"c:\data\p.txt");

            foreach(string pass in passwordList)
            {
                writer.WriteLine(pass);
            }
            
            writer.Close();
            
        }


        private void Deserialize()
        {
            StreamReader reader;
            try
            {

                reader = File.OpenText(@"c:\data\p.txt");
                string pass = reader.ReadLine();

                while (pass != null)
                {
                    passwordList.Add(pass);
                    pass = reader.ReadLine();
                }
                reader.Close();
            }
            catch (Exception)
            {
                //
            }

            if (passwordList.Count == 0)
            {
                Log("No password list found, generating new passwords", EventLogEntryType.Warning);
                GenerateRandomPasswords();
                Serialize();
            }
            else
            {
                Log("Existing password list found. " + passwordList.Count + " entries", EventLogEntryType.Information);
            }

            
        }

        private void GenerateRandomPasswords()
        {
            for (int i = 0; i < 1000; i++)
            {
                passwordList.Add(RandomPasswordGenerator.Generate(5));
            }
        }

        private void Log(string sEvent, EventLogEntryType type)
        {
            string sSource;
            string sLog;

            sSource = "OneTimePasswordService";
            sLog = "Application";

            if (!EventLog.SourceExists(sSource))
                EventLog.CreateEventSource(sSource, sLog);

            EventLog.WriteEntry(sSource, sEvent, type);
                
        }

        protected override void OnStart(string[] args)
        {

            Log("starting v0.0.1", EventLogEntryType.Information);

            Deserialize();

            EventLog[] logs = System.Diagnostics.EventLog.GetEventLogs();
            foreach (EventLog log in logs)
            {
                if (log.Log == "Security")
                {
                    securityLog = log;
                }
            }

            securityLog.EnableRaisingEvents = true;
            securityLog.EntryWritten += new EntryWrittenEventHandler(log_EntryWritten);

        }

        public static void ResetPassword(string computerName, string username, string newPassword) 
        { 
            DirectoryEntry directoryEntry = new DirectoryEntry(string.Format("WinNT://{0}/{1}", computerName, username)); 
            directoryEntry.Invoke("SetPassword", newPassword);
        }

        void log_EntryWritten(object sender, EntryWrittenEventArgs e)
        {
            //Log("security event: " + e.Entry.Message, EventLogEntryType.Information);
            EventLogEntry entry = e.Entry;

            if (entry.InstanceId == 4648)
            {
                if (entry.Message.Contains(username) && !entry.Message.Contains("127.0.0.1"))
                {
                    Match srcip = Regex.Match(entry.Message, "Network Address:.*");

                    string pattern = @"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";
                    Match ip = Regex.Match(srcip.ToString(), pattern);
                    if (ip.Success)
                    {
                        Log("outside login from: " + ip.ToString() , EventLogEntryType.Information);
                        
                        
                        string password = PopPassword();
                        ResetPassword(domain, username, password);
                        Log("poping password: " + password, EventLogEntryType.Information);
                    }

                }


            }


        }

        protected override void OnStop()
        {
            Log("stopping", EventLogEntryType.Information);
            securityLog.EnableRaisingEvents = false;
            Serialize();
        }
    }
}
