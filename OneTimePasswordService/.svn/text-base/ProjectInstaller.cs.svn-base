using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.ServiceProcess;


namespace OneTimePasswordService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        public ProjectInstaller()
        {
            //InitializeComponent();

            ServiceInstaller si = new ServiceInstaller();
            ServiceProcessInstaller spi = new ServiceProcessInstaller();

            si.ServiceName = "OneTimePasswordService"; // this must match the ServiceName specified in WindowsService1.
            si.DisplayName = ""; // this will be displayed in the Services Manager.
            this.Installers.Add(si);

            spi.Account = System.ServiceProcess.ServiceAccount.LocalSystem; // run under the system account.
            spi.Password = null;
            spi.Username = null;
            this.Installers.Add(spi);
        }
    }
}
