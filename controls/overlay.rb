include_controls "redhat-enterprise-linux-8-stig-baseline" do

  # 1. Modify AIDE control to be a slow control and have a fast check (new input aide_check_fast)

  control "SV-251710" do
    title "The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions."
    desc "Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed.
          Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the
          system security policy and supporting the isolation of code and data on which the protection is based. Security functionality
          includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges),
          setting events to be audited, and setting intrusion detection parameters.
  
          This requirement applies to the RHEL 8 operating system performing security function verification/testing and/or systems and
          environments that require this functionality."
    desc "check", %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all
          security functions.
  
          Check that the AIDE package is installed with the following command:
            $ sudo rpm -q aide
  
            aide-0.16-14.el8_5.1.x86_64
  
          If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.
  
          If there is no application installed to perform integrity checks, this is a finding.
  
          If AIDE is installed, check if it has been initialized with the following command:
            $ sudo /usr/sbin/aide --check
  
          If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
    desc "fix", "Install AIDE, initialize it, and perform a manual check.
  
          Install AIDE:
            $ sudo yum install aide
  
          Initialize it:
            $ sudo /usr/sbin/aide --init
  
          Example output:
            Number of entries:      48623
  
            ---------------------------------------------------
            The attributes of the (uncompressed) database(s):
            ---------------------------------------------------
  
            /var/lib/aide/aide.db.new.gz
              SHA1     : LTAVQ8tFJthsrf4m9gfRpnf1vyc=
              SHA256   : NJ9+uzRQKSwmLQ8A6IpKNvYjVKGbhSjt
                BeJBVcmOVrI=
              SHA512   : 7d8I/F6A1b07E4ZuGeilZjefRgJJ/F20
                eC2xoag1OsOVpctt3Mi7Jjjf3vFW4xoY
                5mdS6/ImQpm0xtlTLOPeQQ==
  
            End timestamp: 2022-10-20 10:50:52 -0700 (run time: 0m 46s)
  
          The new database will need to be renamed to be read by AIDE:
            $ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  
          Perform a manual check:
            $ sudo /usr/sbin/aide --check
  
          Example output:
            Start timestamp: 2022-10-20 11:03:16 -0700 (AIDE 0.16)
            AIDE found differences between database and filesystem!!
            ...
  
          Done."
    impact 0.5
    tag check_id: "C-55147r880728_chk"
    tag severity: "medium"
    tag gid: "V-251710"
    tag rid: "SV-251710r880730_rule"
    tag stig_id: "RHEL-08-010359"
    tag gtitle: "SRG-OS-000445-GPOS-00199"
    tag fix_id: "F-55101r880729_fix"
    tag "documentable"
    tag cci: ["CCI-002696"]
    tag nist: ["SI-6 a"]
    tag "host"

    aide_check_fast = input("aide_check_fast", value: false) # Default to false if not specified

    only_if("This control takes a long time to execute so it has been disabled through 'slow_controls'") {
      !input("disable_slow_controls") && !aide_check_fast
    }

    file_integrity_tool = input("file_integrity_tool")

    only_if("Control not applicable within a container", impact: 0.0) do
      !virtualization.system.eql?("docker")
    end

    if file_integrity_tool == "aide"
      if aide_check_fast
        describe file("/var/lib/aide/aide.db.gz") do
          it { should exist }
        end
      else
        describe command("/usr/sbin/aide --check") do
          its("stdout") { should_not include "Couldn't open file" }
        end
      end
    end

    describe package(file_integrity_tool) do
      it { should be_installed }
    end
  end

  # 2. New input called container_host to check if system needs to be able to host containers

  control "SV-230548" do
    title "RHEL 8 must disable the use of user namespaces."
    desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf"
    desc "check", 'Verify RHEL 8 disables the use of user namespaces with the following commands:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable.

$ sudo sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: user.max_user_namespaces = 0

If "user.max_user_namespaces" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure RHEL 8 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable.

user.max_user_namespaces = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230548"
    tag rid: "SV-230548r858828_rule"
    tag stig_id: "RHEL-08-040284"
    tag fix_id: "F-33192r858827_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"

    only_if("This system is acting as a router on the network, this control is Not Applicable", impact: 0.0) {
      !input("network_router")
    }

    only_if("This system is acting as a container host, this control is Not Applicable", impact: 0.0) {
      !input("container_host")
    }

    # Define the kernel parameter to be checked
    parameter = "user.max_user_namespaces"
    action = "user namespaces"
    value = 0

    # Get the current value of the kernel parameter
    current_value = kernel_parameter(parameter)

    # Check if the system is a Docker container
    if virtualization.system.eql?("docker")
      impact 0.0
      describe "Control not applicable within a container" do
        skip "Control not applicable within a container"
      end
    else
      describe kernel_parameter(parameter) do
        it "is disabled in sysctl -a" do
          expect(current_value.value).to cmp value
          expect(current_value.value).not_to be_nil
        end
      end

      # Get the list of sysctl configuration files
      sysctl_config_files = input("sysctl_conf_files").map(&:strip).join(" ")

      # Search for the kernel parameter in the configuration files
      search_results = command("grep -r #{parameter} #{sysctl_config_files} {} \;").stdout.split("\n")

      # Parse the search results into a hash
      config_values = search_results.each_with_object({}) do |item, results|
        file, setting = item.split(":")
        results[file] ||= []
        results[file] << setting.split("=").last
      end

      uniq_config_values = config_values.values.flatten.map(&:strip).map(&:to_i).uniq

      # Check the configuration files
      describe "Configuration files" do
        if search_results.empty?
          it "do not explicitly set the `#{parameter}` parameter" do
            expect(config_values).not_to be_empty, "Add the line `#{parameter}=#{value}` to a file in the `/etc/sysctl.d/` directory"
          end
        else
          it "do not have conflicting settings for #{action}" do
            expect(uniq_config_values.count).to eq(1), "Expected one unique configuration, but got #{config_values}"
          end
          it "set the parameter to the right value for #{action}" do
            expect(config_values.values.flatten.all? { |v| v.to_i.eql?(value) }).to be true
          end
        end
      end
    end
  end

  # 3. (V1R14) Modify control to check for presence of "P" in slub debug parameter of grub 2 configuration (instead of equality)
  control "SV-230279" do
    title "RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks."
    desc "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Poisoning writes an arbitrary value to freed pages, so any modification or
reference to that page after being freed or before being initialized will be
detected and prevented. This prevents many types of use-after-free
vulnerabilities at little performance cost. Also prevents leak of data and
detection of corrupted memory.

    SLAB objects are blocks of physically-contiguous memory.  SLUB is the
unqueued SLAB allocator."
    desc "check", 'Verify that GRUB 2 is configured to enable poisoning of SLUB/SLAB objects to mitigate use-after-free vulnerabilities with the following commands:

Check that the current GRUB 2 configuration has poisoning of SLUB/SLAB objects enabled:

$ sudo grub2-editenv list | grep slub_debug

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 slub_debug=P page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If "slub_debug" does not contain "P" or is missing, this is a finding.

Check that poisoning of SLUB/SLAB objects is enabled by default to persist in kernel updates:

$ sudo grep slub_debug /etc/default/grub

GRUB_CMDLINE_LINUX="slub_debug=P"

If "slub_debug" does not contain "P" or is missing, this is a finding.'
    desc "fix", 'Configure RHEL 8 to enable poisoning of SLUB/SLAB objects with the
following commands:

    $ sudo grubby --update-kernel=ALL --args="slub_debug=P"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="slub_debug=P"'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000134-GPOS-00068"
    tag satisfies: ["SRG-OS-000134-GPOS-00068", "SRG-OS-000433-GPOS-00192"]
    tag gid: "V-230279"
    tag rid: "SV-230279r951598_rule"
    tag stig_id: "RHEL-08-010423"
    tag fix_id: "F-32923r567584_fix"
    tag cci: ["CCI-001084"]
    tag nist: ["SC-3"]
    tag "host"

    only_if("This control is Not Applicable to containers", impact: 0.0) {
      !virtualization.system.eql?("docker")
    }

    grub_stdout = command("grub2-editenv - list").stdout
    setting = /slub_debug\s*=\s*.*P.*/

    describe "GRUB config" do
      it "should enable page poisoning" do
        expect(parse_config(grub_stdout)["kernelopts"]).to match(setting), "Current GRUB configuration does not disable this setting"
        expect(parse_config_file("/etc/default/grub")["GRUB_CMDLINE_LINUX"]).to match(setting), "Setting not configured to persist between kernel updates"
      end
    end
  end

  # 4. (v1r14) rsyslog configuration checks changed to include all possible config files

  control "SV-230228" do
    title "All RHEL 8 remote access methods must be monitored."
    desc "Remote access services, such as those providing remote access to
network devices and information systems, which lack automated monitoring
capabilities, increase risk and make remote user access management difficult at
best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities of remote access capabilities, such as Remote
Desktop Protocol (RDP), on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets)."
    desc "check", %q(Verify that RHEL 8 monitors all remote access methods.

    Check that remote access methods are being logged by running the following
command:

    $ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

    auth.*;authpriv.*;daemon.* /var/log/secure

    If "auth.*", "authpriv.*" or "daemon.*" are not configured to be
logged, this is a finding.)
    desc "fix", 'Configure RHEL 8 to monitor all remote access methods by installing rsyslog
with the following command:

    $ sudo yum install rsyslog

    Then add or update the following lines to the "/etc/rsyslog.conf" file:

    auth.*;authpriv.*;daemon.* /var/log/secure

    The "rsyslog" service must be restarted for the changes to take effect.
To restart the "rsyslog" service, run the following command:

    $ sudo systemctl restart rsyslog.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000032-GPOS-00013"
    tag gid: "V-230228"
    tag rid: "SV-230228r951592_rule"
    tag stig_id: "RHEL-08-010070"
    tag fix_id: "F-32872r567431_fix"
    tag cci: ["CCI-000067"]
    tag nist: ["AC-17 (1)"]
    tag "host"
    tag "container-conditional"

    only_if("Control not applicable; remote access not configured within containerized RHEL", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?)
    }

    rsyslog = file("/etc/rsyslog.conf")

    describe rsyslog do
      it { should exist }
    end

    if rsyslog.exist?
      auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
      authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
      daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

      rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf')

      describe "Logged remote access methods" do
        it "should include auth.*" do
          expect(rsyslog_conf.stdout).to match(auth_pattern), "auth.* not configured for logging"
        end
        it "should include authpriv.*" do
          expect(rsyslog_conf.stdout).to match(authpriv_pattern), "authpriv.* not configured for logging"
        end
        it "should include daemon.*" do
          expect(rsyslog_conf.stdout).to match(daemon_pattern), "daemon.* not configured for logging"
        end
      end
    end
  end

  # 5. Modify SV-230484 to use chrony_conf resource instead of ntp_conf resource to assess chrony.conf file
  control "SV-230484" do
    title "RHEL 8 must securely compare internal information system clocks at
least every 24 hours with a server synchronized to an authoritative time
source, such as the United States Naval Observatory (USNO) time servers, or a
time server designated for the appropriate DoD network (NIPRNet/SIPRNet),
and/or the Global Positioning System (GPS)."
    desc 'Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints).

    If time stamps are not consistently applied and there is no common time
reference, it is difficult to perform forensic analysis.

    Time stamps generated by the operating system include date and time. Time
is commonly expressed in Coordinated Universal Time (UTC), a modern
continuation of Greenwich Mean Time (GMT), or local time with an offset from
UTC.

    RHEL 8 utilizes the "timedatectl" command to view the status of the
"systemd-timesyncd.service". The "timedatectl" status will display the
local time, UTC, and the offset from UTC.

    Note that USNO offers authenticated NTP service to DoD and U.S. Government
agencies operating on the NIPR and SIPR networks. Visit
https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.'
    desc "check", 'Verify RHEL 8 is securely comparing internal information system clocks at
least every 24 hours with an NTP server with the following commands:

    $ sudo grep maxpoll /etc/chrony.conf

    server 0.us.pool.ntp.mil iburst maxpoll 16

    If the "maxpoll" option is set to a number greater than 16 or the line is
commented out, this is a finding.

    Verify the "chrony.conf" file is configured to an authoritative DoD time
source by running the following command:

    $ sudo grep -i server /etc/chrony.conf
    server 0.us.pool.ntp.mil

    If the parameter "server" is not set or is not set to an authoritative
DoD time source, this is a finding.'
    desc "fix", "Configure the operating system to securely compare internal information
system clocks at least every 24 hours with an NTP server by adding/modifying
the following line in the /etc/chrony.conf file.

    server [ntp.server.name] iburst maxpoll 16"
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000355-GPOS-00143"
    tag satisfies: ["SRG-OS-000355-GPOS-00143", "SRG-OS-000356-GPOS-00144", "SRG-OS-000359-GPOS-00146"]
    tag gid: "V-230484"
    tag rid: "SV-230484r877038_rule"
    tag stig_id: "RHEL-08-030740"
    tag fix_id: "F-33128r568199_fix"
    tag cci: ["CCI-001891"]
    tag nist: ["AU-8 (1) (a)"]
    tag "host"

    only_if("This control is Not Applicable to containers", impact: 0.0) {
      !virtualization.system.eql?("docker")
    }

    time_sources = ntp_conf("/etc/chrony.conf").server

    # Cover case when a single server is defined and resource returns a string and not an array
    time_sources = [time_sources] if time_sources.is_a? String

    unless time_sources.nil?
      max_poll_values = time_sources.map { |val|
        val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
      }
    end

    # 6. Verify the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:

    describe ntp_conf("/etc/chrony.conf") do
      its("server") { should_not be_nil }
    end

    unless ntp_conf("/etc/chrony.conf").server.nil?
      if ntp_conf("/etc/chrony.conf").server.is_a? String
        describe ntp_conf("/etc/chrony.conf") do
          its("server") { should match input("authoritative_timeserver") }
        end
      end

      if ntp_conf("/etc/chrony.conf").server.is_a? Array
        describe ntp_conf("/etc/chrony.conf") do
          its("server.join") { should match input("authoritative_timeserver") }
        end
      end
    end
    # All time sources must contain valid maxpoll entries
    unless time_sources.nil?
      describe "chronyd maxpoll values (99=maxpoll absent)" do
        subject { max_poll_values }
        it { should all be < 17 }
      end
    end
  end

  # 6. (v1r14) custom resource sshd_active_config integration (applies to many controls)
  # SV-230225 SV-230244 SV-230288 SV-230290 SV-230291 SV-230296 SV-230330 SV-230380 SV-230382 SV-230385 SV-230527 SV-230555 SV-230556 SV-244245 SV-244528

  # 1/14
  control "SV-230225" do
    title "RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a ssh logon."
    desc %q(Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
    desc "check", 'Verify any publicly accessible connection to the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file being used with the following command:

$ sudo grep -ir banner /etc/ssh/sshd_config*

banner /etc/issue

This command will return the banner keyword and the name of the file that contains the ssh banner (in this case "/etc/issue").

If the line is commented out, this is a finding.
If conflicting results are returned, this is a finding.

View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.'
    desc "fix", 'Configure the operating system to display the Standard Mandatory DoD Notice
and Consent Banner before granting access to the system via the ssh.

    Edit the "/etc/ssh/sshd_config" file to uncomment the banner keyword and
configure it to point to a file that will contain the logon banner (this file
may be named differently or be in a different location if using a version of
SSH that is provided by a third-party vendor). An example configuration line is:

    banner /etc/issue

    Either create the file containing the banner or replace the text in the
file with the Standard Mandatory DoD Notice and Consent Banner. The
DoD-required text is:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."

    The SSH service must be restarted for changes to take effect.'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000023-GPOS-00006"
    tag satisfies: ["SRG-OS-000023-GPOS-00006", "SRG-OS-000228-GPOS-00088"]
    tag gid: "V-230225"
    tag rid: "SV-230225r858694_rule"
    tag stig_id: "RHEL-08-010040"
    tag fix_id: "F-32869r567422_fix"
    tag cci: ["CCI-000048"]
    tag nist: ["AC-8 a"]
    tag "host"
    tag "container-conditional"

    only_if("Control not applicable - SSH is not installed within containerized RHEL", impact: 0.0) {
      !virtualization.system.eql?("docker") || file("/etc/ssh/sshd_config").exist?
    }

    # When Banner is commented, not found, disabled, or the specified file does not exist, this is a finding.
    banner_file = sshd_active_config.banner

    # Banner property is commented out.
    if banner_file.nil?
      describe "The SSHD Banner is not set" do
        subject { banner_file.nil? }
        it { should be false }
      end
    end

    # Banner property is set to "none"
    if !banner_file.nil? && !banner_file.match(/none/i).nil?
      describe "The SSHD Banner is disabled" do
        subject { banner_file.match(/none/i).nil? }
        it { should be true }
      end
    end

    # Banner property provides a path to a file, however, it does not exist.
    if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
      describe "The SSHD Banner is set, but, the file does not exist" do
        subject { file(banner_file).exist? }
        it { should be true }
      end
    end

    # Banner property provides a path to a file and it exists.
    next unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?

    banner = file(banner_file).content.gsub(/[\r\n\s]/, "")
    expected_banner = input("banner_message_text_ral").gsub(/[\r\n\s]/, "")

    describe "The SSHD Banner" do
      it "is set to the standard banner and has the correct text" do
        expect(banner).to eq(expected_banner), "Banner does not match expected text"
      end
    end
  end

  # 2/14
  control "SV-230244" do
    title "RHEL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."
    desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

        Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

        RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.'
    desc "check", 'Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive.

        Check that the "ClientAliveCountMax" is set to "1" by performing the following command:

            $ sudo grep -ir clientalivecountmax /etc/ssh/sshd_config*

            ClientAliveCountMax 1

        If "ClientAliveCountMax" do not exist, is not set to a value of "1" in "/etc/ssh/sshd_config", or is commented out, this is a finding.

        If conflicting results are returned, this is a finding.'
    desc "fix", 'Note: This setting must be applied in conjunction with RHEL-08-010201 to function correctly.

        Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive.

        Modify or append the following lines in the "/etc/ssh/sshd_config" file:

            ClientAliveCountMax 1

        For the changes to take effect, the SSH daemon must be restarted:

            $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000163-GPOS-00072"
    tag satisfies: ["SRG-OS-000163-GPOS-00072", "SRG-OS-000126-GPOS-00066", "SRG-OS-000279-GPOS-00109"]
    tag gid: "V-230244"
    tag rid: "SV-230244r917867_rule"
    tag stig_id: "RHEL-08-010200"
    tag fix_id: "F-32888r917866_fix"
    tag cci: ["CCI-001133"]
    tag nist: ["SC-10"]
    tag "host"
    tag "container-conditional"

    only_if("SSH is not installed on the system this requirement is Not Applicable", impact: 0.0) {
      (service("sshd").enabled? || package("openssh-server").installed?)
    }

    client_alive_count = input("sshd_client_alive_count_max")

    if virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?
      impact 0.0
      describe "skip" do
        skip "SSH configuration does not apply inside containers. This control is Not Applicable."
      end
    else
      describe "SSH ClientAliveCountMax configuration" do
        it "should be set to #{client_alive_count}" do
          expect(sshd_active_config.ClientAliveCountMax).to(cmp(client_alive_count), "SSH ClientAliveCountMax is commented out or not set to the expected value (#{client_alive_count})")
        end
      end
    end
  end

  # 3/14
  control "SV-230288" do
    title "The RHEL 8 SSH daemon must perform strict mode checking of home
directory configuration files."
    desc "If other users have access to modify user-specific SSH configuration
files, they may be able to log on to the system as another user."
    desc "check", 'Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo grep -ir strictmodes /etc/ssh/sshd_config*

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure SSH to perform strict mode checking of home directory
configuration files. Uncomment the "StrictModes" keyword in
"/etc/ssh/sshd_config" and set the value to "yes":

    StrictModes yes

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230288"
    tag rid: "SV-230288r858701_rule"
    tag stig_id: "RHEL-08-010500"
    tag fix_id: "F-32932r567611_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers without SSH installed", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !directory("/etc/ssh").exist?)
    }

    describe sshd_active_config do
      its("StrictModes") { should cmp "yes" }
    end
  end

  # 4/14
  control "SV-230290" do
    title "The RHEL 8 SSH daemon must not allow authentication using known host’s
authentication."
    desc "Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere."
    desc "check", 'Verify the SSH daemon does not allow authentication using known host’s authentication with the following command:

$ sudo grep -ir IgnoreUserKnownHosts /etc/ssh/sshd_config*

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure the SSH daemon to not allow authentication using known host’s
authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "yes":

    IgnoreUserKnownHosts yes

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230290"
    tag rid: "SV-230290r858705_rule"
    tag stig_id: "RHEL-08-010520"
    tag fix_id: "F-32934r567617_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers without SSH installed", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !directory("/etc/ssh").exist?)
    }

    describe sshd_active_config do
      its("IgnoreUserKnownHosts") { should cmp "yes" }
    end
  end

  # 5/14
  control "SV-230291" do
    title "The RHEL 8 SSH daemon must not allow Kerberos authentication, except
to fulfill documented and validated mission requirements."
    desc "Configuring these settings for the SSH daemon provides additional
assurance that remote logon via SSH will not use unused methods of
authentication, even in the event of misconfiguration elsewhere."
    desc "check", 'Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo grep -ir KerberosAuthentication  /etc/ssh/sshd_config*

KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure the SSH daemon to not allow Kerberos authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "no":

    KerberosAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230291"
    tag rid: "SV-230291r858707_rule"
    tag stig_id: "RHEL-08-010521"
    tag fix_id: "F-32935r743956_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers without SSH installed", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !directory("/etc/ssh").exist?)
    }

    describe sshd_active_config do
      its("KerberosAuthentication") { should cmp "no" }
    end
  end

  # 6/14

  control "SV-230296" do
    title "RHEL 8 must not permit direct logons to the root account using remote
access via SSH."
    desc "Even though the communications channel may be encrypted, an additional
layer of security is gained by extending the policy of not logging on directly
as root. In addition, logging on with a user-specific account provides
individual accountability of actions performed on the system."
    desc "check", 'Verify remote access using SSH prevents users from logging on directly as "root".

Check that SSH prevents users from logging on directly as "root" with the following command:

$ sudo grep -ir PermitRootLogin /etc/ssh/sshd_config*

PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure RHEL 8 to stop users from logging on remotely as the "root"
user via SSH.

    Edit the appropriate "/etc/ssh/sshd_config" file to uncomment or add the
line for the "PermitRootLogin" keyword and set its value to "no":

    PermitRootLogin no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000109-GPOS-00056"
    tag gid: "V-230296"
    tag rid: "SV-230296r858711_rule"
    tag stig_id: "RHEL-08-010550"
    tag fix_id: "F-32940r567635_fix"
    tag cci: ["CCI-000770"]
    tag nist: ["IA-2 (5)"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers without SSH installed", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !directory("/etc/ssh").exist?)
    }

    describe sshd_active_config do
      its("PermitRootLogin") { should cmp input("permit_root_login") }
    end
  end

  # 7/14

  control "SV-230330" do
    title "RHEL 8 must not allow users to override SSH environment variables."
    desc "SSH environment options potentially allow users to bypass access
restriction in some configurations."
    desc "check", 'Verify that unattended or automatic logon via ssh is disabled with the following command:

$ sudo grep -ir PermitUserEnvironment /etc/ssh/sshd_config*

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure RHEL 8 to allow the SSH daemon to not allow unattended or
automatic logon to the system.

    Add or edit the following line in the "/etc/ssh/sshd_config" file:

    PermitUserEnvironment no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00229"
    tag gid: "V-230330"
    tag rid: "SV-230330r877377_rule"
    tag stig_id: "RHEL-08-010830"
    tag fix_id: "F-32974r567737_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This requirement is Not Applicable inside a container, the containers host manages the containers filesystems") {
      !(virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?)
    }

    describe sshd_active_config do
      its("PermitUserEnvironment") { should eq "no" }
    end
  end

  # 8/14

  control "SV-230380" do
    title "RHEL 8 must not allow accounts configured with blank or null
passwords."
    desc "If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments."
    desc "check", 'To verify that null passwords cannot be used, run the following command:

$ sudo grep -ir permitemptypasswords /etc/ssh/sshd_config*

PermitEmptyPasswords no

If "PermitEmptyPasswords" is set to "yes", this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Edit the following line in "etc/ssh/sshd_config" to prevent logons with
empty passwords.

    PermitEmptyPasswords no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.7
    tag severity: "high"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230380"
    tag rid: "SV-230380r858715_rule"
    tag stig_id: "RHEL-08-020330"
    tag fix_id: "F-33024r743992_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    if virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?
      impact 0.0
      describe "Control not applicable - SSH is not installed within containerized RHEL" do
        skip "Control not applicable - SSH is not installed within containerized RHEL"
      end
    else
      describe sshd_active_config do
        its("PermitEmptyPasswords") { should cmp "no" }
      end
    end
  end

  # 9/14

  control "SV-230382" do
    title "RHEL 8 must display the date and time of the last successful account
logon upon an SSH logon."
    desc "Providing users with feedback on when account accesses via SSH last
occurred facilitates user recognition and reporting of unauthorized account
use."
    desc "check", 'Verify SSH provides users with feedback on when account accesses last occurred with the following command:

$ sudo grep -ir printlastlog /etc/ssh/sshd_config*

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure SSH to provide users with feedback on when account accesses last
occurred by setting the required configuration options in "/etc/pam.d/sshd"
or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config"
will be used in the example) (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party
vendor).

    Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the
following:

    PrintLastLog yes

    The SSH service must be restarted for changes to "sshd_config" to take
effect.'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230382"
    tag rid: "SV-230382r858717_rule"
    tag stig_id: "RHEL-08-020350"
    tag fix_id: "F-33026r567893_fix"
    tag cci: ["CCI-000366", "CCI-000052"]
    tag nist: ["CM-6 b", "AC-9"]
    tag "host"
    tag "container-conditional"

    if virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?
      impact 0.0
      describe "Control not applicable - SSH is not installed within containerized RHEL" do
        skip "Control not applicable - SSH is not installed within containerized RHEL"
      end
    else
      describe sshd_active_config do
        its("PrintLastLog") { should cmp "yes" }
      end
    end
  end

  # 10/14

  control "SV-230527" do
    title "RHEL 8 must force a frequent session key renegotiation for SSH
connections to the server."
    desc "Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

    Session key regeneration limits the chances of a session key becoming
compromised."
    desc "check", 'Verify the SSH server is configured to force frequent session key renegotiation with the following command:

$ sudo grep -ir RekeyLimit /etc/ssh/sshd_config*

RekeyLimit 1G 1h

If "RekeyLimit" does not have a maximum data amount and maximum time defined, is missing or commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure the system to force a frequent session key renegotiation for SSH
connections to the server by add or modifying the following line in the
"/etc/ssh/sshd_config" file:

    RekeyLimit 1G 1h

    Restart the SSH daemon for the settings to take effect.

    $ sudo systemctl restart sshd.service'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000033-GPOS-00014"
    tag satisfies: ["SRG-OS-000033-GPOS-00014", "SRG-OS-000420-GPOS-00186", "SRG-OS-000424-GPOS-00188"]
    tag gid: "V-230527"
    tag rid: "SV-230527r877398_rule"
    tag stig_id: "RHEL-08-040161"
    tag fix_id: "F-33171r568328_fix"
    tag cci: ["CCI-000068"]
    tag nist: ["AC-17 (2)"]
    tag "host"

    only_if("This control is Not Applicable to containers without SSH enabled", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?)
    }

    describe sshd_active_config do
      its("RekeyLimit") { should cmp "1G 1h" }
    end
  end

  # 11/14

  control "SV-230555" do
    title "RHEL 8 remote X connections for interactive users must be disabled
unless to fulfill documented and validated mission requirements."
    desc %q(The security risk of using X11 forwarding is that the client's X11
display server may be exposed to attack when the SSH client requests
forwarding.  A system administrator may have a stance in which they want to
protect clients that may expose themselves to attack by unwittingly requesting
X11 forwarding, which can warrant a "no" setting.

    X11 forwarding should be enabled with caution. Users with the ability to
bypass file permissions on the remote host (for the user's X11 authorization
database) can access the local X11 display through the forwarded connection. An
attacker may then be able to perform activities such as keystroke monitoring if
the ForwardX11Trusted option is also enabled.

    If X11 services are not required for the system's intended function, they
should be disabled or restricted as appropriate to the system’s needs.)
    desc "check", 'Verify X11Forwarding is disabled with the following command:

$ sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"

X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the Information System Security Officer (ISSO) as an operational requirement or is missing, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the
"X11Forwarding" keyword and set its value to "no" (this file may be named
differently or be in a different location if using a version of SSH that is
provided by a third-party vendor):

    X11Forwarding no

    The SSH service must be restarted for changes to take effect:

    $ sudo systemctl restart sshd'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230555"
    tag rid: "SV-230555r858721_rule"
    tag stig_id: "RHEL-08-040340"
    tag fix_id: "F-33199r568412_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?)
    }

    describe sshd_active_config do
      its("X11Forwarding") { should cmp "no" }
    end
  end

  # 12/14

  control "SV-230556" do
    title "The RHEL 8 SSH daemon must prevent remote hosts from connecting to the
proxy display."
    desc "When X11 forwarding is enabled, there may be additional exposure to
the server and client displays if the sshd proxy display is configured to
listen on the wildcard address.  By default, sshd binds the forwarding server
to the loopback address and sets the hostname part of the DIPSLAY environment
variable to localhost.  This prevents remote hosts from connecting to the proxy
display."
    desc "check", 'Verify the SSH daemon prevents remote hosts from connecting to the proxy display.

Check the SSH X11UseLocalhost setting with the following command:

# sudo grep -ir x11uselocalhost /etc/ssh/sshd_config*
X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure the SSH daemon to prevent remote hosts from connecting to the
proxy display.

    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the
"X11UseLocalhost" keyword and set its value to "yes" (this file may be
named differently or be in a different location if using a version of SSH that
is provided by a third-party vendor):

    X11UseLocalhost yes'
    impact 0.5
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-230556"
    tag rid: "SV-230556r858723_rule"
    tag stig_id: "RHEL-08-040341"
    tag fix_id: "F-33200r568415_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    only_if("This control is Not Applicable to containers", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !file("/etc/ssh/sshd_config").exist?)
    }

    describe sshd_active_config do
      its("X11UseLocalhost") { should cmp "yes" }
    end
  end

  # 13/14

  control "SV-244525" do
    title "RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
    desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.'
    desc "check", 'Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes.

Check that the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

     $ sudo grep -ir clientaliveinterval /etc/ssh/sshd_config*

     ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config" or is commented out, this is a finding.

If conflicting results are returned, this is a finding.'
    desc "fix", 'Note: This setting must be applied in conjunction with RHEL-08-010200 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveInterval 600

For the changes to take effect, the SSH daemon must be restarted.

     $ sudo systemctl restart sshd.service'
    impact 0.0
    tag severity: "medium"
    tag gtitle: "SRG-OS-000163-GPOS-00072"
    tag satisfies: ["SRG-OS-000163-GPOS-00072", "SRG-OS-000126-GPOS-00066", "SRG-OS-000279-GPOS-00109"]
    tag gid: "V-244525"
    tag rid: "SV-244525r917886_rule"
    tag stig_id: "RHEL-08-010201"
    tag fix_id: "F-47757r917885_fix"
    tag cci: ["CCI-001133"]
    tag nist: ["SC-10"]
    tag "host"
    tag "container-conditional"

    setting = "ClientAliveInterval"
    gssapi_authentication = input("sshd_config_values")
    value = gssapi_authentication[setting]
    openssh_present = package("openssh-server").installed?

    only_if("This requirement is Not Applicable in the container without open-ssh installed", impact: 0.0) {
      !(virtualization.system.eql?("docker") && !openssh_present)
    }

    if input("allow_container_openssh_server") == false
      describe "In a container Environment" do
        it "the OpenSSH Server should be installed only when allowed in a container environment" do
          expect(openssh_present).to eq(false), "OpenSSH Server is installed but not approved for the container environment"
        end
      end
    else
      describe "The OpenSSH Server configuration" do
        it "has the correct #{setting} configuration" do
          expect(sshd_active_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Please ensure it set to '#{value}'."
        end
      end
    end
  end

  # 14/14

  control "SV-244528" do
    title "The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements."
    desc "Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere."
    desc "check", 'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.'
    desc "fix", 'Configure the SSH daemon to not allow GSSAPI authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "no":

    GSSAPIAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
    impact 0.0
    tag severity: "medium"
    tag gtitle: "SRG-OS-000480-GPOS-00227"
    tag gid: "V-244528"
    tag rid: "SV-244528r858709_rule"
    tag stig_id: "RHEL-08-010522"
    tag fix_id: "F-47760r743832_fix"
    tag cci: ["CCI-000366"]
    tag nist: ["CM-6 b"]
    tag "host"
    tag "container-conditional"

    setting = "GSSAPIAuthentication"
    gssapi_authentication = input("sshd_config_values")
    value = gssapi_authentication[setting]

    if virtualization.system.eql?("docker")
      describe "In a container Environment" do
        if package("openssh-server").installed?
          it "the OpenSSH Server should be installed when allowed in Docker environment" do
            expect(input("allow_container_openssh_server")).to eq(true), "OpenSSH Server is installed but not approved for the Docker environment"
          end
        else
          it "the OpenSSH Server is not installed" do
            skip "This requirement is not applicable as the OpenSSH Server is not installed in the Docker environment."
          end
        end
      end
    else
      describe "The OpenSSH Server configuration" do
        it "has the correct #{setting} configuration" do
          expect(sshd_active_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Please ensure it set to '#{value}'."
        end
      end
    end
  end

end
