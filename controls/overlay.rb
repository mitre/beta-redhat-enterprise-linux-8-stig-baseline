include_controls 'redhat-enterprise-linux-8-stig-baseline' do

  # 1. Modify AIDE control to be a slow control and have a fast check (new input aide_check_fast)

  control 'SV-251710' do
    title 'The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.'
    desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed.
          Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the
          system security policy and supporting the isolation of code and data on which the protection is based. Security functionality
          includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges),
          setting events to be audited, and setting intrusion detection parameters.
  
          This requirement applies to the RHEL 8 operating system performing security function verification/testing and/or systems and
          environments that require this functionality.'
    desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all
          security functions.
  
          Check that the AIDE package is installed with the following command:
            $ sudo rpm -q aide
  
            aide-0.16-14.el8_5.1.x86_64
  
          If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.
  
          If there is no application installed to perform integrity checks, this is a finding.
  
          If AIDE is installed, check if it has been initialized with the following command:
            $ sudo /usr/sbin/aide --check
  
          If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
    desc 'fix', 'Install AIDE, initialize it, and perform a manual check.
  
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
  
          Done.'
    impact 0.5
    tag check_id: 'C-55147r880728_chk'
    tag severity: 'medium'
    tag gid: 'V-251710'
    tag rid: 'SV-251710r880730_rule'
    tag stig_id: 'RHEL-08-010359'
    tag gtitle: 'SRG-OS-000445-GPOS-00199'
    tag fix_id: 'F-55101r880729_fix'
    tag 'documentable'
    tag cci: ['CCI-002696']
    tag nist: ['SI-6 a']
    tag 'host'
  
    aide_check_fast = input('aide_check_fast', value: false) # Default to false if not specified
  
    only_if("This control takes a long time to execute so it has been disabled through 'slow_controls'") {
      !input('disable_slow_controls') && !aide_check_fast
    }
  
    file_integrity_tool = input('file_integrity_tool')
  
    only_if('Control not applicable within a container', impact: 0.0) do
      !virtualization.system.eql?('docker')
    end
  
    if file_integrity_tool == 'aide'
      if aide_check_fast
        describe file('/var/lib/aide/aide.db.gz') do
          it { should exist }
        end
      else
        describe command('/usr/sbin/aide --check') do
          its('stdout') { should_not include "Couldn't open file" }
        end
      end
    end
  
    describe package(file_integrity_tool) do
      it { should be_installed }
    end
  end

# 2. New input called container_host to check if system needs to be able to host containers

control 'SV-230548' do
  title 'RHEL 8 must disable the use of user namespaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 disables the use of user namespaces with the following commands:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable.

$ sudo sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: user.max_user_namespaces = 0

If "user.max_user_namespaces" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

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
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230548'
  tag rid: 'SV-230548r858828_rule'
  tag stig_id: 'RHEL-08-040284'
  tag fix_id: 'F-33192r858827_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  only_if('This system is acting as a container host, this control is Not Applicable', impact: 0.0) {
    !input('container_host')
  }
  
  # Define the kernel parameter to be checked
  parameter = 'user.max_user_namespaces'
  action = 'user namespaces'
  value = 0

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif 
  else

    describe kernel_parameter(parameter) do
      it 'is disabled in sysctl -a' do
        expect(current_value.value).to cmp value
        expect(current_value.value).not_to be_nil
      end
    end

    # Get the list of sysctl configuration files
    sysctl_config_files = input('sysctl_conf_files').map(&:strip).join(' ')

    # Search for the kernel parameter in the configuration files
    search_results = command("grep -r #{parameter} #{sysctl_config_files} {} \;").stdout.split("\n")

    # Parse the search results into a hash
    config_values = search_results.each_with_object({}) do |item, results|
      file, setting = item.split(':')
      results[file] ||= []
      results[file] << setting.split('=').last
    end

    uniq_config_values = config_values.values.flatten.map(&:strip).map(&:to_i).uniq

    # Check the configuration files
    describe 'Configuration files' do
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
control 'SV-230279' do
  title 'RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks.'
  desc 'Some adversaries launch attacks with the intent of executing code in
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
unqueued SLAB allocator.'
  desc 'check', 'Verify that GRUB 2 is configured to enable poisoning of SLUB/SLAB objects to mitigate use-after-free vulnerabilities with the following commands:

Check that the current GRUB 2 configuration has poisoning of SLUB/SLAB objects enabled:

$ sudo grub2-editenv list | grep slub_debug

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 slub_debug=P page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If "slub_debug" does not contain "P" or is missing, this is a finding.

Check that poisoning of SLUB/SLAB objects is enabled by default to persist in kernel updates:

$ sudo grep slub_debug /etc/default/grub

GRUB_CMDLINE_LINUX="slub_debug=P"

If "slub_debug" does not contain "P" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enable poisoning of SLUB/SLAB objects with the
following commands:

    $ sudo grubby --update-kernel=ALL --args="slub_debug=P"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="slub_debug=P"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192']
  tag gid: 'V-230279'
  tag rid: 'SV-230279r951598_rule'
  tag stig_id: 'RHEL-08-010423'
  tag fix_id: 'F-32923r567584_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grub2-editenv - list').stdout
  setting = /slub_debug\s*=\s*.*P.*/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['kernelopts']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end


# 4. (v1r14) 

control 'SV-230228' do
  title 'All RHEL 8 remote access methods must be monitored.'
  desc 'Remote access services, such as those providing remote access to
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
servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that RHEL 8 monitors all remote access methods.

    Check that remote access methods are being logged by running the following
command:

    $ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

    auth.*;authpriv.*;daemon.* /var/log/secure

    If "auth.*", "authpriv.*" or "daemon.*" are not configured to be
logged, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to monitor all remote access methods by installing rsyslog
with the following command:

    $ sudo yum install rsyslog

    Then add or update the following lines to the "/etc/rsyslog.conf" file:

    auth.*;authpriv.*;daemon.* /var/log/secure

    The "rsyslog" service must be restarted for the changes to take effect.
To restart the "rsyslog" service, run the following command:

    $ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-230228'
  tag rid: 'SV-230228r951592_rule'
  tag stig_id: 'RHEL-08-010070'
  tag fix_id: 'F-32872r567431_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable; remote access not configured within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  rsyslog = file('/etc/rsyslog.conf')

  describe rsyslog do
    it { should exist }
  end

  if rsyslog.exist?

    auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
    authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
    daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

    rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf')

    describe 'Logged remote access methods' do
      it 'should include auth.*' do
        expect(rsyslog_conf.stdout).to match(auth_pattern), 'auth.* not configured for logging'
      end
      it 'should include authpriv.*' do
        expect(rsyslog_conf.stdout).to match(authpriv_pattern), 'authpriv.* not configured for logging'
      end
      it 'should include daemon.*' do
        expect(rsyslog_conf.stdout).to match(daemon_pattern), 'daemon.* not configured for logging'
      end
    end
  end
end



end