# frozen_string_literal: true

# bm:lang=ruby
# bm:version=2
# Copyright (C) 2026 Luke Saunderson — AGPL-3.0
##
# This module requires Metasploit: https://metasploit.com/download
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Common

  BM_SYSADMIN_DIR = File.expand_path('~/apps/chloe/modules/sysadmin')
  BM_BIN_DIR      = File.expand_path('~/bin')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'BlackMagic Toolkit Deploy',
        'Description'  => %q{
          Deploys the BlackMagic sysadmin .bm toolkit onto a compromised Linux
          host via an active session. Uploads all sysadmin .bm modules + bmc,
          bmpkg, bmanalyze to a writable directory on the target.

          After deployment: run the .bm modules directly on the target via the
          session shell. All modules are self-contained bash — no Ruby required.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Luke Saunderson'],
        'Platform'     => ['linux'],
        'SessionTypes' => %w[meterpreter shell],
        'Notes'        => {
          'SideEffects' => [ARTIFACTS_ON_DISK],
          'Reliability' => [REPEATABLE_SESSION],
          'Stability'   => [CRASH_SAFE]
        }
      )
    )

    register_options([
      OptString.new('DEPLOY_DIR', [true, 'Remote directory to deploy BM toolkit', '/tmp/.bm']),
      OptBool.new('DEPLOY_BINS', [true, 'Also deploy bmc/bmpkg/bmanalyze binaries', true])
    ])
  end

  def run
    deploy_dir = datastore['DEPLOY_DIR']
    print_status("Deploying BlackMagic toolkit to target:#{deploy_dir}")

    # Ensure deploy dir exists on target
    cmd_exec("mkdir -p #{deploy_dir}/sysadmin 2>/dev/null")

    # Upload sysadmin .bm modules
    bm_files = Dir.glob(File.join(BM_SYSADMIN_DIR, '*.bm'))
    if bm_files.empty?
      fail_with(Failure::NotFound,
                "No .bm modules found at #{BM_SYSADMIN_DIR}")
    end

    bm_files.each do |local_file|
      fname = File.basename(local_file)
      remote_path = "#{deploy_dir}/sysadmin/#{fname}"
      print_status("  Uploading #{fname}...")
      upload_file(remote_path, local_file)
      cmd_exec("chmod +x #{remote_path} 2>/dev/null")
    end
    print_good("Uploaded #{bm_files.size} sysadmin modules")

    if datastore['DEPLOY_BINS']
      %w[bmc bmpkg bmanalyze].each do |bin|
        local_bin = File.join(BM_BIN_DIR, bin)
        next unless File.exist?(local_bin)

        remote_bin = "#{deploy_dir}/#{bin}"
        print_status("  Uploading #{bin}...")
        upload_file(remote_bin, local_bin)
        cmd_exec("chmod +x #{remote_bin} 2>/dev/null")
      end
      print_good('Uploaded BM binaries (bmc, bmpkg, bmanalyze)')
    end

    print_line('')
    print_good("BlackMagic toolkit deployed to target:#{deploy_dir}")
    print_status("Run modules on target:")
    print_status("  bash #{deploy_dir}/sysadmin/sysmon.bm --overview")
    print_status("  bash #{deploy_dir}/sysadmin/procwatch.bm --top-cpu 10")
    print_status("  bash #{deploy_dir}/sysadmin/nethunt.bm --scan <target>")
    print_status("  bash #{deploy_dir}/sysadmin/inspect.bm --stuck")
  end
end
