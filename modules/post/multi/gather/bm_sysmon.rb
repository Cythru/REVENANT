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
  include Msf::Auxiliary::Report

  BM_SYSMON = File.expand_path('~/apps/chloe/modules/sysadmin/sysmon.bm')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'BlackMagic SysMon — System Snapshot Gatherer',
        'Description'  => %q{
          Gathers a full system snapshot using the BlackMagic sysmon.bm module:
          memory, disk, CPU load, process counts, and optionally network bandwidth.
          Stores structured JSON results in the MSF database as loot.

          Modes: overview, disk, info, json (default)
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Luke Saunderson'],
        'Platform'     => %w[linux android],
        'SessionTypes' => %w[meterpreter shell],
        'Notes'        => {
          'SideEffects' => [],
          'Reliability' => [REPEATABLE_SESSION],
          'Stability'   => [CRASH_SAFE]
        }
      )
    )

    register_options([
      OptString.new('MODE', [true, 'Mode: overview, disk, info, json', 'json']),
      OptBool.new('STORE_LOOT', [false, 'Store JSON snapshot as MSF loot', true])
    ])
  end

  def run
    unless File.exist?(BM_SYSMON)
      fail_with(Failure::NotFound,
                "sysmon.bm not found at #{BM_SYSMON}")
    end

    mode = datastore['MODE'].to_s.downcase
    flag = "--#{mode}"

    print_status("Running sysmon.bm #{flag}...")
    output = capture_bm(BM_SYSMON, flag)

    if mode == 'json' && datastore['STORE_LOOT']
      store_loot(
        'bm.sysmon.snapshot',
        'application/json',
        session.session_host,
        output,
        'sysmon_snapshot.json',
        'BlackMagic SysMon system snapshot'
      )
      print_good('Snapshot stored as loot (bm.sysmon.snapshot)')
    end

    print_status('SysMon complete.')
  end

  private

  def capture_bm(script, *flags)
    cmd = ['bash', script] + flags.map(&:to_s)
    output = ''
    IO.popen(cmd, err: %i[child out]) do |io|
      io.each_line do |line|
        output << line
        print_status(line.chomp)
      end
    end
    output
  rescue Errno::ENOENT => e
    fail_with(Failure::BadConfig, "Exec failed: #{e.message}")
  end
end
