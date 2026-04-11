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

  BM_PROCWATCH = File.expand_path('~/apps/chloe/modules/sysadmin/procwatch.bm')
  BM_INSPECT   = File.expand_path('~/apps/chloe/modules/sysadmin/inspect.bm')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'BlackMagic ProcWatch — Post-Exploitation Process Surveillance',
        'Description'    => %q{
          After gaining a session, uses the BlackMagic procwatch.bm + inspect.bm
          sysadmin modules to survey running processes on the local host (useful
          during local engagements or when pivoting through localhost sessions).

          Modes:
            top      — top N processes by CPU/memory
            stuck    — find zombie + stalled processes
            pid      — deep snapshot of a specific pid
            tree     — full process tree

          JSON output available for pipeline integration with other modules.
        },
        'License'        => MSF_LICENSE,
        'Author'         => ['Luke Saunderson'],
        'Platform'       => %w[linux android],
        'SessionTypes'   => %w[meterpreter shell],
        'Notes'          => {
          'SideEffects' => [ARTIFACTS_ON_DISK],
          'Reliability' => [REPEATABLE_SESSION],
          'Stability'   => [CRASH_SAFE]
        }
      )
    )

    register_options([
      OptString.new('MODE', [true, 'Mode: top, stuck, pid, tree', 'top']),
      OptInt.new('TOP_N', [false, 'Number of top processes to show', 10]),
      OptInt.new('PID', [false, 'Target PID (for pid mode)', 0]),
      OptBool.new('JSON_OUTPUT', [false, 'JSON output for pipeline use', false])
    ])
  end

  def run
    unless File.exist?(BM_PROCWATCH)
      fail_with(Failure::NotFound,
                "procwatch.bm not found at #{BM_PROCWATCH}")
    end

    mode = datastore['MODE'].to_s.downcase
    n    = datastore['TOP_N'].to_i
    pid  = datastore['PID'].to_i
    json = datastore['JSON_OUTPUT']

    case mode
    when 'top'
      flag = json ? '--json-top' : '--top-cpu'
      run_bm(BM_PROCWATCH, flag, n.to_s)
    when 'stuck'
      run_bm(BM_PROCWATCH, '--stuck')
    when 'pid'
      fail_with(Failure::BadConfig, 'Set PID option for pid mode') if pid.zero?
      flag = json ? '--json' : '--pid'
      run_bm(BM_INSPECT, flag, pid.to_s)
    when 'tree'
      run_bm(BM_PROCWATCH, '--tree')
    else
      fail_with(Failure::BadConfig, "Unknown MODE '#{mode}' — use: top, stuck, pid, tree")
    end
  end

  private

  def run_bm(script, *flags)
    cmd = ['bash', script] + flags.map(&:to_s)
    print_status("BM: #{cmd[1..].join(' ')}")
    IO.popen(cmd, err: %i[child out]) do |io|
      io.each_line { |line| print_status(line.chomp) }
    end
  rescue Errno::ENOENT => e
    fail_with(Failure::BadConfig, "Exec failed: #{e.message}")
  end
end
