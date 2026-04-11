# frozen_string_literal: true

# bm:lang=ruby
# bm:version=2
# Copyright (C) 2026 Luke Saunderson — AGPL-3.0
##
# This module requires Metasploit: https://metasploit.com/download
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  BM_NETHUNT = File.expand_path('~/apps/chloe/modules/sysadmin/nethunt.bm')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'BlackMagic NetHunt — Network Recon',
        'Description' => %q{
          Wraps the BlackMagic nethunt.bm sysadmin module for network recon.
          Performs nmap scanning, traceroute with whois annotation, HTTP probing,
          and DNS inspection — all composable with other BM sysadmin modules.

          Requires nethunt.bm + nmap, traceroute, whois, xh installed via bmpkg.
        },
        'Author'      => ['Luke Saunderson'],
        'License'     => MSF_LICENSE,
        'Notes'       => {
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION],
          'Stability'   => [CRASH_SAFE]
        }
      )
    )

    register_options([
      OptString.new('MODE', [true, 'Recon mode: scan, scan-full, trace, whois, http, local', 'scan']),
      OptString.new('RHOST', [false, 'Target host (for scan/trace/whois/http modes)', '']),
      OptString.new('URL', [false, 'Full URL for http mode', '']),
      OptBool.new('JSON_OUTPUT', [false, 'Emit machine-readable JSON (for bm_nethunt --json)', false])
    ])

    deregister_options('RPORT', 'RHOSTS')
  end

  def check_bm
    unless File.exist?(BM_NETHUNT)
      fail_with(Failure::NotFound,
                "nethunt.bm not found at #{BM_NETHUNT} — clone Chloe modules first")
    end
  end

  def run_nethunt(*flags)
    cmd = ['bash', BM_NETHUNT] + flags
    print_status("Running: #{cmd.join(' ')}")
    output = ''
    IO.popen(cmd, err: %i[child out]) do |io|
      io.each_line do |line|
        output << line
        print_status(line.chomp)
      end
    end
    output
  rescue Errno::ENOENT => e
    fail_with(Failure::BadConfig, "Could not exec nethunt.bm: #{e.message}")
  end

  def run_host(ip)
    check_bm
    mode = datastore['MODE'].to_s.downcase

    case mode
    when 'scan'
      target = ip.empty? ? datastore['RHOST'] : ip
      fail_with(Failure::BadConfig, 'No target — set RHOST or use with RHOSTS') if target.empty?
      output = datastore['JSON_OUTPUT'] ? run_nethunt('--json', target) : run_nethunt('--scan', target)
      parse_and_report(target, output) if datastore['JSON_OUTPUT']

    when 'scan-full'
      target = ip.empty? ? datastore['RHOST'] : ip
      fail_with(Failure::BadConfig, 'No target — set RHOST') if target.empty?
      run_nethunt('--scan-full', target)

    when 'trace'
      target = ip.empty? ? datastore['RHOST'] : ip
      fail_with(Failure::BadConfig, 'No target') if target.empty?
      run_nethunt('--trace', target)

    when 'whois'
      target = ip.empty? ? datastore['RHOST'] : ip
      fail_with(Failure::BadConfig, 'No target') if target.empty?
      run_nethunt('--whois', target)

    when 'http'
      url = datastore['URL']
      fail_with(Failure::BadConfig, 'Set URL option for http mode') if url.empty?
      run_nethunt('--http', url)

    when 'local'
      run_nethunt('--local')

    else
      fail_with(Failure::BadConfig, "Unknown MODE '#{mode}' — use: scan, scan-full, trace, whois, http, local")
    end
  end

  private

  def parse_and_report(host, json_output)
    require 'json'
    data = JSON.parse(json_output.lines.last || '{}')
    ports = data['open_ports'] || []
    ports.each do |p|
      report_service(
        host: host,
        port: p['port'],
        proto: p['proto'],
        name: p['service']
      )
      print_good("  #{host}:#{p['port']}/#{p['proto']} — #{p['service']}")
    end
  rescue JSON::ParserError
    vprint_warning('Could not parse JSON output for reporting')
  end
end
