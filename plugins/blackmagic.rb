# frozen_string_literal: true

# bm:lang=ruby
# bm:version=2
# Copyright (C) 2026 Luke Saunderson — AGPL-3.0
#
# blackmagic.rb — BlackMagic superset plugin for msfconsole
#
# Integrates the full BM sysadmin toolkit into msfconsole.
# All bm_* commands delegate to ~/apps/chloe/modules/sysadmin/*.bm
#
# Usage in msfconsole:
#   bm_help               — list all BM commands
#   bm_sysmon [flags]     — system overview
#   bm_nethunt [flags]    — network hunt/scan
#   bm_inspect [flags]    — process/binary inspector
#   bm_procwatch [flags]  — single-process watcher
#   bm_netpipe [flags]    — TCP tunnel/relay
#   bm_vault [flags]      — secrets/crypto
#   bm_filemove [flags]   — file find/sync/fetch
#   bm_sched [flags]      — task scheduler
#   bm_analyze <file>     — BigO analyzer on any file
#   bm_pkgstatus          — toolchain status

module Msf
  class Plugin::BlackMagic < Msf::Plugin

    BM_SYSADMIN = File.expand_path('~/apps/chloe/modules/sysadmin')
    BM_BIN      = File.expand_path('~/bin')

    MODULES = {
      'sysmon'   => { file: 'sysmon.bm',   desc: 'System overview: cpu/mem/disk/net' },
      'nethunt'  => { file: 'nethunt.bm',  desc: 'Network: nmap/traceroute/whois/http' },
      'inspect'  => { file: 'inspect.bm',  desc: 'Process/binary inspector: strace/lsof/hexyl/r2' },
      'procwatch'=> { file: 'procwatch.bm',desc: 'Single-process deep-watch' },
      'netpipe'  => { file: 'netpipe.bm',  desc: 'TCP tunnel/relay/tor/iperf' },
      'vault'    => { file: 'vault.bm',    desc: 'Secrets: pass/gpg/age' },
      'filemove' => { file: 'filemove.bm', desc: 'File find/sync/fetch/dedupe' },
      'sched'    => { file: 'sched.bm',    desc: 'Task scheduler: cron/at/services' }
    }.freeze

    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'BlackMagic'
      end

      def commands
        base = {
          'bm_help'      => 'List all BlackMagic commands',
          'bm_pkgstatus' => 'Show BM toolchain install status',
          'bm_analyze'   => 'BigO + language analyzer on a file',
        }
        Msf::Plugin::BlackMagic::MODULES.each_key do |mod|
          base["bm_#{mod}"] = Msf::Plugin::BlackMagic::MODULES[mod][:desc]
        end
        base
      end

      def cmd_bm_help(*_args)
        print_status('BlackMagic Superset — sysadmin toolkit integrated into msfconsole')
        print_line('')
        print_line(format('  %-20s %s', 'Command', 'Description'))
        print_line(format('  %-20s %s', '-------', '-----------'))
        Msf::Plugin::BlackMagic::MODULES.each do |mod, info|
          print_line(format('  %-20s %s', "bm_#{mod}", info[:desc]))
        end
        print_line(format('  %-20s %s', 'bm_analyze <file>', 'BigO + language recommender'))
        print_line(format('  %-20s %s', 'bm_pkgstatus', 'Toolchain install status'))
        print_line('')
        print_status('All bm_* commands accept the same flags as the .bm modules.')
        print_status("Run: bm_nethunt --scan <host>  or  bm_sysmon --overview")
      end

      def cmd_bm_pkgstatus(*_args)
        bmpkg = File.join(Msf::Plugin::BlackMagic::BM_BIN, 'bmpkg')
        unless File.executable?(bmpkg)
          print_error("bmpkg not found at #{bmpkg}")
          return
        end
        print_status('BlackMagic toolchain status:')
        output = `#{bmpkg} status 2>&1`
        output.each_line do |line|
          if line.include?('MISSING')
            print_warning(line.chomp)
          else
            print_good(line.chomp)
          end
        end
      end

      def cmd_bm_analyze(*args)
        bmanalyze = File.join(Msf::Plugin::BlackMagic::BM_BIN, 'bmanalyze')
        unless File.executable?(bmanalyze)
          print_error("bmanalyze not found at #{bmanalyze}")
          return
        end
        if args.empty?
          print_error('Usage: bm_analyze <file> [--rewrite-rust] [--threshold 1|2|3]')
          return
        end
        file = args.shift
        unless File.exist?(file)
          print_error("File not found: #{file}")
          return
        end
        print_status("Analyzing #{file}...")
        run_bm_cmd(bmanalyze, [file] + args)
      end

      # Dynamically generate bm_<module> command handlers
      Msf::Plugin::BlackMagic::MODULES.each do |mod, info|
        define_method("cmd_bm_#{mod}") do |*args|
          bm_file = File.join(Msf::Plugin::BlackMagic::BM_SYSADMIN, info[:file])
          unless File.exist?(bm_file)
            print_error("#{info[:file]} not found at #{bm_file}")
            return
          end
          if args.include?('--help') || args.include?('-h')
            run_bm_cmd('bash', [bm_file, '--help'])
          elsif args.empty?
            print_status("#{mod} — #{info[:desc]}")
            print_status("Usage: bm_#{mod} [flags]  — run 'bm_#{mod} --help' for options")
          else
            run_bm_cmd('bash', [bm_file] + args)
          end
        end
      end

      private

      def run_bm_cmd(binary, args)
        cmd = [binary] + args
        # Use IO.popen for streaming output into msfconsole
        IO.popen(cmd, err: %i[child out]) do |io|
          io.each_line do |line|
            line = line.chomp
            if line.start_with?('[+]') || line.include?('ok') || line.include?('installed')
              print_good(line)
            elsif line.start_with?('[!]') || line.include?('MISS') || line.include?('ERR')
              print_warning(line)
            elsif line.start_with?('[-]') || line.include?('error') || line.include?('fatal')
              print_error(line)
            else
              print_status(line)
            end
          end
        end
      rescue Errno::ENOENT => e
        print_error("Could not execute: #{e.message}")
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_status('BlackMagic plugin loaded — type bm_help for commands')
    end

    def cleanup
      remove_console_dispatcher('BlackMagic')
    end

    def name
      'blackmagic'
    end

    def desc
      'BlackMagic superset sysadmin toolkit integrated into msfconsole'
    end
  end
end
