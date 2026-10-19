package main

import (
	"fmt"
	"os"
	"sort"

	"corkboard/internal/cli"
)

var version = "dev"

type subcommand struct {
	summary string
	run     func(args []string) error
}

var commands = map[string]subcommand{
	"version": {
		summary: "print cork version",
		run: func([]string) error {
			fmt.Println("cork " + version)
			return nil
		},
	},
	"init": {
		summary: "create a fresh data dir (server.yaml, scope, team passphrase)",
		run:     cli.RunInit,
	},
	"passphrase": {
		summary: "set or change the team passphrase (cork passphrase --data DIR)",
		run:     cli.RunPassphrase,
	},
	"serve": {
		summary: "run the cork server (cork serve --data DIR)",
		run:     cli.RunServe,
	},
	"login": {
		summary: "verify credentials, pin TLS fingerprint, write client config",
		run:     cli.RunLogin,
	},
	"push": {
		summary: "push scan result files (nmap XML, nxc DBs/workspaces)",
		run:     cli.RunPush,
	},
	"hosts": {
		summary: "list hosts with filters",
		run:     cli.RunHosts,
	},
	"host": {
		summary: "show one host in full (services, web, creds masked, notes)",
		run:     cli.RunHost,
	},
	"targets": {
		summary: "raw target list for piping into nmap -iL",
		run:     cli.RunTargets,
	},
	"claim": {
		summary: "claim a host, task, service, or application (cork claim IP|TASKID|service:ID [--steal])",
		run:     cli.RunClaim,
	},
	"release": {
		summary: "release a claim (cork release IP|TASKID|service:ID)",
		run:     cli.RunRelease,
	},
	"log": {
		summary: "log what you did (cork log IP[:PORT] \"text\" [--worked|--failed] [--cmd CMD])",
		run:     cli.RunLog,
	},
	"note": {
		summary: "same as cork log",
		run:     cli.RunLog,
	},
	"tag": {
		summary: "add/remove tags (cork tag IP +web -dc)",
		run:     cli.RunTag,
	},
	"priority": {
		summary: "set a host's priority (cork priority IP 1|2|3)",
		run:     cli.RunPriority,
	},
	"explored": {
		summary: "mark a service explored (cork explored IP:PORT[/udp] [--undo])",
		run:     cli.RunExplored,
	},
	"status": {
		summary: "team dashboard: counts, my claims, scope alarms",
		run:     cli.RunStatus,
	},
	"scope": {
		summary: "local scope check/exclude (cork scope check TARGET...)",
		run:     cli.RunScope,
	},
	"checks":  {summary: "credential check queue, results, scope, and history", run: cli.RunChecks},
	"access":  {summary: "access ledger: how access was gained, vantages, tunnels (cork access list --as-of T)", run: cli.RunAccess},
	"changes": {summary: "what others changed since you last looked (--since 8h --all for standup)", run: cli.RunChanges},
	"search":  {summary: "search hosts, services, log entries, tasks, findings and identities", run: cli.RunSearch},
	"task": {
		summary: "tasks: list / done / block / add",
		run:     cli.RunTask,
	},
	"cred": {
		summary: "credentials: add / list / where / reveal",
		run:     cli.RunCred,
	},
	"owned": {
		summary: "mark a host compromised (cork owned IP --level L -m \"how\")",
		run:     cli.RunOwned,
	},
	"evidence": {summary: "attach image/text evidence or an external reference", run: cli.RunEvidence},
	"finding": {
		summary: "findings: list / confirm / reject",
		run:     cli.RunFinding,
	},
	"export": {
		summary: "export hosts.csv | services.csv | creds.csv | findings.csv | all.json | appendix.md | narrative.md",
		run:     cli.RunExport,
	},
	"bloodhound": {
		summary: "BloodHound ownership: status / check / sync / owned",
		run:     cli.RunBloodHound,
	},
	"archive": {
		summary: "export, inspect, or restore a complete engagement snapshot",
		run:     cli.RunArchive,
	},
	"purge": {
		summary: "purge all data after the engagement (cork purge --confirm NAME)",
		run:     cli.RunPurge,
	},
}

func main() {
	cli.Version = version
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(1)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage(os.Stdout)
		return
	}
	sub, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "cork: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(1)
	}
	if err := sub.run(args); err != nil {
		fmt.Fprintf(os.Stderr, "cork %s: %v\n", cmd, err)
		os.Exit(cli.ExitCode(err))
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "cork — shared recon hub for pen-testing teams (server + client in one binary)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  cork <command> [flags] [args]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %-10s %s\n", name, commands[name].summary)
	}
	fmt.Fprintln(w, "  help       show this help")
}
