package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF6B6B")).
			PaddingLeft(2)

	menuStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A0A0A0"))

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Background(lipgloss.Color("#1A1A1A")).
			PaddingLeft(1).
			PaddingRight(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFD93D")).
			PaddingBottom(1)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6BCB77"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			PaddingTop(1)
)

type item struct {
	name    string
	command string
	desc    string
}

type model struct {
	items   []item
	cursor  int
	running bool
	output  string
	quitting bool
}

func defaultItems() []item {
	return []item{
		{name: "Launch (opsec up)", command: "sudo bash ~/.opsec/launch.sh up", desc: "VPN + Tor + Docker sandbox"},
		{name: "Teardown (opsec down)", command: "sudo bash ~/.opsec/launch.sh down", desc: "Stop everything, clean up"},
		{name: "Status", command: "sudo bash ~/.opsec/launch.sh status", desc: "Show all protection status"},
		{name: "Enter Red Team Shell", command: "docker exec -it opsec-redteam bash", desc: "Drop into isolated container"},
		{name: "Scan Target", command: "", desc: "Honeypot check before engaging"},
		{name: "VPN Rotate", command: "sudo bash ~/.opsec/vpn-rotate.sh rotate", desc: "Switch to new exit IP"},
		{name: "VPN Status", command: "sudo bash ~/.opsec/vpn-rotate.sh status", desc: "Show VPN connection info"},
		{name: "Honeypot Detect", command: "", desc: "Scan target for honeypots"},
		{name: "My IP", command: "curl -s https://api.ipify.org", desc: "Show current public IP"},
		{name: "Tor IP", command: "proxychains4 curl -s https://api.ipify.org", desc: "Show Tor exit IP"},
		{name: "Opsec Check", command: "bash ~/.opsec/check.sh", desc: "Validate security posture"},
		{name: "Wipe Quick", command: "sudo bash ~/.opsec/anti-forensics.sh quick", desc: "Clean session traces"},
		{name: "Wipe Full", command: "sudo bash ~/.opsec/anti-forensics.sh full", desc: "Deep clean all artifacts"},
		{name: "MAC Randomize", command: "sudo bash ~/.opsec/mac-randomize.sh", desc: "Randomize network interface MAC"},
		{name: "Firewall", command: "sudo bash ~/.opsec/firewall.sh", desc: "Configure UFW + iptables"},
		{name: "Quit", command: "", desc: "Exit spoof"},
	}
}

func initialModel() model {
	return model{
		items: defaultItems(),
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if !m.running {
				m.quitting = true
				return m, tea.Quit
			}
		case "up", "k":
			if !m.running && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if !m.running && m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			if !m.running {
				selected := m.items[m.cursor]

				// Special handling for interactive commands
				if selected.name == "Enter Red Team Shell" {
					m.quitting = true
					return m, tea.Quit
				}

				if selected.name == "Scan Target" || selected.name == "Honeypot Detect" {
					// Will prompt after quit
					m.output = "PROMPT_TARGET"
					m.quitting = true
					return m, tea.Quit
				}

				if selected.command != "" {
					m.running = true
					m.output = ""
					return m, m.runCommand(selected.command)
				}

				if selected.name == "Quit" {
					m.quitting = true
					return m, tea.Quit
				}
			}
		}
	case execResultMsg:
		m.running = false
		m.output = msg.output
		if msg.err != nil {
			m.output = errorStyle.Render("Error: ") + msg.err.Error() + "\n" + msg.output
		}
	}
	return m, nil
}

type execResultMsg struct {
	output string
	err    error
}

func (m model) runCommand(command string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("sh", "-c", command)
		out, err := cmd.CombinedOutput()
		return execResultMsg{output: string(out), err: err}
	}
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  ⚡ SPOF — Red Team Opsec Launcher"))
	b.WriteString("\n\n")

	for i, item := range m.items {
		cursor := "  "
		name := menuStyle.Render(item.name)
		desc := menuStyle.Render("  " + item.desc)

		if i == m.cursor && !m.running {
			cursor = selectedStyle.Render("▶ ")
			name = selectedStyle.Render(item.name)
		}

		b.WriteString(fmt.Sprintf("%s%s%s\n", cursor, name, desc))
	}

	if m.running {
		b.WriteString("\n")
		b.WriteString(statusStyle.Render("  Running..."))
		b.WriteString("\n")
	}

	if m.output != "" && m.output != "PROMPT_TARGET" {
		b.WriteString("\n")
		b.WriteString("  " + strings.Repeat("─", 50))
		b.WriteString("\n")
		b.WriteString(m.output)
		b.WriteString("\n")
	}

	b.WriteString(helpStyle.Render("  j/k or arrows to navigate • enter to select • q to quit"))

	return b.String()
}

func main() {
	// Direct command execution mode
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "up":
			exec.Command("sh", "-c", "sudo bash ~/.opsec/launch.sh up").Run()
			return
		case "down":
			exec.Command("sh", "-c", "sudo bash ~/.opsec/launch.sh down").Run()
			return
		case "status":
			exec.Command("sh", "-c", "sudo bash ~/.opsec/launch.sh status").Run()
			return
		case "scan":
			if len(os.Args) < 3 {
				fmt.Println("Usage: spoof scan <target-ip>")
				os.Exit(1)
			}
			exec.Command("sh", "-c", "sudo bash ~/.opsec/launch.sh scan "+os.Args[2]).Run()
			return
		case "vpn":
			exec.Command("sh", "-c", "sudo bash ~/.opsec/vpn-rotate.sh rotate").Run()
			return
		case "wipe":
			mode := "quick"
			if len(os.Args) > 2 {
				mode = os.Args[2]
			}
			exec.Command("sh", "-c", "sudo bash ~/.opsec/anti-forensics.sh "+mode).Run()
			return
		case "help":
			fmt.Println("spoof — Red Team Opsec Launcher")
			fmt.Println("")
			fmt.Println("Usage:")
			fmt.Println("  spoof          Launch TUI menu")
			fmt.Println("  spoof up       Start full protection")
			fmt.Println("  spoof down     Stop everything")
			fmt.Println("  spoof status   Show protection status")
			fmt.Println("  spoof scan IP  Honeypot check target")
			fmt.Println("  spoof vpn      Rotate VPN IP")
			fmt.Println("  spoof wipe     Clean traces (quick|full|nuclear)")
			fmt.Println("  spoof help     Show this help")
			return
		default:
			fmt.Printf("Unknown command: %s\nRun 'spoof help' for usage\n", cmd)
			os.Exit(1)
		}
	}

	// Launch TUI
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle post-quit actions
	// (TUI exits, then we handle interactive prompts)
}
