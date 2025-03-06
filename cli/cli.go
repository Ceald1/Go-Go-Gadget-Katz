package cli

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"katz/katz/modules"
	"katz/katz/utils"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sys/windows"
)

var (
	commands = []string{"sam::dump", "sam::sysKey", "sam::bootKey", "token", "lsa::dump"}
)

type Model struct {
	textInput   textinput.Model
	width       int
	height      int
	inputBuffer string
	outputtext  string
	wintoken    windows.Token
	parsedArgs  map[string]string
	valueFound  bool
}

func InitialModel() Model {
	ti := textinput.New()
	ti.CharLimit = 5000
	ti.Prompt = "&> "
	ti.Focus()
	return Model{
		textInput: ti,
		wintoken:  0,
		parsedArgs: make(map[string]string),
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			m.inputBuffer = m.textInput.Value() // Update the input buffer with the current text input value
			m.parseInput()
			commandOutput := fmt.Sprintf("%s%s\n", m.textInput.Prompt, m.inputBuffer)
			switch {
			case strings.HasPrefix(m.inputBuffer, "token"):
				wintoken, err := utils.GetSystem()
				m.wintoken = wintoken
				if err != nil {
					commandOutput += err.Error() + "\n"
				} else {
					commandOutput += "Got System Token!\n"
				}
			case strings.HasPrefix(m.inputBuffer, "quitKatz"),
				strings.HasPrefix(m.inputBuffer, "exitKatz"),
				strings.HasPrefix(m.inputBuffer, "exit"),
				strings.HasPrefix(m.inputBuffer, "quit"),
				strings.HasPrefix(m.inputBuffer, "quitkatz"),
				strings.HasPrefix(m.inputBuffer, "exitkatz"):
				return m, tea.Quit
			case strings.HasPrefix(m.inputBuffer, "sam::dump"):
				if m.wintoken == 0 {
					commandOutput += "Need system account token!\n"
				} else {
					var result string
					data, err := modules.DumpSAM(m.wintoken)
					if err != nil {
						result = err.Error()
					} else {
						var formatted []string
						for _, d := range data {
							rid := d.Rid
							Name := d.Name
							nt := d.Nthash
							d_str := fmt.Sprintf("%s:%d:%s", Name, rid, nt)
							d_str = strings.Replace(d_str, " ", "", -1)
							formatted = append(formatted, d_str)
						}
						result = strings.Join(formatted[:], "\n")
					}
					commandOutput += result + "\n"
				}
			case strings.HasPrefix(m.inputBuffer, "sam::sysKey"):
				if m.wintoken == 0 {
					commandOutput += "Need system account token!\n"
				} else {
					var result string
					result, err := modules.GetSysKey(m.wintoken)
					if err != nil {
						result = fmt.Sprintf("Error: %s", err)
					}
					commandOutput += result + "\n"

				}
			case strings.HasPrefix(m.inputBuffer, "sam::bootKey"):
				if m.wintoken == 0 {
					commandOutput += "Need system account token!\n"
				} else {
					var result string
					data, err := modules.GetBootKey(m.wintoken)
					result = "0x" + hex.EncodeToString(data)
					if err != nil {
						result = fmt.Sprintf("Error: %s", err)
					}
					commandOutput += result + "\n"

				}
			case strings.HasPrefix(m.inputBuffer, "lsa::dump"):
				if m.wintoken == 0 {
					commandOutput += "Need system account token!\n"
				} else {
					var result string
					var bootKey []byte
					bootKey, err := modules.GetBootKey(m.wintoken)
					if err != nil {
						result = fmt.Sprintf("Error: %s", err)
					} else {
						var VistaStyle = true
						var history = false
						for arg, _ := range m.parsedArgs {
							if arg == "nonVista" {
								commandOutput += "attacking old ass system\n"
								VistaStyle = false
							}
							if arg == "history" {
								history = true
								commandOutput += "getting history\n"
							}else {
								commandOutput += fmt.Sprintf("unknown arg '%s'\n",arg)
							}

						}
						secrets, err := modules.DumpLSASecrets(m.wintoken,bootKey, VistaStyle, history)
						if err != nil {
							result = "error: "+ err.Error()
						}else {
							for index := range secrets{
								commandOutput += secrets[index].PrintSecret() + "\n"
							}
						}
					}
					commandOutput += result + "\n"

				}
			// case strings.HasPrefix(m.inputBuffer, "custom::command"):
			// 	commandOutput += "Parsed Arguments:\n"
			// 	for key, value := range m.parsedArgs {
			// 		commandOutput += fmt.Sprintf("  %s: %s\n", key, value)
			// 	}
			default:
				commandOutput += "Unknown command\n available commands:\n"
				for _, i := range commands {
					commandOutput += fmt.Sprintf("%s\n", i)
				}
			}
			m.outputtext += commandOutput
			m.textInput.SetValue("") // Clear the input after processing
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)

	return m, cmd
}

func (m *Model) parseInput() {
	re := regexp.MustCompile(`/(\w+):([^ ]+)`)
	matches := re.FindAllStringSubmatch(m.inputBuffer, -1)
	m.parsedArgs = make(map[string]string)
	for _, match := range matches {
		if len(match) == 3 {
			m.parsedArgs[match[1]] = match[2]
		}
	}
}

func (m Model) View() string {
	return fmt.Sprintf("%s\n%s", m.outputtext,m.textInput.View())
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func Run() {
	p := tea.NewProgram(InitialModel())
	if err := p.Start(); err != nil {
		fmt.Printf("Error: %v", err)
	}
}