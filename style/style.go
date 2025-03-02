package style


import (
	"github.com/charmbracelet/lipgloss"
)

// Catppuccin colors
var (
	rosewater = lipgloss.Color("#f4dbd6")
	flamingo  = lipgloss.Color("#f0c6c6")
	pink      = lipgloss.Color("#f5bde6")
	mauve     = lipgloss.Color("#c6a0f6")
	red       = lipgloss.Color("#ed8796")
	maroon    = lipgloss.Color("#ee99a0")
	peach     = lipgloss.Color("#f5a97f")
	yellow    = lipgloss.Color("#eed49f")
	green     = lipgloss.Color("#a6da95")
	teal      = lipgloss.Color("#8bd5ca")
	sky       = lipgloss.Color("#91d7e3")
	sapphire  = lipgloss.Color("#7dc4e4")
	blue      = lipgloss.Color("#8aadf4")
	lavender  = lipgloss.Color("#b7bdf8")
	text      = lipgloss.Color("#cad3f5")
	subtext1  = lipgloss.Color("#b8c0e0")
	subtext0  = lipgloss.Color("#a5adcb")
	overlay2  = lipgloss.Color("#939ab7")
	overlay1  = lipgloss.Color("#8087a2")
	overlay0  = lipgloss.Color("#6e738d")
	surface2  = lipgloss.Color("#5b6078")
	surface1  = lipgloss.Color("#494d64")
	surface0  = lipgloss.Color("#363a4f")
	base      = lipgloss.Color("#24273a")
	mantle    = lipgloss.Color("#1e2030")
	crust     = lipgloss.Color("#181926")
)

// Styles
var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(lavender).
			Background(crust).
			Bold(true).
			Padding(1, 2)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(teal).
			Background(crust).
			Italic(true).
			Padding(0, 2)

	BodyTextStyle = lipgloss.NewStyle().
			Foreground(text).
			Background(base).
			Padding(1, 2)

	ErrorTextStyle = lipgloss.NewStyle().
			Foreground(red).
			Background(base).
			Padding(1, 2)

	SuccessTextStyle = lipgloss.NewStyle().
			Foreground(green).
			Background(base).
			Padding(1, 2)

	WarningTextStyle = lipgloss.NewStyle().
			Foreground(yellow).
			Background(base).
			Padding(1, 2)

	InfoTextStyle = lipgloss.NewStyle().
			Foreground(blue).
			Background(base).
			Padding(1, 2)

	FooterStyle = lipgloss.NewStyle().
			Foreground(subtext1).
			Background(crust).
			Padding(1, 2)
)