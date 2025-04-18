package runner

import (
	"github.com/projectdiscovery/gologger"
)

const banner = `
               __    _____           __                   __          
   _______  __/ /_  / __(_)___  ____/ /__  _____   ____  / /_  _______
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/  / __ \/ / / / / ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /     / /_/ / / /_/ (__  ) 
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/     / .___/_/\__,_/____/  
                                               /_/    
`

// Name
const ToolName = `subfinder-plus`

// Version is the current version of subfinder
const version = `v1.0.2-cnb`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tdocs.xscan.wiki\n\n")
}

// GetUpdateCallback returns a callback function that updates subfinder
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		//updateutils.GetUpdateToolCallback("subfinder", version)()
	}
}
