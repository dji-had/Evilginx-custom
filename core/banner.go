package core

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const (
	VERSION = "2.4.2"
)

func putAsciiArt(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "#":
			color.Set(color.BgRed)
			d = " "
		case "@":
			color.Set(color.BgBlack)
			d = " "
		case `:`:
			color.Set(color.BgGreen)
			d = " "
		case `$`:
			color.Set(color.BgYellow)
			d = " "
		case `/`:
			color.Set(color.BgBlue)
			d = " "
		case " ":
			color.Unset()
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printLogo(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "_":
			color.Set(color.FgWhite)
		case "\n":
			color.Unset()
		default:
			color.Set(color.FgHiBlack)
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printUpdateName() {
	nameClr := color.New(color.FgHiRed)
	txt := nameClr.Sprintf("                 - --  Gone Phishing  -- -")
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner1() {
	handleClr := color.New(color.FgHiBlue)
	versionClr := color.New(color.FgGreen)
	textClr := color.New(color.FgHiBlack)
	spc := strings.Repeat(" ", 10-len(VERSION))
	txt := textClr.Sprintf("              Modified by (") + handleClr.Sprintf("𝕷 𝕮") + textClr.Sprintf(")") + spc + textClr.Sprintf("Version ") + versionClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner2() {
	textClr := color.New(color.FgHiBlack)
	red := color.New(color.FgRed)
	white := color.New(color.FgWhite)
	txt := red.Sprintf("                   Don't be evil") + white.Sprintf(" - ") + textClr.Sprintf("Modified version")
	fmt.Fprintf(color.Output, "%s", txt)
}

func Banner() {
	fmt.Println()

	putAsciiArt("             ##                                          ##           ")
	fmt.Println()
	putAsciiArt("             ####                                      ####           ")
	fmt.Println()
	putAsciiArt("             ######                                  ######            ")
	fmt.Println()
	putAsciiArt("              #######                              #######            ")
	fmt.Println()
	putAsciiArt("               ##########################################             ")
	fmt.Println()
	putAsciiArt("                 ######################################               ")
	fmt.Println()
	putAsciiArt("               ##########################################             ")
	fmt.Println()
	putAsciiArt("           ##################################################         ")
	fmt.Println()
	putAsciiArt("         #####################################################        ")
	fmt.Println()
	putAsciiArt(`        #########@@##################################@@########       `)
	fmt.Println()
	putAsciiArt("       ##########@@@@@@##########################@@@@@@#########      ")
	fmt.Println()
	putAsciiArt("      #############@@@@@@@#####################@@@@@@############     ")
	fmt.Println()
	putAsciiArt("     #############################################################    ")
	fmt.Println()
	putAsciiArt("    ###############################################################   ")
	fmt.Println()
	putAsciiArt("   #################################################################  ")
	fmt.Println()
	putAsciiArt("   #################################################################  ")
	fmt.Println()
	putAsciiArt("   $$$$$$$$$$$$$                      //////////////////////////////  ")
	fmt.Println()
	putAsciiArt("   $$$$$$$$$$$$$                      //////////////////////////////  ")
	fmt.Println()
	putAsciiArt("   $$$$$$$$$$$$$                      //////////////////////////////  ")
	fmt.Println()
	putAsciiArt("   $$$$$$$$$$$$$                      //////////////////////////////  ")
	fmt.Println()
	putAsciiArt("   $$$$$$$$$$$$:                                      //////////////  ")
	fmt.Println()
	putAsciiArt("    $$$$$$$$::::::                                   //////////////   ")
	fmt.Println()
	putAsciiArt("     $$$$:::::::::::                                //////////////    ")
	fmt.Println()
	putAsciiArt("      ::::::::::::::::                            ///////////////     ")
	fmt.Println()
	putAsciiArt("       :::::::::::::::::                        :://////////////      ")
	fmt.Println()
	putAsciiArt("         ::::::::::::::::::::::::::::::::::::::::::://////////        ")
	fmt.Println()
	putAsciiArt("           ::::::::::::::::::::::::::::::::::::::::::://////          ")
	fmt.Println()
	putAsciiArt("              :::::::::::::::::::::::::::::::::::::::::::             ")
	fmt.Println()
	putAsciiArt("                 :::::::::::::::::::::::::::::::::::::                ")
	fmt.Println()
	putAsciiArt("                    :::::::::::::::::::::::::::::::                   ")
	fmt.Println()
	putAsciiArt("                        :::::::::::::::::::::::                       ")
	fmt.Println()
	printUpdateName()
	fmt.Println()
	printOneliner1()
	fmt.Println()
	printOneliner2()
	fmt.Println()
	fmt.Println()
}