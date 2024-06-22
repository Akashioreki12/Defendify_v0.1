import os
import sys
from colorama import Fore, Style, init

# Initialize colorama
init()

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def show_logo():
    logo = f"""
{Fore.GREEN}
  ____          __                   _  _   __        
 |  _ \   ___  / _|  ___  _ __    __| |(_) / _| _   _ 
 | | | | / _ \| |_  / _ \| '_ \  / _` || || |_ | | | |
 | |_| ||  __/|  _||  __/| | | || (_| || ||  _|| |_| |
 |____/  \___||_|   \___||_| |_| \__,_||_||_|   \__, |
                                                |___/                                        
{Style.RESET_ALL}
"""
    print(logo)

def show_menu():
    menu = f"""
{Fore.CYAN}Select a vulnerability test to run:{Style.RESET_ALL}
{Fore.YELLOW}1. XSS Testing{Style.RESET_ALL}
{Fore.YELLOW}2. SQLi Testing{Style.RESET_ALL}
{Fore.YELLOW}3. LFI/RFI Testing{Style.RESET_ALL}
{Fore.YELLOW}4. Exit{Style.RESET_ALL}
"""
    print(menu)

def run_test(choice):
    scripts = {
        '1': 'xss1.py',
        '2': 'sqli1.py',
        '3': 'lfi.py'
    }
    script = scripts.get(choice)
    if script:
        os.system(f"python {script}")
    else:
        print(f"{Fore.RED}Invalid choice, exiting...{Style.RESET_ALL}")
        sys.exit(0)

def main():
    clear_screen()
    show_logo()
    show_menu()
    choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")
    run_test(choice)
    print(f"{Fore.GREEN}Bye!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
