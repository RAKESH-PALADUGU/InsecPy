# Libraries 
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
import socket as s
import requests
from urllib.parse import urlparse
import os

#-------------------------------------------------------------------------------------------------------------------------------------------
console = Console()
#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to get the website's IP address
def get_ip_address(host):
    try:
        ip_address = s.gethostbyname(host)
        return ip_address
    except s.gaierror:
        return "Invalid domain or unable to resolve IP."

#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to check open ports
def check_open_ports(domain, ports):
    open_ports = []
    ip_address = get_ip_address(domain)
    if "Invalid domain" in ip_address:
        return "Cannot check ports for an invalid domain."

    for port in ports:
        try:
            with s.create_connection((ip_address, port), timeout=2):
                open_ports.append(port)
        except (s.timeout, ConnectionRefusedError):
            pass
    return open_ports if open_ports else "No open ports found."

#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to check for SQL Injection
def check_sql_injection(url):

    payloads = [ "'", "\"", "1=1", "1' OR '1'='1", "' OR 1=1 --", "\" OR 1=1 --", "' OR '1'='1' --", 
                "' OR '1'='1' #", "' OR 1=1 #", "\" OR 1=1 #", "' OR ''='", "' OR 1=1; --", "' AND SLEEP(5) --" ]

    console.print(f"\n\n[+] Checking for SQL Injection in [blue]{website}[/blue] :\n")
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=20)  # Set timeout for time-based SQLi
            if response.status_code == 200:
                if "error" in response.text.lower() or response.elapsed.total_seconds() > 5:
                    console.print(f"[red]Potential SQL Injection vulnerability found with payload: {payload}[/red]")
                    vulnerable = True
        except Exception as e:
            console.print(f"[red]Error during SQL Injection check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No SQL Injection vulnerabilities found![/green]")

#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to check for XSS
def check_xss(url):

    payloads = [ "<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>", '"><script>alert("XSS")</script>', "';!--\"<XSS>=&{()}", 
                "<img src=x onerror=alert('XSS')>", "<iframe src=javascript:alert('XSS')>", "<svg onload=alert('XSS')>", "<body onload=alert('XSS')>" ]
    
    console.print(f"\n\n[+] Checking for XSS in [blue]{website}[/blue] :\n")
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=20)
            if response.status_code == 200 and payload in response.text:
                console.print(f"[red]Potential XSS vulnerability found with payload: {payload}[/red]")
                vulnerable = True
        except Exception as e:
            console.print(f"[red]Error during XSS check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No XSS vulnerabilities found![/green]")

#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to check for Open Redirect
def check_open_redirect(url):
    payloads = [url]
    console.print(f"\n\n[+] Checking for Open Redirects in [blue]{website}[/blue] :\n")
    vulnerable = False

    for payload in payloads:
        test_url = f"{url}?redirect={payload}"
        try:
            response = requests.get(test_url, allow_redirects=True)
            # Parse the final URL after all redirections
            final_url = response.url
            initial_domain = urlparse(url).netloc
            final_domain = urlparse(final_url).netloc

            # Check if the final redirected domain is different from the initial domain
            if initial_domain != final_domain:
                console.print(f"[red]❗ Potential Open Redirect vulnerability found with payload: {payload}[/red]")
                console.print(f"[red]Redirected to: {final_url}[/red]")
                vulnerable = True
                console.print("[bold red]Open Redirect vulnerability detected![/bold red]")
        except Exception as e:
            console.print(f"[red]Error during Open Redirect check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No Open Redirect vulnerabilities found![/green]")

#-------------------------------------------------------------------------------------------------------------------------------------------

# Function to check Cookie Security
def check_cookie_security(url):
    console.print(f"\n\n[+] Checking for Cookie Security in [blue]{website}[/blue] :\n")
    try:
        response = requests.get(url)
        cookies = response.cookies
        vulnerable = False
        for cookie in cookies:
            console.print(f"Cookie: {cookie.name}, Secure: {cookie.secure}, HttpOnly: {'HttpOnly' in cookie._rest.keys()}")
            if not cookie.secure:
                console.print(f"[red]Warning: Cookie {cookie.name} is not marked as Secure![/red]")
                vulnerable = True
            if 'HttpOnly' not in cookie._rest.keys():
                console.print(f"[red]Warning: Cookie {cookie.name} is not marked as HttpOnly![/red]")
                vulnerable = True

        if not vulnerable:
            console.print("[green]No issues found with Cookie Security![/green]")

    except Exception as e:
        console.print(f"[red]Error checking cookies: {e}[/red]")

#-------------------------------------------------------------------------------------------------------------------------------------------



# Main function to perform vulnerability scan
def vulnerability_scan(domain):
    
    title_screen(count)

    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = "http://" + domain.lower()
    else:
        url = domain.lower()

    #---------------------------------------------------------------------------------------------------------------------------------------
    
    console.print(f"\n\n\n----- Basic Information of [blue]{domain}[/blue] -----\n", justify = "center")

    # For IP_address 
    console.print(f"\n[+] IP address for [blue]{domain}[/blue]  :  [bold green]{get_ip_address(domain)}[/bold green]")

    # For Identifying Commonly known open ports
    common_ports = [ 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 995, 993, 3306, 3389, 8080 ]
    console.print(f"\n[+] Open Ports for [blue]{domain}[/blue]  :  [bold green]{check_open_ports(domain, common_ports)}[/bold green]\n\n")

    #---------------------------------------------------------------------------------------------------------------------------------------

    console.print(f"\n\n----- Performing Vulnerability Scan on [blue]{domain}[/blue] -----\n", justify = "center")

    # Run the vulnerability tests
    check_sql_injection(url)
    check_xss(url)
    check_open_redirect(url)
    check_cookie_security(url)

    console.print(f"\n\n[green]Vulnerability scan for [blue]{website}[/blue] is completed![/green]\n\n", justify = "center")
    
    


#-------------------------------------------------------------------------------------------------------------------------------------------


# Initialize the console
def title_screen(count):
    os.system('cls') if os.name == 'nt' else os.system('clear')

    # Main title
    title = Text("InsecPy", style="bold white", justify="center")

    # Subtitle
    if count == 1 :
        subtitle = Text("A simple Python tool designed to perform a website vulnerability scan", style="bold green", justify="center")
    else :
        subtitle = Text("A simple Python tool designed to perform a website vulnerability scan", style="bold yellow", justify="center")

    # Combine title and subtitle with new lines
    combined_text = Text("\n", style="bold white")
    combined_text.append(title)
    combined_text.append("\n\n", style="bold white")
    combined_text.append(subtitle)

    # Create a panel with the combined text
    panel = Panel.fit(combined_text)

    # Print the panel to the console, centered
    console.print(panel, justify="center")


#-------------------------------------------------------------------------------------------------------------------------------------------


# Prompt the user and display the entered details
if __name__ == "__main__":
    
     while True:
        count = 1
        title_screen(count)
        count +=1
            
        website = console.input("\n[yellow]Enter a Domain or Website Host name [ example.com ] : [/yellow]")
        
        vulnerability_scan(website)
        
        # Ask the user if they want to run another option or exit
        again = Prompt.ask(f"\nDo you want to run another scan",choices=[ "Y", "N" ], default="N")
        if again.upper() != "Y" or again.upper() == "N" :
            console.print("\n[bold yellow]Exiting now.... Stay secure![/bold yellow]\nThank You for using [bold blue]InsecPy[/bold blue]", justify="center")
            break



#-------------------------------------------------------------------------------------------------------------------------------------------
