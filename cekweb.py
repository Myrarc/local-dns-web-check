import tkinter as tk
from tkinter import ttk
import dns.resolver
import threading
import time

BLOCKED_IPS = {"36.86.63.185", "99.83.188.13", "114.7.94.105", "202.3.218.139"}
progress_bar = None
timer_id = None  # Global variable to store the timer ID
timer_running = False  # Global variable to keep track of timer state

def is_website_blocked(website, dns_server):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        answers = resolver.resolve(website)

        # Check if the DNS response contains any IP address with network ID starting with 36, 99, or 114
        blocked = any(any(str(answer).startswith(network_id) for network_id in ["36.", "99.", "114."]) for answer in answers)
        return blocked, answers

    except dns.resolver.NXDOMAIN:
        # If the website is blocked, it will raise an NXDOMAIN exception
        return True, None

    except dns.resolver.Timeout:
        print(f"DNS lookup for {website} timed out.")
        return False, None

    except dns.resolver.NoNameservers:
        print(f"No nameservers found to resolve {website}.")
        return False, None

    except dns.resolver.NoAnswer:
        print(f"No DNS answer found for {website}.")
        return False, None

def check_blocked_websites():
    dns_server_name = dns_var.get()
    dns_server = None

    for option in dns_options:
        if option[0] == dns_server_name:
            dns_server = option[1]
            break

    if dns_server is None:
        print("Invalid DNS server selected.")
        return

    websites = website_entry.get("1.0", tk.END).splitlines()

    blocked_websites = []
    allowed_websites = []
    unresolved_websites = []

    for website in websites:
        website = website.strip()
        if not website:
            continue  # Skip empty domains

        blocked, dns_response = is_website_blocked(website, dns_server)
        if dns_response is None:
            unresolved_websites.append(website)
        elif blocked:
            blocked_websites.append(website)
        else:
            resolved_ips = [str(answer) for answer in dns_response]
            allowed_websites.append(f"{website} (IP: {', '.join(resolved_ips)})")

    blocked_text.config(state=tk.NORMAL)
    blocked_text.delete("1.0", tk.END)
    blocked_text.insert(tk.END, "Blocked Websites:\n", "bold")
    blocked_text.insert(tk.END, "\n".join(blocked_websites))
    blocked_text.config(state=tk.DISABLED)

    allowed_text.config(state=tk.NORMAL)
    allowed_text.delete("1.0", tk.END)
    allowed_text.insert(tk.END, "Allowed Websites:\n", "bold")
    allowed_text.insert(tk.END, "\n".join(allowed_websites))
    allowed_text.config(state=tk.DISABLED)

    unresolved_text.config(state=tk.NORMAL)
    unresolved_text.delete("1.0", tk.END)
    unresolved_text.insert(tk.END, "Unresponsive Links:\n", "bold")
    unresolved_text.insert(tk.END, "\n".join(unresolved_websites))
    unresolved_text.config(state=tk.DISABLED)

def process_websites():
    check_blocked_websites()

def update_timer(seconds):
    global timer_running, timer_id
    timer_label.config(text=f"Time Remaining: {seconds // 60:02d}:{seconds % 60:02d}")
    if seconds == 0:
        stop_timer()
    else:
        seconds -= 1
        if timer_running:
            timer_id = app.after(1000, update_timer, seconds)

def start_timer(minutes):
    global progress_bar, timer_running, timer_id  # Declare all global variables
    if progress_bar is not None:
        return  # Prevent starting a new timer if one is already running

    seconds = minutes * 60  # Convert minutes to seconds

    def timer_thread():
        time.sleep(seconds)
        stop_timer()

    timer_thread = threading.Thread(target=timer_thread)
    timer_thread.start()

    # Create the progress bar
    progress_bar = ttk.Progressbar(app, orient="horizontal", length=200, mode="determinate")
    progress_bar.pack(pady=5)

    # Start the visual timer
    timer_id = app.after(0, update_timer, seconds)  # Use 'after' to start the timer

    timer_running = True  # Set the timer_running flag to True
    timer_10_button.config(state=tk.DISABLED)  # Disable the button while timer is running

def stop_progress():
    global progress_bar, timer_id
    if progress_bar is not None:
        progress_bar.destroy()
        check_button.config(state=tk.NORMAL)
        app.after_cancel(timer_id)  # Cancel the timer after
        progress_bar = None

        # Call the website check function after the progress bar is destroyed
        process_websites()

    # Restart the 10-minute timer after a few seconds
    app.after(3000, lambda: start_timer(10))

def stop_timer():
    global timer_running, timer_id
    if timer_running:
        app.after_cancel(timer_id)  # Cancel the timer after
        stop_progress()
        timer_running = False
        timer_10_button.config(state=tk.NORMAL)  # Enable the button after stopping timer
        timer_label.config(text="Time Remaining: 00:00")  # Reset the timer label

app = tk.Tk()
app.title("Cek Web")
app.geometry("800x700")

default_font = ("Arial", 10)
app.option_add("*Font", default_font)

dns_options = [("Telkomsel", "203.130.193.74"),("Telkomsel 2", "202.134.0.155"), ("XL", "112.215.198.254")]
dns_var = tk.StringVar()
dns_var.set(dns_options[0][0])  # Set the default DNS server to the first option

dns_label = tk.Label(app, text="DNS yang digunakan:", font=("Arial", 12, "bold"))
dns_label.pack(pady=5)

dns_dropdown = ttk.Combobox(app, textvariable=dns_var, values=[option[0] for option in dns_options])
dns_dropdown.pack()

website_label = tk.Label(app, text="Link Web (1 per baris):", font=("Arial", 12, "bold"))
website_label.pack(pady=5)

timer_label = tk.Label(app, text="", font=("Arial", 12))
timer_label.pack()

timer_10_button = tk.Button(app, text="10 Minutes", command=lambda: start_timer(10), font=("Arial", 12))
timer_10_button.pack(pady=5)

website_entry = tk.Text(app, height=10, width=50, font=default_font)
website_entry.pack()

check_button = tk.Button(app, text="Check", command=process_websites, font=("Arial", 12))
check_button.pack(pady=10)

output_frame = tk.Frame(app)
output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

blocked_text = tk.Text(output_frame, height=10, width=30, wrap=tk.WORD, state=tk.DISABLED, font=default_font)
blocked_text.tag_configure("bold", font=("Arial", 12, "bold"))
blocked_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

allowed_text = tk.Text(output_frame, height=10, width=30, wrap=tk.WORD, state=tk.DISABLED, font=default_font)
allowed_text.tag_configure("bold", font=("Arial", 12, "bold"))
allowed_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

unresolved_text = tk.Text(output_frame, height=10, width=30, wrap=tk.WORD, state=tk.DISABLED, font=default_font)
unresolved_text.tag_configure("bold", font=("Arial", 12, "bold"))
unresolved_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

app.mainloop()
