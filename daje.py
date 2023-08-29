import tkinter as tk
from tkinter import filedialog
import requests
import csv
import json
from tkinter import ttk
from tkinter import font

# Function to retrieve information about an IP address from VirusTotal API
def check(ip, index, total):
    api_key = "<YOUR_API_KEY_HERE>"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    result = {
        "index": index,
        "total": total,
        "ip": ip,
        "response": response.json() if response.status_code == 200 else None
    }
    return result

# Function to process the selected CSV file and generate JSON
def process_csv():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if file_path:
        # Open the CSV file for reading
        with open(file_path, 'r') as file:
            csv_reader = csv.reader(file)
            
            # Check if the CSV has a header
            has_header = csv.Sniffer().has_header(file.read(1024))
            file.seek(0)
            
            # Skip the header row if present
            if has_header:
                next(csv_reader)
            
            # Count the total number of IP addresses in the CSV
            total_ips = sum(1 for _ in csv_reader)
            file.seek(0)
            
            # Configure the progress bar
            progress_bar.config(maximum=total_ips)
            progress_bar["value"] = 0
            
            results = []
            
            # Iterate through each row in the CSV
            for index, row in enumerate(csv_reader, start=1):
                if row and row[0] and row[0] != "0.0.0.0":
                    ip_address = row[0]
                    result = check(ip_address, index, total_ips)
                    results.append(result)
                    progress_bar["value"] = index
                    app.update_idletasks()
            
            # Save the results to a JSON file
            output_file = 'results.json'
            with open(output_file, 'w') as json_file:
                json.dump(results, json_file, indent=2)
            
            # Process the generated JSON and display results in the GUI
            generate_and_display_csv_results(output_file)

# Function to generate CSV results and display them in the GUI
def generate_and_display_csv_results(input_json_path):
    output_csv_path = 'output.csv'
    generate_csv(input_json_path, output_csv_path)
    
    # Read the generated CSV file and display results in the GUI
    with open(output_csv_path, 'r') as csv_file:
        csv_reader = csv.reader(csv_file)
        csv_data = list(csv_reader)
        results_text.config(state=tk.NORMAL)
        results_text.delete("1.0", tk.END)
        for row in csv_data:
            if row[1] == 'not ok':
                results_text.insert(tk.END, '\n'.join(row) + '\n', 'red')  # Apply "red" tag
            else:
                results_text.insert(tk.END, '\n'.join(row) + '\n')
        results_text.config(state=tk.DISABLED)

# Function to generate CSV from JSON data
def generate_csv(input_json_path, output_csv_path):
    # Read the JSON data from the provided file
    with open(input_json_path, 'r') as json_file:
        data = json.load(json_file)

    # Define the header for the CSV file
    csv_header = ['ip', 'status', 'country']

    # Initialize a list to store CSV rows
    csv_rows = []

    # Process each entry in the JSON data
    for entry in data:
        ip = entry['ip']
        response = entry['response']

        if response:
            last_analysis_results = response['data']['attributes']['last_analysis_results']

            # Check if all vendors marked it as "clean"
            clean_vendors = all(result['result'] == 'clean' for result in last_analysis_results.values())
            
            if clean_vendors:
                status = 'ok'
            else:
                status = 'not ok'
            
            country = response['data']['attributes']['country']
        else:
            status = 'null'
            country = ''

        csv_rows.append([ip, status, country])

    # Write the CSV file
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_header)
        csv_writer.writerows(csv_rows)

    print(f"CSV file '{output_csv_path}' generated successfully.")

# Create the main application window
app = tk.Tk()
app.title("IP CHECKER")
app.geometry("420x400")  # Set window size to 420p x 400p

# Create a custom style for modern look
style = ttk.Style()
style.theme_use("clam")  # You can change the theme to 'clam', 'alt', 'default', etc.

# Custom font for the application
custom_font = font.Font(family="Helvetica", size=12)
app.option_add("*TButton*Font", custom_font)
app.option_add("*TLabel*Font", custom_font)
app.option_add("*TEntry*Font", custom_font)

# Create a button to initiate file selection and processing
select_button = ttk.Button(app, text="Select CSV File", command=process_csv)
select_button.pack(pady=20)

# Create a progress bar
progress_bar = ttk.Progressbar(app, orient="horizontal", length=300, mode="determinate")
progress_bar.pack()

# Create a text widget to display CSV results
results_text = tk.Text(app, wrap=tk.WORD, state=tk.DISABLED)
results_text.tag_configure('red', foreground='red')  # Define "red" tag with red foreground color
results_text.pack(pady=20, padx=10, fill=tk.BOTH, expand=True)

# Create a scrollbar for the text widget
scrollbar = tk.Scrollbar(app, command=results_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
results_text.config(yscrollcommand=scrollbar.set)

# Start the GUI event loop
app.mainloop()
