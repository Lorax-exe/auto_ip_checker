import requests
import csv
import json
import sys

# Function to retrieve information about an IP address from VirusTotal API
def check(ip, index, total):
    api_key = "<YOUR_API_KEY_HERE>"

    # Construct the API URL for the given IP address
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }

    # Send a GET request to VirusTotal API
    response = requests.get(url, headers=headers)

    # Prepare the result dictionary
    result = {
        "index": index,
        "total": total,
        "ip": ip,
        "response": response.json() if response.status_code == 200 else None
    }

    return result

# Get the CSV file name from command line argument
csv_file = sys.argv[1]
# Define the output JSON file name
output_file = 'results.json'

# List to store results for each IP address
results = []

# Open the CSV file for reading
with open(csv_file, 'r') as file:
    csv_reader = csv.reader(file)
    # Skip the header row if present
    next(csv_reader)

    # Count the total number of IP addresses in the CSV
    total_ips = sum(1 for _ in csv_reader)
    # Reset the file iterator to the beginning
    file.seek(0)

    # Iterate through each row in the CSV
    for index, row in enumerate(csv_reader, start=1):
        if row:  # Check if the row is not empty
            # Extract the IP address (assuming it's in the first column)
            ip_address = row[0]
            # Call the check function to retrieve information
            result = check(ip_address, index, total_ips)
            # Append the result to the list
            results.append(result)
            # Print the progress
            print(f"{index}/{total_ips}")

# Save the results to a JSON file
with open(output_file, 'w') as json_file:
    # Write the results list to the JSON file with indentation for readability
    json.dump(results, json_file, indent=2)

# Print a message to indicate that the results have been saved
print("Results saved to", output_file)

#ex. python3 code.py ip_list.csv
