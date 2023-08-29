import requests
import csv
import json
import sys

def check(ip, index, total):
    api_key = "5493d1126ded7770a4054e1eee6f1c0f76eda470712cab5ff300220386cea56e"
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

def print_progress_bar(iteration, total, prefix='', length=50, fill='█'):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% Complete')
    sys.stdout.flush()

def generate_csv(input_json_path, output_csv_path):
    with open(input_json_path, 'r') as json_file:
        data = json.load(json_file)

    csv_header = ['ip', 'status', 'country']
    csv_rows = []

    for entry in data:
        ip = entry['ip']
        response = entry['response']

        if response:
            last_analysis_results = response['data']['attributes']['last_analysis_results']
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

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_header)
        csv_writer.writerows(csv_rows)

    print(f"CSV file '{output_csv_path}' generated successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py input.csv output.json output.csv")
        sys.exit(1)
    
    input_csv_path = sys.argv[1]
    output_json_path = sys.argv[2]
    output_csv_path = sys.argv[3]
    
    results = []

    with open(input_csv_path, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)
        total_ips = sum(1 for _ in csv_reader)
        file.seek(0)

        for index, row in enumerate(csv_reader, start=1):
            if row:
                ip_address = row[0]
                result = check(ip_address, index, total_ips)
                results.append(result)
                print_progress_bar(index, total_ips, prefix='Progress:', length=50)
    
    with open(output_json_path, 'w') as json_file:
        json.dump(results, json_file, indent=2)
    
    generate_csv(output_json_path, output_csv_path)
    print("\nResults saved to", output_json_path)
    print(f"CSV file '{output_csv_path}' generated successfully.")
