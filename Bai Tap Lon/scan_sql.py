import requests
from time import time
import argparse
from urllib.parse import urlparse, parse_qsl, urlsplit

# Lấy payload từ file cho vào mảng
def get_payload(name_file):
    payloads = ""
    with open("wordlist/" + name_file, "r") as f:
        payloads = f.read()
    payloads = payloads.split("\n")
    return payloads

# send request
def send_request(url, method, data, payload):
    if method == "get":
        res = requests.get(url + payload)
        return res.text
    elif method == "post":
        data = data.replace('$', payload)
        data = dict(parse_qsl(urlsplit('?' + data).query))
        res = requests.post(url, data = data)
        return res.text

class Detect:
    def __init__(self, url, method, data):
        self.url = url
        self.method = method
        self.data = data
        self.file_name = ["Generic_TimeBased.txt", "Generic_ErrorBased.txt", "Generic_UnionSelect.txt", "Generic_Boolean.txt"]
    
    # Các dạng tấn công
    def time_based(self):
        print("\nĐang thực hiện check SQL Injection Time Based")
        payloads = get_payload(self.file_name[0])

        for payload in payloads:
            before_time = time()
            res = send_request(self.url, self.method, self.data, payload)
            # Nếu thời gian gửi request lớn hơn hoặc bằng 5s thì có thể URL bị Sql Injection dạng Time Based
            if time() - before_time >= 5:
                print("Đã phát hiện URL bị lỗi Sql Injection dạng Time Based")
                print("Payload: " + payload)
                return True
        print("URL không tồn tại lỗ hổng SQL Injection Time Based")
        return False


    def error_based(self):
        print("\nĐang thực hiện check SQL Injection Error based")
        payloads = get_payload(self.file_name[1])

        for payload in payloads:
            res = send_request(self.url, self.method, self.data, payload)
            
            # Nếu response có tồn tại chữ sql hoặc error -> trang web có lỗi SQL Injection
            if "sql" in res or "error" in res:
                print("Đã phát hiện URL tồn tại lỗi Sql Injectioon dạng Error Based")
                print("Payload: " + payload)
                return True
        print("URL không tồn tại lỗ hổng SQL Injection Error Based")
        return False


    def union_based(self):
        print("\nĐang thực hiện check SQL Injection Union Based")
        payloads = get_payload(self.file_name[2])

        for payload in payloads:
            before_res = send_request(self.url, self.method, self.data, "")
            after_res = send_request(self.url, self.method, self.data, payload)
            
            # Nếu độ dài response có gửi theo payload dài hơn response gửi bình thường -> URL có lỗi SQL Injection
            if len(after_res) >= len(before_res):
                print("Đã phát hiện URL tồn tại lỗi Sql Injection dạng Union Based")
                print("Payload: " + payload)
                return True
        print("URL không tồn tại lỗ hổng SQL Injection dạng Union Based")
        return False


    def boolean_based(self):
        print("\nĐang thực hiện check SQL Injection Boolean Based")
        payloads = get_payload(self.file_name[3])

        for payload in payloads:
            before_res = send_request(self.url, self.method, self.data, "")
            after_res = send_request(self.url, self.method, self.data, payload)

            # Nếu độ dài response có gửi theo payload dài hơn response gửi bình thường -> URL có lỗi SQL Injection
            if len(after_res) >= len(before_res):
                print("Đã phát hiện URL tồn tại lỗ hổng Sql Injection dạng Boolean Based")
                print("Payload: " + payload)
                return True
        print("URL không tồn tại lỗ hổng SQL Injection dạng Boolean Based")
        return False


def scan(url, method, data):
    detect = Detect(url, method, data)
    detect.time_based()
    detect.error_based()
    detect.union_based()
    detect.boolean_based()



def main():
    parser = argparse.ArgumentParser(description="Script Scan Sql Injection")
    parser.add_argument('--url', help="Url want scan")
    parser.add_argument('--method', help="Method url want scan")
    parser.add_argument('--data', help="Body data")
    parser.add_argument('--file', help="File Url want scan")
    parser.add_argument('--type', help="Type Attack (time/error/union/boolean)")
    args = parser.parse_args()
    url = args.url
    method = args.method
    data = args.data
    file_name = args.file
    type_attack = args.type
    
    if url != None:
        detect = Detect(url, method, data) 
        if type_attack == "time":
            print("Bắt đầu thực hiện scan SQL Injection Time Based trên " + url)
            detect.time_based()
        elif type_attack == "error":
            print("Bắt đầu thực hiện scan SQL Injection Error Based trên " + url)
            detect.error_based()
        elif type_attack == "union":
            print("Bắt đầu thực hiện scan SQL Injection Union Based trên " + url)
            detect.union_based()
        elif type_attack == "boolean":
            print("Bắt đầu thực hiện scan SQL Injection Boolean Based trên " + url)
            detect.boolean_based()
        else:
            print("Bắt đầu scan " + url)
            scan(url, method, data)
    else:
        urls = ""
        with open(file_name, "r") as f:
            urls = f.read()
        urls = urls.split("\n")
        for url in urls:
            print("\nBắt đầu scan " + url)
            scan(url, method, data)
    
if __name__ == "__main__":
    main()
