import requests


def get(url, name_file):
    res = requests.get(url).text
    name_file = "wordlist\\" + name_file
    with open(name_file, "w") as f:
        f.write(res)

def main():
    list_url = ["GenericBlind.txt", "Generic_ErrorBased.txt", "Generic_TimeBased.txt", "Generic_UnionSelect.txt"]
    url = "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/"
    for u in list_url:
        get(url + u, u)

if __name__ == "__main__":
    main()