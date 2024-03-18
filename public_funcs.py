import os
import zipfile
import requests

# Файл с методами, которые непосредственно надо запускать в main файлах

# Основной метод, который работает в первой части задания
def virus_total_analise(file_path, password, api_key):
    headers = {
        "x-apikey": api_key
    }
    headers_json = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print("Происходит распаковка архива")
    path_unzip = "unzipped_archive"
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(path_unzip, pwd=password)
    
    files = os.listdir(path_unzip)
    print(f"Архив распакован. В нём находятся файлы в количестве {len(files)}")

    for file in files:
        unzipped_file_path = os.path.join(path_unzip, file)
        
        print(f"Начинается анализ файла {unzipped_file_path}")

        print("Происходит отправка файла для анализа")
        with open(file_path, "rb") as file:
            files = {"file": (file_path, file)}
            response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            url_for_analysis = response.json()["data"]["links"]["self"]

        print("Происходит анализ файла")
        response = requests.get(url_for_analysis, headers=headers_json)
        analysis = response.json()

        dict_stats = analysis["data"]["attributes"]["stats"]

        print("Краткий итог")
        for stat_name, stat_value in dict_stats.items():
            print(f"{stat_name}: {stat_value}")

        dict_antivirus = analysis["data"]["attributes"]["results"]

        print("Информация по антивирусам")
        for antivirus, info in dict_antivirus.items():
            print(f"Антивирус: {antivirus}")
            engine_version = info["engine_version"]
            category = info["category"]
            result = info["result"]
            print(f"engine_version: {engine_version}")
            print(f"category: {category}")
            print(f"result: {result}")


        sha256 = analysis["meta"]["file_info"]["sha256"]
        behaviour_summary = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary", headers=headers_json).json()
        behaviour_summary_data = behaviour_summary["data"]

        print("Полученных данных достаточно много. Для примера выведем созданные процессы.")
        processes_created = behaviour_summary_data["processes_created"]
        print(processes_created)

        print("Анализ файла закончен.")