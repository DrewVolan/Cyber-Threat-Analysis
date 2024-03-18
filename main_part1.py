import public_funcs as pf

# Файл с вызовом функции для решения первой части

path = "protected_archive.zip"
password = b"netology"
api_key = "15c5f0e18466690b7bdcc7a0c39aa07a32796be6f73904219782aa0743736854"

pf.virus_total_analise(path, password, api_key)