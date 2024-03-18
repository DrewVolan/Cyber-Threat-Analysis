import public_funcs as pf

# Файл с вызовом функции для решения второй части

initial_data = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
    ]
api_key = "JLTC3LINW0XHI814LFN7LUAHGW1TC3IPR7SIAR9KZG9AY8FDBT4RZ7LG1OH6ZCAC"

pf.vulners_analise(initial_data, api_key)