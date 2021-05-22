logs = {
        "dh": {"dir": "logs/dh/", "data": ["log_dh_128", "log_dh_192", "log_dh_256"], "name": "Diffie-Hellman Experiments"},
        "aes": {"dir": "logs/aes/", "data": ["log_encdec_time_128", "log_encdec_time_192", "log_encdec_time_256"], "name": "AES Encryption/Decryption Time"},
        "no-aes": {"dir": "logs/aes/"},
        "controller_aes": {"dir": "logs/controller/", "data": ["log_encdec_time_128", "log_encdec_time_192", "log_encdec_time_256"]},
        "controller_dh": {"dir": "logs/controller/","data": ["log_dh_128", "log_dh_192", "log_dh_256"]},
        "embedded": {"dir": "logs/embedded/", "data": ["log_encdec_time_128", "log_encdec_time_192", "log_encdec_time_256"]}
}

colors = {
        "log_dh_128": "black",
        "log_dh_192": "red",
        "log_dh_256": "purple",
        "log_encdec_time_128": "black",
        "log_encdec_time_192": "red",
        "log_encdec_time_256": "purple"
}
