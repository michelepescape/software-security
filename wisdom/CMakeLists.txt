cmake_minimum_required(VERSION 3.7)

# Dai un nome al tuo progetto
project(WisdomPatcher)

# 1. Trova il pacchetto DynamoRIO (i percorsi li daremo da riga di comando)
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package not found. Assicurati di impostare -DDynamoRIO_DIR")
endif()

# 2. Definisci il tuo client come una libreria condivisa (.so)
# "patch_client" sarà il nome del file generato (patch_client.so)
# "client.c" è il nome del tuo file sorgente
add_library(patch_client_libc SHARED client_wisdom_libc.c)

# 3. Applica la "magia" di DynamoRIO (imposta automaticamente tutti i flag del compilatore necessari)
configure_DynamoRIO_client(patch_client_libc)

# 4. Linka le estensioni di cui abbiamo bisogno (drmgr e drwrap)
use_DynamoRIO_extension(patch_client_libc drmgr)
use_DynamoRIO_extension(patch_client_libc drwrap)
