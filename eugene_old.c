/* --------------------------------------------------------------------------------- */
/* Пример example-g03n02.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>

 int main(int argc, char *argv[])
{
    if (argc >= 3){
        if ((strcmp(argv[2], "-key") == 0) && (argc != 4)){
            fprintf(stderr, "3 addition arguments is available and neaded: File_name -key input_key");
            return EXIT_FAILURE;
        }
    }
    else {
        fprintf(stderr, "3 addition arguments is available and neaded: File_name Password Salt");
        return EXIT_FAILURE;
    }

    // инициализируем криптобиблиотеку 
    if (ak_libakrypt_create(NULL) != ak_true){
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    FILE *file; // указатель на файл
    char *message = NULL; // указатель на строку, в которую будет считан текст
    char *out_message = NULL; // указатель на строку, в которую будет записан зашифрованный текст
    long length; // переменная для хранения размера файла

    struct bckey key; // значение секретного ключа
    ak_uint8 iv[8] = {0x01, 0x02, 0x03, 0x04, 0x11, 0xaa, 0x4e, 0x12}; // значение синхропосылки

    // открываем файл для чтения
    file = fopen(argv[1], "r");
    if (file == NULL){
        fprintf(stderr,"can't open file");
        return EXIT_FAILURE;
    }

    // определяем размер файла
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // выделение памяти для хранения содержимого файла
    message = (char *)malloc(length);
    if (message == NULL){
        fprintf(stderr, "malloc error");
        fclose(file);
        return EXIT_FAILURE;
    }
    out_message = (char *)malloc(length);
    if (out_message == NULL){
        fprintf(stderr, "malloc error");
        fclose(file);
        return EXIT_FAILURE;
    }

    // считывание содержимого файла в message
    fread(message, 1, length, file);
    fclose(file);


    // создаем ключ и присваиваем ему значение, выработанное из пароля пользователя 
    ak_bckey_create_oid(&key, ak_oid_find_by_name( "kuznechik"));
    if (strcmp(argv[2], "-key"))
        ak_bckey_set_key(&key, argv[3], 32);
    else
        ak_bckey_set_key_from_password(&key, argv[2], strlen(argv[2]), argv[3], strlen(argv[3]));

    // зашифровываем данные единым фрагментом
    ak_bckey_ctr(&key, message, out_message, length, iv, 8);
    
    // открываем файл на запись
    file = fopen(argv[1], "w");
    if (file == NULL){
        fprintf(stderr, "can't open file");
        return EXIT_FAILURE;
    }

    // записываем в файл
    fprintf(file, out_message);
    fclose(file);
    

    ak_bckey_destroy(&key);
    ak_libakrypt_destroy();

    printf("Input message: %s\n", message);
    printf("Output message: %s\n", out_message);

    free(message);
    free(out_message);

    return EXIT_SUCCESS;
}
