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
        if ((strcmp(argv[2], "-key") == 0) && ((argc != 4) && (argc != 3))){
            printf("3 addition arguments is available and neaded: File_name -key input_key\n");
            return EXIT_FAILURE;
        }
    }
    else {
        printf("3 addition arguments is available and neaded: File_name Password Salt\n");
        return EXIT_FAILURE;
    }

    // инициализируем криптобиблиотеку 
    if (ak_libakrypt_create(NULL) != ak_true){
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    ak_uint8 const_key[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38
    };

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
    if ((strcmp(argv[2], "-key") == 0) && (argc == 4)){
            ak_uint8 input_key[32];
            size_t key_size = sizeof(input_key);

            ak_hexstr_to_ptr(argv[3], input_key, key_size, 0);
            
            printf("Key: ");

            for (size_t i=0; i < key_size; ++i){
                printf("%02x", input_key[i]);
            }

            printf("\n");
            ak_bckey_set_key(&key, input_key, 32);
        }
    else if ((strcmp(argv[2], "-key") == 0) && (argc == 3))
        ak_bckey_set_key(&key, const_key, 32);
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