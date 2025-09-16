#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <ctype.h>  

// ==================== Структуры и функции WiresharkParser ====================

#define MAX_LINE_LENGTH 1024

void extract_hex_bytes(const char *line, FILE *outputFile) {
    const char *ptr = line;
    int byteCount = 0;
    char hexByte[3] = {0};
    
    while (*ptr != '\0') {
        // Ищем два подряд hex-символа
        if (isxdigit(*ptr) && isxdigit(*(ptr+1))) {
            // Извлекаем байт
            hexByte[0] = *ptr;
            hexByte[1] = *(ptr+1);
            hexByte[2] = '\0';
            
            // Записываем в файл
            if (byteCount > 0) {
                fprintf(outputFile, " ");
            }
            fprintf(outputFile, "%s", hexByte);
            byteCount++;
            
            ptr += 2; // Перемещаемся на два символа вперед
        } else {
            ptr++; // Перемещаемся на один символ вперед
        }
    }
    
    if (byteCount > 0) {
        fprintf(outputFile, "\n");
    }
}

int is_hex_data_line(const char *line) {
    const char *ptr = line;
    int hexPairs = 0;
    
    while (*ptr != '\0') {
        if (isxdigit(*ptr) && isxdigit(*(ptr+1))) {
            hexPairs++;
            ptr += 2;
        } else {
            ptr++;
        }
    }
    
    return hexPairs >= 4; // Считаем строкой с данными, если есть хотя бы 4 байта
}

int wireshark_parser(const char* filename) {
    FILE *inputFile = fopen(filename, "r");
    if (inputFile == NULL) {
        printf("Ошибка открытия файла %s\n", filename);
        return 1;
    }

    FILE *outputFile = fopen("filtered.txt", "w");
    if (outputFile == NULL) {
        perror("Ошибка создания выходного файла");
        fclose(inputFile);
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    int lineCount = 0;
    int dataLinesFound = 0;

    printf("=== WIRESHARK PARSER ===\n");
    printf("Обработка файла %s...\n", filename);

    while (fgets(line, sizeof(line), inputFile) != NULL) {
        lineCount++;
        
        // Удаляем символ новой строки
        line[strcspn(line, "\n")] = '\0';
        
        // Пропускаем пустые строки
        if (strlen(line) == 0) {
            continue;
        }
        
        // Пропускаем строки, которые начинаются с "Frame" (заголовки кадров)
        if (strncmp(line, "Frame", 5) == 0) {
            continue;
        }
        
        // Пропускаем строки, которые содержат только текстовое представление
        // (после байтов обычно идет текст в ASCII)
        int hasTextPart = 0;
        const char *ptr = line;
        while (*ptr != '\0') {
            if (!isxdigit(*ptr) && *ptr != ' ' && *ptr != '\t') {
                hasTextPart = 1;
                break;
            }
            ptr++;
        }
        
        if (hasTextPart) {
            // Это может быть строка с байтами и текстом, проверим
            if (is_hex_data_line(line)) {
                printf("Обрабатываем строку %d: %s\n", lineCount, line);
                extract_hex_bytes(line, outputFile);
                dataLinesFound++;
            }
            continue;
        }
        
        // Обрабатываем строки, содержащие только hex-байты
        if (is_hex_data_line(line)) {
            printf("Обрабатываем строку %d: %s\n", lineCount, line);
            extract_hex_bytes(line, outputFile);
            dataLinesFound++;
        }
    }

    fclose(inputFile);
    fclose(outputFile);

    printf("\nОбработка завершена!\n");
    printf("Обработано строк: %d\n", lineCount);
    printf("Найдено строк с данными: %d\n", dataLinesFound);
    printf("Результат сохранен в filtered.txt\n\n");
    
    return 0;
}

// ==================== Структуры и функции RSPparser ====================

// Структура для хранения команд и счетчиков
typedef struct {
    const char* name; // Имя команды RSP
    int count;        // Счетчик использований
} RspCommandCounter;

// Словарь
RspCommandCounter command_dictionary[] = {
    {"qSupported", 0},
    {"qTStatus", 0},
    {"qXfer", 0},
    {"qRcmd", 0},
    {"QStartNoAckMode", 0},
    {"vMustReplyEmpty", 0},
    {"vCont", 0},
    {"?", 0},
    {"g", 0},
    {"G", 0},
    {"m", 0},
    {"M", 0},
    {"c", 0},
    {"s", 0},
    {"!", 0},
    {"Hg", 0},
    {"Hc", 0},
    {"OK", 0},
    {"E", 0},
    {"S", 0},
    {"T", 0},
    {"W", 0},
    {"O", 0},
    {"_UNKNOWN_", 0}
};

#define DICTIONARY_SIZE (sizeof(command_dictionary) / sizeof(command_dictionary[0]))

void increment_command_count(const char* cmd) {
    for (size_t i = 0; i < DICTIONARY_SIZE - 1; i++) {
        const char* dict_name = command_dictionary[i].name;
        size_t name_len = strlen(dict_name);
        if (strncmp(cmd, dict_name, name_len) == 0) {
            command_dictionary[i].count++;
            return;
        }
    }
    command_dictionary[DICTIONARY_SIZE - 1].count++;
}

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Функция для преобразования HEX-строки в бинарные данные
unsigned char* hex_to_bin(const char* hex_str, size_t* output_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Ошибка: Длина HEX-строки должна быть четной.\n");
        return NULL;
    }
    
    *output_len = hex_len / 2;
    unsigned char* bin_data = malloc(*output_len);
    if (bin_data == NULL) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для бинарных данных.\n");
        return NULL;
    }
    
    for (size_t i = 0, j = 0; i < hex_len; i += 2, j++) {
        int high_nibble = hex_char_to_int(hex_str[i]);
        int low_nibble = hex_char_to_int(hex_str[i+1]);
        
        if (high_nibble == -1 || low_nibble == -1) {
            fprintf(stderr, "Ошибка: Входная строка содержит не-HEX символы.\n");
            free(bin_data);
            return NULL;
        }
        
        bin_data[j] = (high_nibble << 4) | low_nibble;
    }
    
    return bin_data;
}

// Функция для проверки контрольной суммы RSP-пакета
int verify_checksum(const unsigned char* packet, size_t length) {
    if (length < 4) return 0; // Минимальная длина пакета: $ + данные + # + 2 символа checksum
    
    unsigned char calculated = 0;
    for (size_t i = 1; i < length - 3; i++) {
        calculated += packet[i];
    }
    
    char checksum_str[3];
    checksum_str[0] = packet[length - 2];
    checksum_str[1] = packet[length - 1];
    checksum_str[2] = '\0';
    
    unsigned char received;
    sscanf(checksum_str, "%02hhx", &received);
    
    return calculated == received;
}

// Функция для поиска подстроки в строке (аналог strstr с возвратом индекса)
int find_substring(const char* str, const char* substr) {
    char* pos = strstr(str, substr);
    if (pos == NULL) return -1;
    return pos - str;
}

// Функция для извлечения RSP-пакетов из HEX-строки
void extract_rsp_packets_from_hex(const char* hex_str, char** output_str) {
    size_t len = strlen(hex_str);
    size_t cursor = 0;
    *output_str = malloc(1);
    (*output_str)[0] = '\0';
    size_t output_size = 0;

    while (cursor < len) {
        // Ищем начало пакета - "$" в HEX: "24"
        int dollar_pos = find_substring(hex_str + cursor, "24");
        if (dollar_pos == -1) break;
        dollar_pos += cursor;

        // Ищем конец пакета - "#" в HEX: "23"
        int hash_pos = find_substring(hex_str + dollar_pos, "23");
        if (hash_pos == -1) break;
        hash_pos += dollar_pos;

        // Проверяем, что после "#" есть два HEX-символа для контрольной суммы
        if (hash_pos + 5 >= len) break; // Нужно 4 HEX-символа для контрольной суммы

        // Извлекаем HEX-представление пакета (включая контрольную сумму)
        size_t packet_hex_len = hash_pos - dollar_pos + 6; // 6 = 2 для '#' + 4 для контрольной суммы
        char* packet_hex = malloc(packet_hex_len + 1);
        strncpy(packet_hex, hex_str + dollar_pos, packet_hex_len);
        packet_hex[packet_hex_len] = '\0';

        // Преобразуем HEX в бинарные данные для проверки контрольной суммы
        size_t bin_len;
        unsigned char* bin_packet = hex_to_bin(packet_hex, &bin_len);
        free(packet_hex);

        if (bin_packet == NULL) {
            cursor = dollar_pos + 2;
            continue;
        }

        if (verify_checksum(bin_packet, bin_len)) {
            // Пакет валиден, извлекаем команду
            size_t cmd_len = bin_len - 4; // Исключаем '$', '#', и два байта контрольной суммы
            char* command = malloc(cmd_len + 1);
            memcpy(command, bin_packet + 1, cmd_len); // Пропускаем '$'
            command[cmd_len] = '\0';
            increment_command_count(command);
            free(command);

            // Преобразуем пакет в читаемый вид
            char* printable_packet = malloc(bin_len * 4 + 1);
            size_t pos = 0;
            for (size_t i = 0; i < bin_len; i++) {
                // Отображаем '$' и '#' как обычные символы, а не как escape-последовательности
                if (bin_packet[i] == '$' || bin_packet[i] == '#') {
                    printable_packet[pos++] = bin_packet[i];
                }
                else if (isprint(bin_packet[i])) {
                    printable_packet[pos++] = bin_packet[i];
                } else {
                    pos += sprintf(printable_packet + pos, "\\x%02X", bin_packet[i]);
                }
            }
            printable_packet[pos] = '\0';

            // Добавляем пакет к выходной строке
            *output_str = realloc(*output_str, output_size + strlen(printable_packet) + 1);
            strcpy(*output_str + output_size, printable_packet);
            output_size += strlen(printable_packet);
            free(printable_packet);
        }

        free(bin_packet);
        cursor = hash_pos + 6; // Перемещаем курсор после обработанного пакета
    }
}

void print_results() {
    printf("\n--- Статистика использования команд RSP ---\n");
    printf("-----------------------------------------\n");
    int total_packets = 0;
    for (size_t i = 0; i < DICTIONARY_SIZE; i++) {
        if (command_dictionary[i].count > 0) {
            printf("Команда: %-20s | Использований: %d\n",
                command_dictionary[i].name,
                command_dictionary[i].count);
            total_packets += command_dictionary[i].count;
        }
    }
    printf("-----------------------------------------\n");
    printf("Всего распознанных пакетов: %d\n", total_packets);
    printf("-----------------------------------------\n");
}

int rsp_parser(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Ошибка при открытии файла");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Ошибка: Файл пуст или не может быть прочитан.\n");
        fclose(file);
        return 1;
    }

    char* file_content = malloc(file_size + 1);
    if (file_content == NULL) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для содержимого файла.\n");
        fclose(file);
        return 1;
    }

    fread(file_content, 1, file_size, file);
    file_content[file_size] = '\0';
    fclose(file);

    // Очистка HEX-строки от не-HEX символов
    char* clean_hex_input = malloc(file_size + 1);
    if (clean_hex_input == NULL) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для очищенной строки.\n");
        free(file_content);
        return 1;
    }

    int clean_index = 0;
    for (int i = 0; file_content[i] != '\0'; i++) {
        if (isxdigit((unsigned char)file_content[i])) {
            clean_hex_input[clean_index++] = file_content[i];
        }
    }
    clean_hex_input[clean_index] = '\0';
    free(file_content);

    printf("=== RSP PARSER ===\n");
    printf("Очищенная HEX строка из файла: %s\n", clean_hex_input);

    // Извлечение RSP-пакетов из HEX-строки
    char* printable_output = NULL;
    extract_rsp_packets_from_hex(clean_hex_input, &printable_output);
    free(clean_hex_input);

    if (printable_output != NULL && strlen(printable_output) > 0) {
        printf("Преобразованная ASCII строка: %s\n", printable_output);
    } else {
        printf("В файле не найдено валидных RSP-пакетов.\n");
    }
    free(printable_output);

    print_results();
    return 0;
}

// ==================== Главная функция ====================

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Использование: %s <имя_файла.c>\n", argv[0]);
        fprintf(stderr, "Поддерживаемые расширения: .c\n");
        return 1;
    }

    const char* filename = argv[1];
    
    // Проверяем расширение .c
    if (strlen(filename) < 2 || strcmp(filename + strlen(filename) - 2, ".c") != 0) {
        printf("Ошибка: файл должен иметь расширение .c\n");
        return 1;
    }

    // Шаг 1: Запускаем WiresharkParser
    printf("=== ЗАПУСК WIRESHARK PARSER ===\n");
    if (wireshark_parser(filename) != 0) {
        return 1;
    }

    // Шаг 2: Запускаем RSPparser на обработанных данных
    printf("=== ЗАПУСК RSP PARSER ===\n");
    if (rsp_parser("filtered.txt") != 0) {
        return 1;
    }

    printf("\n=== ОБРАБОТКА ЗАВЕРШЕНА ===\n");
    return 0;
}