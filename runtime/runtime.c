#include <stdio.h>
#include <stdlib.h>
#include <efivar.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// usage: ./runtime <guid string> <var name> <filename>

int main(int argc, char *argv[]) {
    int ret;

    if (argc != 4) {
        printf("usage: %s <.efi name>\n", argv[0]);
        return -1;
    }

    struct stat stat;
    int fd = open(argv[3], O_RDONLY);
    fstat(fd, &stat);

    uint8_t *buf = malloc(stat.st_size);
    read(fd, buf, stat.st_size);

    int attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    efi_guid_t guid;
    efi_str_to_guid(argv[1], &guid);
    char *guid_str;
    efi_guid_to_str(&guid, &guid_str);
    printf("[runtime]: setting var (guid, name, filename), (%s, %s, %s)\n", guid_str, argv[2], argv[3]);
    ret = efi_set_variable(guid, argv[2], buf, stat.st_size, attributes, 777);
    if (ret != 0) {
        printf("failed to set uefi variable, error code %i\n", ret);
        return -1;
    }

    free(buf);
    return 0;
}
