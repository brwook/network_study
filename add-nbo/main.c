#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t openConvert(const char *path)
{
    uint32_t res;
    FILE *fp = fopen(path, "r");
    if(fp == NULL)
    {
        fprintf(stderr, "file open error\n");
        return 0;
    }
    fread(&res, 4, 1, fp);
    res = ntohl(res);
    fclose(fp);
    return res;
}

int main(int argc, char *argv[])
{
    uint32_t val_1 = openConvert(argv[1]);
    uint32_t val_2 = openConvert(argv[2]);
    uint32_t sum = val_1 + val_2;
    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", val_1, val_1, val_2, val_2, sum, sum);
    return 0;
}

