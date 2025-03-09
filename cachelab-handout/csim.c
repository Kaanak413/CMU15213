#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <strings.h>

#include "cachelab.h"


void parse(int *s_ptr, int *S_ptr, int *E_ptr, int *b_ptr, int *B_ptr,
    char **trace_file_ptr, int argc, char *argv[]) {
int opt;
while ((opt = getopt(argc, argv, "s:E:b:t:")) != -1) {
 switch (opt) {
     case 's':
         *s_ptr = atoi(optarg);
         *S_ptr =  *s_ptr;
         break;
     case 'E':
         *E_ptr = atoi(optarg);
         break;
     case 'b':
         *b_ptr = atoi(optarg);
         *B_ptr =  *b_ptr;
         break;
     case 't':
         *trace_file_ptr = optarg;
         break;
     default:
         printf("Error: Unrecognized program option!");
         exit(1);
 }
}

if (*S_ptr <= 0 || *E_ptr <= 0 || *B_ptr <= 0 || trace_file_ptr == NULL) {
 printf("Error: Invalid program option");
 exit(1);
}
}

FILE * openFile(char *path, char* mode) {
    FILE * file = fopen(path, mode);
    if (!file) {
        printf("Error: Cannot open file %s", path);
        exit(1);
    }

    return file;
}


typedef struct cacheBlock
{
    int validBit;
    long long tagNumber;
    unsigned data;
    int lru_counter;
}CpuCacheBlock;


typedef struct cache{
    unsigned setsize;
    unsigned associvity;
    unsigned blockSize;
    
    unsigned totalblock;
    unsigned totalAssoc;
    unsigned totalSet;

    CpuCacheBlock** mat;

    int hitCount;
    int missCount;
    int evictionCount;

}CpuCache;



CpuCache* createCache(unsigned setSize,unsigned associvity,unsigned blockSize);
int cacheLoad(CpuCache* cache,int setBits,int tagBits,int* hitCount,int *missCount,int* evictCount);


int main(int argc, char* argv[])
{
    int s, S, E, b, B;
    char *file_path;

    int set;
    CpuCache *cache;
    FILE *file;
    char *operationString;
    long long address;  // long long used for 64-bit address
    int size;
    long long unsigned set_mask, set_bits, tag_bits;
    int hit, miss, evict;
    int time;
    char operation;

    // 1. Parse command line options
    s = S = E = b = B = 0;
    file_path = NULL;

    parse(&s, &S, &E, &b, &B, &file_path, argc, argv);
    printf("s = %d, E = %d, b = %d, file = \"%s\"\n", s, E, b, file_path);
    cache = createCache(S,E,B);
    file = openFile(file_path, "r");

    operationString = malloc(sizeof(char) * 2);
    set_mask = ~((-1) << s);
    hit = miss = evict = 0;
    time = 0;
    while (fscanf(file, "%s %llx,%d\n", operationString, &address, &size) != EOF) {
        time++;
        set_bits = set_mask & (address >> b);
        tag_bits = address >> (b + s);
        set = set_bits;
        operation = *operationString;
        // printf("Set%d: , tag:%lld",set,tag_bits);
        if (operation=='M')
        {
            cacheLoad(cache,set,tag_bits,&hit,&miss,&evict);
            hit++;
        }
        else if((operation == 'L') |(operation == 'S'))
        {
            cacheLoad(cache,set,tag_bits,&hit,&miss,&evict);
        }
        
    
    }    

    printSummary(hit, miss, evict);
    return 0;
}




CpuCache* createCache(unsigned setSize, unsigned associvity, unsigned blockSize)
{
    CpuCache* c = (CpuCache*)malloc(sizeof(CpuCache)); // Allocate memory for CpuCache
    
    if (c == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    c->setsize = setSize;
    c->associvity = associvity;
    c->blockSize = blockSize;

    c->totalblock = blockSize;
    c->totalAssoc = associvity;
    c->totalSet = 1 << c->setsize ;
    
    // Allocate memory for the 2D matrix
    c->mat = (CpuCacheBlock**)malloc(c->totalSet * sizeof(CpuCacheBlock*));
    
    if (c->mat == NULL) {
        free(c);
        return NULL;
    }

    // Allocate memory for each row in the 2D matrix
    for (size_t i = 0; i < c->totalSet; i++) {
        c->mat[i] = (CpuCacheBlock*)malloc(c->totalAssoc * sizeof(CpuCacheBlock));
        
        if (c->mat[i] == NULL) {
            // Handle failure to allocate memory for a row
            for (size_t j = 0; j < i; j++) {
                free(c->mat[j]);
            }
            free(c->mat);
            free(c);
            return NULL;
        }
    }

    for (size_t i = 0; i < c->totalSet; i++) {
        for (size_t j = 0; j < c->totalAssoc; j++) {
            c->mat[i][j].validBit = 0; 
            c->mat[i][j].lru_counter = 0;
        }
    }

    return c;
}
int cacheLoad(CpuCache* cache, int setBits, int tagBits, int* hitCount, int* missCount, int* evictCount) {
    int setIndex = setBits;
    int lruIndex = 0, maxLRU = -1;

    // 1. Check for a hit
    for (size_t i = 0; i < cache->associvity; i++) {
        if (cache->mat[setIndex][i].validBit && cache->mat[setIndex][i].tagNumber == tagBits) {
            // HIT: Update LRU
            for (size_t j = 0; j < cache->associvity; j++) {
                if (cache->mat[setIndex][j].validBit && cache->mat[setIndex][j].lru_counter < cache->mat[setIndex][i].lru_counter) {
                    cache->mat[setIndex][j].lru_counter++;
                }
            }
            cache->mat[setIndex][i].lru_counter = 0; // Reset LRU for this block
            (*hitCount)++;
            return 1; // Cache hit
        }
    }

    (*missCount)++;

    // 2. Cache miss: Find an empty slot
    for (size_t i = 0; i < cache->associvity; i++) {
        if (!cache->mat[setIndex][i].validBit) {
            // Empty block found
            cache->mat[setIndex][i].validBit = 1;
            cache->mat[setIndex][i].tagNumber = tagBits;
            cache->mat[setIndex][i].lru_counter = 0;
            
            // Update LRU counters for others
            for (size_t j = 0; j < cache->associvity; j++) {
                if (cache->mat[setIndex][j].validBit && j != i) {
                    cache->mat[setIndex][j].lru_counter++;
                }
            }

            return 0; // Cache miss
        }
        if (cache->mat[setIndex][i].lru_counter > maxLRU) {
            maxLRU = cache->mat[setIndex][i].lru_counter;
            lruIndex = i;
        }
    }

    if (cache->mat[setIndex][lruIndex].validBit) {
        (*evictCount)++;
    }

    // Evict the LRU block and insert the new block
    cache->mat[setIndex][lruIndex].tagNumber = tagBits;
    cache->mat[setIndex][lruIndex].validBit = 1;
    cache->mat[setIndex][lruIndex].lru_counter = 0;

    // Update LRU counters for others
    for (size_t i = 0; i < cache->associvity; i++) {
        if (cache->mat[setIndex][i].validBit && i != lruIndex) {
            cache->mat[setIndex][i].lru_counter++;
        }
    }

    return 0; // Cache miss with eviction
}

