#include <stddef.h>
#include <stdint.h>
#include <assert.h>

struct htbl_entry {
    uint32_t hash;
    uint64_t value;
};

static inline size_t htbl_distance(uint32_t hash, size_t size, size_t idx) {
    size_t bucket = hash & (size-1);
    return bucket <= idx ? (idx - bucket) : (size - (bucket - idx));
}

typedef int (*htbl_cmp)(uint64_t needle, uint64_t haystack, void *userdata);

struct htbl_entry *htbl_insert(
    struct htbl_entry *table,
    size_t size,
    uint32_t hash,
    uint64_t value) {
    assert((size & (size-1)) == 0 && "size must be power of two");
    assert(hash != 0 && "has must be non-zero");

    size_t bucket = hash & (size-1);
    for(size_t probe = 0; probe < size; ++probe) {
        size_t idx = (bucket + probe) & (size-1);

        if(table[idx].hash == 0) {
            // empty bucket found
            table[idx].hash = hash;
            table[idx].value = value;
            return table + idx;
        }

        if(hash == table[idx].hash) {
            // TODO: hash collision
        }

        if(htbl_distance(table[idx].hash, size, idx) <
            htbl_distance(hash, size, idx)) {
            // found an entry in a better position, swap with new entry
            uint32_t old_hash = table[idx].hash;
            uint64_t old_value = table[idx].value;
            table[idx].hash = hash;
            table[idx].value = value;
            hash = old_hash;
            value = old_value;
        }
    }

    return 0; // table is full and has been corrupted by swapping
}

struct htbl_entry *htbl_remove(
    struct htbl_entry *table,
    size_t size,
    struct htbl_entry *entry) {
    assert((size & (size-1)) == 0 && "size must be power of two");
    assert(table <= entry && entry < (table + size) && "entry must be in table");

    entry->hash = 0;
    entry->value = 0;

    size_t idx = entry - table;
    for(size_t i = 0; i < size; ++i) {
        size_t prev = (idx + i) & (size-1);
        size_t next = (idx + i + 1) & (size-1);

        if(htbl_distance(table[next].hash, size, next) == 0) {
            // found an entry with zero distance, stop
            return 0; // XXX: return value
        }

        table[prev].hash = table[next].hash;
        table[prev].value = table[next].value;
    }

    return 0; // XXX: return value?
}

struct htbl_entry *htbl_lookup(
    struct htbl_entry *table,
    size_t size,
    uint32_t hash) {
    assert((size & (size-1)) == 0 && "size must be power of two");
    assert(hash != 0 && "has must be non-zero");

    size_t bucket = hash & (size-1);
    for(size_t probe = 0; probe < size; ++probe) {
        size_t idx = (bucket + probe) & (size-1);

        if(table[idx].hash == 0) {
            // empty entry found, hash is not in this table
            return 0;
        } if(table[idx].hash == hash) {
            // TODO: check for value equality in case of hash collision
            return table + idx;
        }
    }

    return 0;
}

void htbl_resize(
    const struct htbl_entry *old_table,
    size_t old_size,
    struct htbl_entry *new_table,
    size_t new_size) {
    assert((old_size & (old_size-1)) == 0 && "size must be power of two");
    assert((new_size & (new_size-1)) == 0 && "size must be power of two");

    for(size_t i = 0; i < old_size; ++i) {
        if(old_table[i].hash != 0) {
            htbl_insert(new_table, new_size, old_table[i].hash, old_table[i].value);
        }
    }
}

#include <stdio.h>
#include <string.h>

static void print_table(const struct htbl_entry *table, size_t size) {
    for(size_t i = 0; i < size; ++i) {
        printf("(0x%x: 0x%lx)  ", table[i].hash, table[i].value);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    size_t table_size = 8;
    struct htbl_entry table[table_size];
    memset(table, 0, table_size * sizeof(struct htbl_entry));

    print_table(table, table_size);

    htbl_insert(table, table_size, 0x100, 0x1);
    print_table(table, table_size);

    htbl_insert(table, table_size, 0x107, 0x1);
    print_table(table, table_size);

    htbl_insert(table, table_size, 0x107, 0x2);
    print_table(table, table_size);

    htbl_insert(table, table_size, 0x100, 0x2);
    print_table(table, table_size);

    return 0;
}
