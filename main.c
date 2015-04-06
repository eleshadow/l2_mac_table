#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define MAC_ADDR_LEN 6
#define MAC_TABLE_SIZE 1024 

#define OK 0
#define ERROR -1

#define CANT_FIND 0
#define INIT_TIME 60

struct mac_table_entry
{
    uint8_t port;
    uint8_t time;
    uint8_t mac_addr[MAC_ADDR_LEN];
}mac_table[MAC_TABLE_SIZE];

pthread_mutex_t mac_table_lock;

void mac_table_age_thread(void *ptr)
{
    while (1)
    {
        int i = 0;

        pthread_mutex_lock(&mac_table_lock);
        printf("update mac table age\n");
        for (i=0; i<MAC_TABLE_SIZE; i++)
        {
            if (mac_table[i].port)
            {
                mac_table[i].time -= 10;
            }

            if (mac_table[i].time <= 0)
            {
                memset(&mac_table[i], 0, sizeof(struct mac_table_entry));
            }
        }
        pthread_mutex_unlock(&mac_table_lock);

        sleep(10);
    }
}

int mac_address_hash(uint8_t *mac_addr)
{
    return mac_addr[MAC_ADDR_LEN-1]*256 + mac_addr[MAC_ADDR_LEN-2];    
}

int insert_mac_addr(uint8_t port, uint8_t *mac_addr)
{
    int index = 0;

    index = mac_address_hash(mac_addr);
    if (mac_table[index].port == 0 || mac_table[index].port != port)
    {
        mac_table[index].port = port;
        memcpy(mac_table[index].mac_addr, mac_addr, MAC_ADDR_LEN);
    }

    pthread_mutex_lock(&mac_table_lock);
    mac_table[index].time = INIT_TIME; 
    pthread_mutex_unlock(&mac_table_lock);

    return OK;
}

uint8_t get_output_port(uint8_t in_port, uint8_t *src_mac, uint8_t *dst_mac)
{
    int index = 0;

    insert_mac_addr(in_port, src_mac);

    index = mac_address_hash(dst_mac);
    if (!memcmp(dst_mac, mac_table[index].mac_addr, MAC_TABLE_SIZE))
    {
        return mac_table[index].port;
    }

    return CANT_FIND;
}

int init_global_mac_table(void)
{
    memset(mac_table, 0, sizeof(struct mac_table_entry)* MAC_TABLE_SIZE);

    return OK;
}

void debug_mac_table(void)
{
    int i = 0;

    for (i=0; i<MAC_TABLE_SIZE; i++)
    {
        if (mac_table[i].port)
        {
            printf("index=%d, port=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x, time=%d\n",
                    i, mac_table[i].port,
                    mac_table[i].mac_addr[0], mac_table[i].mac_addr[1],
                    mac_table[i].mac_addr[2], mac_table[i].mac_addr[3],
                    mac_table[i].mac_addr[4], mac_table[i].mac_addr[5],
                    mac_table[i].time);
        }
    }
}

int main()
{
    uint8_t mac1[] = {0x00, 0x03, 0x0f, 0x00, 0x00, 0x01};
    uint8_t mac2[] = {0x00, 0x03, 0x0f, 0x00, 0x00, 0x02};

    pthread_t age_thread;
    pthread_mutex_init(&mac_table_lock, NULL);

    init_global_mac_table();
    pthread_create(&age_thread, NULL, (void *)mac_table_age_thread, NULL);

    get_output_port(1, mac1, mac2);
    get_output_port(2, mac2, mac1);

    debug_mac_table();
    sleep(10);

    get_output_port(1, mac2, mac1);
    debug_mac_table();

    sleep(10);
    debug_mac_table();

    sleep(50);
    debug_mac_table();

    return 0;
}
