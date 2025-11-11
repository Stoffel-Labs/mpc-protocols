#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "../shamirshare.h"

void setup_bracha_parties(size_t n, size_t t, BrachaOpaque **parties)
{
    // create n bracha instances
    for (size_t i = 0; i < n; i++)
    {
        enum RbcErrorCode e = bracha_new(i, n, t, &parties[i]);
        if (e != RbcSuccess)
        {
            printf("Error in creating bracha instance for party %zu\n", i);
            exit(1);
        }
    }
}

void *recv_msg(void *arg)
{
    struct
    {
        struct FakeNetworkReceiversOpaque *receivers;
        struct BrachaOpaque *node;
        struct NetworkOpaque *net;
        size_t node_index;
    } *params = arg;
    while (true)
    {
        struct ByteSlice msg = node_receiver_recv_sync(params->receivers, params->node_index);
        if (msg.len == 0)
        {
            printf("No message received for party %zu\n", params->node_index);
            pthread_exit(NULL);
        }
        struct RbcMsg rbc_msg;
        enum RbcErrorCode re = deserialize_rbc_msg(msg, &rbc_msg);
        if (re != RbcSuccess)
        {
            printf("Error in deserializing rbc message for party %zu, error code: %d\n", params->node_index, re);
            pthread_exit(NULL);
        }
        printf("Party %zu received message of length %lu from sender %lu\n", params->node_index, rbc_msg.msg_len, rbc_msg.sender_id);
        // process message
        enum RbcErrorCode e = sync_bracha_process(params->node, rbc_msg, params->net);
        if (e == RbcSessionEnded)
        {
            printf("Bracha protocol finished for party %zu\n", params->node_index);
            pthread_exit(NULL);
        }
        if (e != RbcSuccess)
        {
            printf("Error in bracha process for party %zu, error code: %d\n", params->node_index, e);
            pthread_exit(NULL);
        }
    }
    return NULL;
}

void test_bracha_rbc_basic()
{
    size_t n = 4;
    size_t t = 1;
    uintptr_t channel_buff_size = 500;
    char myString[] = "Hello, MPC!";
    new_session_id(Rbc, 0, 0, 12);
    struct BrachaOpaque *prt_array[n];
    struct FakeNetworkReceiversOpaque *receivers;
    struct NetworkOpaque _net;

    setup_bracha_parties(n, t, prt_array);
    struct NetworkOpaque *net = new_fake_network(n, NULL, channel_buff_size, &receivers);
    // get bracha instance id
    uintptr_t id = get_bracha_id(prt_array[3]);
    // printf("bracha instance 3 id: %lu\n", id);

    struct ByteSlice payload;
    payload.pointer = (uint8_t *)myString;
    payload.len = strlen(myString) + 1;

    uint64_t session_id = new_session_id(Rbc, 0, 0, 12);
    // party 0 init
    enum RbcErrorCode e = sync_bracha_init(prt_array[0], payload, session_id, net);
    if (e != RbcSuccess)
    {
        printf("Error in bracha init for party 1, error code: %d\n", e);
        exit(1);
    }
    // create threads to receive messages for all parties
    pthread_t thread1, thread2, thread3, thread4;

    struct ThreadArgs
    {
        struct FakeNetworkReceiversOpaque *receivers;
        struct BrachaOpaque *node;
        struct NetworkOpaque *net;
        size_t node_index;
    };
    struct ThreadArgs args1 = {
        .receivers = receivers,
        .node = prt_array[0],
        .net = net,
        .node_index = 0,
    };
    struct ThreadArgs args2 = {
        .receivers = receivers,
        .node = prt_array[1],
        .net = net,
        .node_index = 1,
    };
    struct ThreadArgs args3 = {
        .receivers = receivers,
        .node = prt_array[2],
        .net = net,
        .node_index = 2,
    };
    struct ThreadArgs args4 = {
        .receivers = receivers,
        .node = prt_array[3],
        .net = net,
        .node_index = 3,
    };

    pthread_create(&thread1, NULL, recv_msg, (void *)&args1);
    pthread_create(&thread2, NULL, recv_msg, (void *)&args2);
    pthread_create(&thread3, NULL, recv_msg, (void *)&args3);
    pthread_create(&thread4, NULL, recv_msg, (void *)&args4);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    pthread_join(thread4, NULL);

    // read output message from all parties
    for (size_t i = 0; i < n; i++)
    {
        // make sure session has ended
        bool session_ended = has_bracha_session_ended(prt_array[i], session_id);
        assert(session_ended);
        struct ByteSlice output = get_bracha_output(prt_array[i], session_id);
        if (output.len == 0 || output.pointer == NULL)
        {
            printf("Error: output is empty for party %zu\n", i);
            exit(1);
        }
        printf("Output for party %zu: %s\n", i, output.pointer);
        assert(strcmp((char *)output.pointer, myString) == 0);
    }
}

int main()
{
    test_bracha_rbc_basic();
    return 0;
}