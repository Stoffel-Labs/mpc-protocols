#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#include "../honey_badger_bindings.h"

void *quic_accept_process(void *arg)
{
    struct
    {
        struct QuicNetworkOpaque *net;
        struct QuicPeerConnectionsOpaque *peer_connections;
        size_t node_index;
    } *params = arg;

    while (true)
    {
        char *returned_addr;
        NetworkErrorCode e = quic_accept(params->net, params->peer_connections, &returned_addr);
        if (e != NetworkSuccess)
        {
            printf("Error accepting connection for addr1, error code: %d\n", e);
            pthread_exit(NULL);
        }
        else
        {
            printf("Node%zu accepted connection from %s\n", params->node_index, returned_addr);
        }
    }
}

void *quic_recv_process(void *arg)
{
    struct
    {
        struct QuicPeerConnectionsOpaque *peer_connections;
        char *addr;
        size_t node_index;
    } *params = arg;
    while (true)
    {
        struct ByteSlice msg;
        NetworkErrorCode e = quic_receive_from_sync(params->peer_connections, params->addr, &msg);
        if (e != NetworkSuccess)
        {
            printf("Error recv from %s, error code: %d\n", params->addr, e);
            pthread_exit(NULL);
        }
        printf("Node %zu Received from %s: %s\n", params->node_index, params->addr, msg.pointer);
    }
}

void quic_test()
{
    // Setup crypto provider for rustls
    // Must be called first
    init_tls();

    struct QuicPeerConnectionsOpaque *peer_connection1;
    struct QuicPeerConnectionsOpaque *peer_connection2;
    struct QuicPeerConnectionsOpaque *peer_connection3;
    struct QuicNetworkOpaque *quic_node1 = new_quic_network(&peer_connection1);
    struct QuicNetworkOpaque *quic_node2 = new_quic_network(&peer_connection2);
    struct QuicNetworkOpaque *quic_node3 = new_quic_network(&peer_connection3);

    // start the listening processes
    char addr1[] = "127.0.0.1:9090";
    char addr2[] = "127.0.0.1:9091";
    char addr3[] = "127.0.0.1:9092";
    NetworkErrorCode e = quic_listen(quic_node1, addr1);
    if (e != NetworkSuccess)
    {
        printf("Error starting net1, error code: %d\n", e);
        exit(1);
    }
    e = quic_listen(quic_node2, addr2);
    if (e != NetworkSuccess)
    {
        printf("Error starting net2, error code: %d\n", e);
        exit(1);
    }
    e = quic_listen(quic_node3, addr3);
    if (e != NetworkSuccess)
    {
        printf("Error starting net2, error code: %d\n", e);
        exit(1);
    }

    // start the processes to accept connections for node 2 and node 3
    pthread_t acc_thread2, acc_thread3;
    struct QuicAcceptArgs
    {
        struct QuicNetworkOpaque *quic_node;
        struct QuicPeerConnectionsOpaque *peer_connections;
        size_t node_index;
    };
    struct QuicAcceptArgs acc_args2 = {
        .quic_node = quic_node2,
        .peer_connections = peer_connection2,
        .node_index = 2,
    };
    struct QuicAcceptArgs acc_args3 = {
        .quic_node = quic_node3,
        .peer_connections = peer_connection3,
        .node_index = 3,
    };
    pthread_create(&acc_thread2, NULL, quic_accept_process, (void *)&acc_args2);
    pthread_create(&acc_thread3, NULL, quic_accept_process, (void *)&acc_args3);

    // node1 -> node2
    e = quic_connect(quic_node1, peer_connection1, addr2);
    if (e != NetworkSuccess)
    {
        printf("Error connecting to addr: %s, error code: %d\n", addr2, e);
        exit(1);
    }
    printf("Node1 connected to addr: %s\n", addr2);
    // node1 -> node3
    e = quic_connect(quic_node1, peer_connection1, addr3);
    if (e != NetworkSuccess)
    {
        printf("Error connecting to addr: %s, error code: %d\n", addr3, e);
        exit(1);
    }
    printf("Node1 connected to addr: %s\n", addr3);
    // wait for connections
    usleep(100000);

    // start the recv process for
    // node2 -> node1, node3 -> node1, node1 -> node2, node1 -> node3
    pthread_t recv_thread1, recv_thread2, recv_thread3, recv_thread4;
    struct QuicRecvArgs
    {
        struct QuicPeerConnectionsOpaque *peer_connections;
        char *addr;
        size_t node_index;
    };
    struct QuicRecvArgs recv_args1 = {
        .peer_connections = peer_connection1,
        .addr = addr2,
        .node_index = 1};
    struct QuicRecvArgs recv_args2 = {
        .peer_connections = peer_connection1,
        .addr = addr3,
        .node_index = 1};
    struct QuicRecvArgs recv_args3 = {
        .peer_connections = peer_connection2,
        .addr = addr1,
        .node_index = 2};
    struct QuicRecvArgs recv_args4 = {
        .peer_connections = peer_connection3,
        .addr = addr1,
        .node_index = 3};
    pthread_create(&recv_thread1, NULL, quic_recv_process, (void *)&recv_args1);
    pthread_create(&recv_thread2, NULL, quic_recv_process, (void *)&recv_args2);
    pthread_create(&recv_thread3, NULL, quic_recv_process, (void *)&recv_args3);
    pthread_create(&recv_thread4, NULL, quic_recv_process, (void *)&recv_args4);

    // send message
    // node1 -> node2
    char myString[] = "Hello from node1";
    struct ByteSlice msg;
    msg.pointer = (uint8_t *)myString;
    msg.len = strlen(myString) + 1;
    quic_send(peer_connection1, addr2, msg);

    // node3 -> node1
    char myString2[] = "Hello from node3";
    struct ByteSlice msg2;
    msg2.pointer = (uint8_t *)myString2;
    msg2.len = strlen(myString2) + 1;
    quic_send(peer_connection3, addr1, msg2);

    // must stop accepting connections before calling quic_into_hb_network
    // since quic_node will be consumed
    pthread_cancel(acc_thread2);
    pthread_cancel(acc_thread3);
    pthread_join(acc_thread2, NULL);
    pthread_join(acc_thread3, NULL);

    // cast quic network to HoneyBadgerMPC network
    // Note - this function will consume the quic node
    // make sure to finish quic setup before this function
    NetworkOpaque *hb_net1 = quic_into_hb_network(&quic_node1);
    NetworkOpaque *hb_net2 = quic_into_hb_network(&quic_node2);
    NetworkOpaque *hb_net3 = quic_into_hb_network(&quic_node3);
    assert(quic_node1 == NULL);
    assert(quic_node2 == NULL);
    assert(quic_node3 == NULL);

    sleep(1);
    // stop recv threads
    pthread_cancel(recv_thread1);
    pthread_cancel(recv_thread2);
    pthread_cancel(recv_thread3);
    pthread_cancel(recv_thread4);
}

int main()
{
    quic_test();
    return 0;
}