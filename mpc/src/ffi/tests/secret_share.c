#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "../shamirshare.h"

ShareErrorCode test_create_and_recover_shamir_shares()
{
    struct Bls12Fr secret_fr = {{520, 86, 9, 18}};
    struct ShamirShareSliceBls12 output_shares;
    uintptr_t id[6] = {1, 2, 3, 4, 5, 6};
    struct UsizeSlice ids = {id, 6};
    // create a single shamir share
    ShamirShareBls12 _s = shamir_share_new(secret_fr, 9, 10);
    // create an array of shamir shares with provided ids
    ShareErrorCode e = shamir_share_compute_shares(secret_fr, 4, &ids, &output_shares);
    if (e != ShareSuccess)
    {
        return e;
    }
    // print returned shamir shares
    for (int i = 0; i < output_shares.len; i++)
    {
        ShamirShareBls12 share = output_shares.pointer[i];
        printf("share_id_%zu = [ %llu, %llu, %llu, %llu ]\n",
               share.id,
               share.share.data[0], share.share.data[1],
               share.share.data[2], share.share.data[3]);
    }

    // recover the original secret with shares
    struct Bls12Fr recovered_secret;
    struct Bls12FrSlice recovered_coeff;
    e = shamir_share_recover_secret(output_shares, &recovered_secret, &recovered_coeff);
    if (e != ShareSuccess)
    {
        return e;
    }
    printf("original_secret = [ %llu, %llu, %llu, %llu ]\n",
           secret_fr.data[0], secret_fr.data[1],
           secret_fr.data[2], secret_fr.data[3]);
    printf("recovered_secret = [ %llu, %llu, %llu, %llu ]\n",
           recovered_secret.data[0], recovered_secret.data[1],
           recovered_secret.data[2], recovered_secret.data[3]);
    // coeff[0] == secret
    printf("recovered_coeff[0] = [ %llu, %llu, %llu, %llu ]\n",
           recovered_coeff.pointer[0].data[0], recovered_coeff.pointer[0].data[1],
           recovered_coeff.pointer[0].data[2], recovered_coeff.pointer[0].data[3]);
    int result = memcmp(recovered_secret.data, secret_fr.data, sizeof(uint64_t) * 4);
    assert(result == 0);
    // free the memory of slices in rust
    free_shamir_share_bls12_slice(output_shares);
    free_bls12_fr_slice(recovered_coeff);

    return ShareSuccess;
}

ShareErrorCode test_create_and_recover_robust_shares()
{
    struct Bls12Fr secret_fr = {{3, 3, 22, 22}};
    struct RobustShareSliceBls12 output_shares;
    // number of nodes
    uintptr_t n = 6;
    // create a single robust share
    RobustShareBls12 _s = robust_share_new(secret_fr, 9, 10);
    // create an array of shamir shares with provided ids
    ShareErrorCode e = robust_share_compute_shares(secret_fr, 2, n, &output_shares);
    if (e != ShareSuccess)
    {
        return e;
    }
    // print returned shamir shares
    for (int i = 0; i < output_shares.len; i++)
    {
        RobustShareBls12 share = output_shares.pointer[i];
        printf("share_id_%zu = [ %llu, %llu, %llu, %llu ]\n",
               share.id,
               share.share.data[0], share.share.data[1],
               share.share.data[2], share.share.data[3]);
    }

    // recover the original secret with shares
    struct Bls12Fr recovered_secret;
    struct Bls12FrSlice recovered_coeff;
    e = robust_share_recover_secret(output_shares, n, &recovered_secret, &recovered_coeff);
    if (e != ShareSuccess)
    {
        return e;
    }
    printf("original_secret = [ %llu, %llu, %llu, %llu ]\n",
           secret_fr.data[0], secret_fr.data[1],
           secret_fr.data[2], secret_fr.data[3]);
    printf("recovered_secret = [ %llu, %llu, %llu, %llu ]\n",
           recovered_secret.data[0], recovered_secret.data[1],
           recovered_secret.data[2], recovered_secret.data[3]);
    // coeff[0] == secret
    printf("recovered_coeff[0] = [ %llu, %llu, %llu, %llu ]\n",
           recovered_coeff.pointer[0].data[0], recovered_coeff.pointer[0].data[1],
           recovered_coeff.pointer[0].data[2], recovered_coeff.pointer[0].data[3]);
    int result = memcmp(recovered_secret.data, secret_fr.data, sizeof(uint64_t) * 4);
    assert(result == 0);
    // free the memory of slices in rust
    free_robust_share_bls12_slice(output_shares);
    free_bls12_fr_slice(recovered_coeff);

    return ShareSuccess;
}

ShareErrorCode test_create_and_recover_non_robust_shares()
{
    struct Bls12Fr secret_fr = {{16, 33, 44, 81}};
    struct NonRobustShareSliceBls12 output_shares;
    // number of nodes
    uintptr_t n = 6;
    // create a single robust share
    NonRobustShareBls12 _s = non_robust_share_new(secret_fr, 9, 10);
    // create an array of shamir shares with provided ids
    ShareErrorCode e = non_robust_share_compute_shares(secret_fr, 5, n, &output_shares);
    if (e != ShareSuccess)
    {
        return e;
    }
    // print returned shamir shares
    for (int i = 0; i < output_shares.len; i++)
    {
        NonRobustShareBls12 share = output_shares.pointer[i];
        printf("share_id_%zu = [ %llu, %llu, %llu, %llu ]\n",
               share.id,
               share.share.data[0], share.share.data[1],
               share.share.data[2], share.share.data[3]);
    }

    // recover the original secret with shares
    struct Bls12Fr recovered_secret;
    struct Bls12FrSlice recovered_coeff;
    e = non_robust_share_recover_secret(output_shares, n, &recovered_secret, &recovered_coeff);
    if (e != ShareSuccess)
    {
        return e;
    }
    printf("original_secret = [ %llu, %llu, %llu, %llu ]\n",
           secret_fr.data[0], secret_fr.data[1],
           secret_fr.data[2], secret_fr.data[3]);
    printf("recovered_secret = [ %llu, %llu, %llu, %llu ]\n",
           recovered_secret.data[0], recovered_secret.data[1],
           recovered_secret.data[2], recovered_secret.data[3]);
    // coeff[0] == secret
    printf("recovered_coeff[0] = [ %llu, %llu, %llu, %llu ]\n",
           recovered_coeff.pointer[0].data[0], recovered_coeff.pointer[0].data[1],
           recovered_coeff.pointer[0].data[2], recovered_coeff.pointer[0].data[3]);
    int result = memcmp(recovered_secret.data, secret_fr.data, sizeof(uint64_t) * 4);
    assert(result == 0);
    // free the memory of slices in rust
    free_non_robust_share_bls12_slice(output_shares);
    free_bls12_fr_slice(recovered_coeff);

    return ShareSuccess;
}

int main()
{
    printf("\n================================ shamir share ================================\n\n");
    ShareErrorCode e = test_create_and_recover_shamir_shares();
    if (e != ShareSuccess)
    {
        printf("Error code: %d\n", e);
        return 1;
    }

    printf("\n================================ robust share ================================\n\n");
    e = test_create_and_recover_robust_shares();
    if (e != ShareSuccess)
    {
        printf("Error code: %d\n", e);
        return 1;
    }

    printf("\n================================ non robust share ================================\n\n");
    e = test_create_and_recover_non_robust_shares();
    if (e != ShareSuccess)
    {
        printf("Error code: %d\n", e);
        return 1;
    }
    return 0;
}
