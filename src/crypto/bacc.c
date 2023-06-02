
#include "bee2/crypto/bacc.h"
#include "bee2/core/util.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bash.h"
#include "bee2/math/zz.h"
#include "bee2/core/blob.h"
#include "bee2/math/ec.h"
#include "bee2/math/ecp.h"
#include "bee2/crypto/bign.h"
#include "bign_lcl.h"
#include "bee2/crypto/bake.h"


static const char* curveOid(size_t l)
{
    switch (l)
    {
        case 128:
            return "1.2.112.0.2.0.34.101.45.3.1";
        case 192:
            return "1.2.112.0.2.0.34.101.45.3.2";
        case 256:
            return "1.2.112.0.2.0.34.101.45.3.3";
        default:
            return NULL;
    }
}

static void baccHash(
    octet *hash,
    size_t l,
    const octet * acc_old,
    const octet * acc_new,
    size_t old_acc_len,
    const octet * r
) {

    void* state[2048];
    bign_params params[1];
    ec_o* ec;

    ASSERT(sizeof(state) >= beltHash_keep());
    ASSERT(sizeof(state) >= bashHash_keep());
    ASSERT(sizeof(state) >= bignStart_keep(l, 0));
    ASSERT(l == 128 || l == 192 || l == 256);
    ASSERT(memIsValid(hash, baccZq_keep(l)));

    if (l==128) {
        beltHashStart(state);
        beltHashStepH(acc_old, old_acc_len * baccGq_keep(l), state);
        beltHashStepH(acc_new, (old_acc_len+1) * baccGq_keep(l), state);
        beltHashStepH(r, old_acc_len * baccGq_keep(l), state);
        beltHashStepG(hash, state);
    }
    else {
        bashHashStart(state, l);
        bashHashStepH(acc_old, old_acc_len * baccGq_keep(l), state);
        bashHashStepH(acc_new, (old_acc_len+1) * baccGq_keep(l), state);
        bashHashStepH(r, old_acc_len * baccGq_keep(l), state);
        bashHashStepG(hash, l/4, state);
    }

    ASSERT(bignStdParams(params, curveOid(l)) == ERR_OK);
    ASSERT(bignStart(state, params)==ERR_OK);
    ec = (ec_o*)state;

    zzMod((word *) hash,
          (const word *) hash, W_OF_O(l/4),
          ec->order, ec->f->n,
          state
    );
}


static err_t bignSum(
    octet c[],
    const bign_params* params,
    const octet a[],
    const octet b[]
){
    err_t code;
    size_t no, n;
    ec_o* ec;				/* описание эллиптической кривой */
    word *Q1, *Q2;
    void* stack;
    void* state [2048];

    if (!memIsValid(params, sizeof(bign_params)))
        return ERR_BAD_INPUT;
    if (params->l != 128 && params->l != 192 && params->l != 256)
        return ERR_BAD_PARAMS;
    code = bignStart(state, params);
    ERR_CALL_HANDLE(code, blobClose(state));
    ec = (ec_o*)state;
    no  = ec->f->no;
    n = ec->f->n;

    // проверить входные указатели
    if (!memIsValid(a, 2 * no) ||
        !memIsValid(b, 2 * no))
    {
        return ERR_BAD_INPUT;
    }
    // раскладка состояния
    Q1 = objEnd(ec, word);
    Q2 = Q1 + 2*n;

    stack = Q2 + 2 * n;

    // загрузить Q
    if (!qrFrom(ecX(Q1), a, ec->f, stack) ||
        !qrFrom(ecY(Q1, n), a + no, ec->f, stack) ||
        !ecpIsOnA(Q1, ec, stack))
    {
        return ERR_BAD_PUBKEY;
    }
    if (!qrFrom(ecX(Q2), b, ec->f, stack) ||
        !qrFrom(ecY(Q2, n), b + no, ec->f, stack) ||
        !ecpIsOnA(Q2, ec, stack))
    {
        return ERR_BAD_PUBKEY;
    }

    if (ecpAddAA(Q1, Q1,Q2, ec, stack))
    {
        qrTo((octet*)Q1, ecX(Q1), ec->f, stack);
        qrTo((octet*)Q1 + no, ecY(Q1, n), ec->f, stack);
        memCopy(c, Q1, 2*no);
    }
    else
        code = ERR_BAD_PARAMS;
    // завершение
    return code;
}


static err_t baccMul(
    const bign_params* params,
    octet * acc,
    size_t acc_len,
    const octet* privkey
) {
    err_t code;
    size_t i;
    ASSERT(memIsValid(params, sizeof (bign_params)));

    for (i = 0; i < acc_len; i++) {
        code = bignDH(
                acc + i * baccGq_keep(params->l),
                params,
                privkey,
                acc + i * baccGq_keep(params->l),
                baccGq_keep(params->l)
        );
        ERR_CALL_CHECK(code);
    }
    return code;
}


static err_t baccSum(
    octet * r,
    const bign_params* params,
    const octet * acc1,
    const octet * acc2,
    size_t acc_len
) {
    err_t code;
    size_t i;
    ASSERT(memIsValid(params, sizeof (bign_params)));

    for (i = 0; i < acc_len; i++) {
        code = bignSum(
                r + i * baccGq_keep(params->l),
                params,
                acc1 + i * baccGq_keep(params->l),
                acc2 + i * baccGq_keep(params->l)
        );
        ERR_CALL_CHECK(code);
    }
    return code;
}

static void baccHash2(
    octet * hash,
    const octet* acc,
    size_t acc_len,
    const octet* r,
    const octet* pubkey,
    const octet* adata,
    size_t adata_size,
    const bign_params* params
) {
    void* state[1024];
    const size_t l = params->l;
    ec_o* ec;

    ASSERT(memIsValid(params, sizeof(bign_params)));
    ASSERT(sizeof(state) >= beltHash_keep());
    ASSERT(sizeof(state) >= bashHash_keep());
    ASSERT(l == 128 || l == 192 || l == 256);
    ASSERT(memIsValid(hash, baccZq_keep(l)));
    ASSERT(memIsNullOrValid(adata, adata_size));

    if (l == 128) {
        beltHashStart(state);
        beltHashStepH(acc, acc_len * baccGq_keep(l), state);
        beltHashStepH(r, acc_len * l,state);
        beltHashStepH(pubkey, l / 2, state);
        if (adata)
            beltHashStepH(adata, adata_size, state);
        beltHashStepG(hash, state);
    } else {
        bashHashStart(state, l);
        bashHashStepH(acc, acc_len * baccGq_keep(l), state);
        bashHashStepH(r, acc_len * l,state);
        bashHashStepH(pubkey, l / 2, state);
        if (adata)
            bashHashStepH(adata, adata_size, state);
        bashHashStepG(hash, l/4, state);
    }

    ASSERT(bignStart(state, params)==ERR_OK);
    ec = (ec_o*)state;

    zzMod((word *) hash,
          (const word *) hash, W_OF_O(baccZq_keep(l)),
          ec->order, ec->f->n,
          state
    );
}

static err_t baccMul2(
    octet *mul,
    const bign_params* params,
    const octet *k,
    const octet* g1,
    const octet* g2
){
    ASSERT(memIsValid(mul, baccGq_keep(params->l)*2));

    memCopy(mul, g1, baccGq_keep(params->l));
    memCopy(mul + baccGq_keep(params->l), g2, baccGq_keep(params->l));
    return baccMul(params, mul, 2, k);
}

err_t baccGenKey(
    const bign_params* params,
    octet * privkey,
    octet * pubkey,
    gen_i rng,
    void* rng_state
){

    err_t code;
    octet _privkey[64];
    octet _pubkeykey[128];

    ASSERT(memIsValid(params, sizeof (bign_params)));

    code = bignGenKeypair(_privkey, _pubkeykey, params, rng, rng_state);
    ERR_CALL_CHECK(code);

    if (privkey){
        memCopy(privkey, _privkey, params->l/4);
    }
    if (pubkey){
        memCopy(pubkey, _pubkeykey, params->l/2);
    }

    return code;
}


err_t baccDHInit(octet * acc, size_t l, octet * msg, gen_i rng, void* rng_state) {

    err_t code;
    bign_params params[1];

    ASSERT(l==128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(memIsValid(acc, l));

    if (msg){
        ASSERT(memIsValid(msg, l/4));
        return bakeSWU(acc, params, msg);
    }

    return baccGenKey(params, 0, acc, rng, rng_state);
}

size_t baccDHAdd_keep(size_t l, size_t acc_len){
    return baccGq_keep(l) * (acc_len + 1);
}

err_t baccDHAdd(
    size_t l,
    octet * acc,
    size_t acc_len,
    const octet* privkey
){

    err_t code;
    octet g0[baccGq_keep(256)];
    bign_params params[1];

    ASSERT(l == 128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(memIsValid(params, sizeof (bign_params)));
    ASSERT(memIsValid(privkey, baccZq_keep(l)));

    memCopy(g0, acc, baccGq_keep(l));
    code = baccMul(params, acc, acc_len, privkey);
    ERR_CALL_CHECK(code);

    memCopy(acc + acc_len * baccGq_keep(l), g0, baccGq_keep(l));
    acc_len = acc_len+1;

    return code;
}


err_t baccDHPrvAdd(
    octet * proof,
    size_t l,
    const octet* old_acc,
    const octet* new_acc,
    size_t old_acc_len,
    size_t new_acc_len,
    const octet* privkey,
    gen_i rng,
    void* rng_state
){
    err_t code;
    octet k[baccZq_keep(256)];
    octet hash[baccZq_keep(256)];
    word hu_mod_q[8];
    void* stack[2048];

    bign_params params[1];
    void* state[2048];
    ec_o* ec;

    ASSERT(l==128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(sizeof (stack) >= zzMulMod_deep(baccZq_keep(l)));
    ASSERT(memIsValid(privkey, baccZq_keep(l)));
    ASSERT(memIsValid(old_acc, old_acc_len * baccGq_keep(l)));
    ASSERT(memIsValid(new_acc, new_acc_len * baccGq_keep(l)));
    ASSERT(memIsValid(proof, (old_acc_len+1) * baccGq_keep(l)));

    if (old_acc_len +1 != new_acc_len)
        return ERR_MAX;

    if (!memEq(old_acc, new_acc + old_acc_len * baccGq_keep(l), baccGq_keep(l)))
        return ERR_MAX;

    code = baccGenKey(params, k, 0, rng, rng_state);
    ERR_CALL_CHECK(code);

    memCopy(proof, old_acc, old_acc_len * baccGq_keep(l));

    code = baccMul(params, proof, old_acc_len, k);
    ERR_CALL_CHECK(code)

    baccHash(hash, l, old_acc, new_acc, old_acc_len, proof);

    code = bignStart(state, params);
    ERR_CALL_CHECK(code);

    ec = (ec_o*)state;

    //hu mod q
    zzMulMod(hu_mod_q,
             (const word *) hash,
             (const word *) privkey,
             ec->order,ec->f->n,
             stack
    );

    // (k-hu) mod q
    zzSubMod(
            (word *) (proof + old_acc_len * baccGq_keep(l)),
            (const word *) k,
            hu_mod_q,
            ec->order,ec->f->n
    );

    return ERR_OK;
}


size_t baccDHPrvAdd_keep(size_t l, size_t old_acc_len){
    return l * old_acc_len;
}


size_t baccDHVfyAdd_deep(size_t l, size_t old_acc_len){
    return l * (2*old_acc_len+1) ;
}


err_t baccDHVfyAdd(
    size_t l,
    const octet* proof,
    const octet* old_acc,
    const octet* new_acc,
    size_t old_acc_len,
    size_t new_acc_len,
    void *stack
) {

    const octet *s;
    err_t code;
    octet hash[baccZq_keep(256)];

    bign_params params[1];
    octet * most_a;

    ASSERT(l==128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(memIsValid(params, sizeof (bign_params)));
    ASSERT(memIsValid(stack, baccDHVfyAdd_deep(l, old_acc_len)));

    if (old_acc_len + 1 != new_acc_len)
        return ERR_MAX;

    if (!memEq(old_acc, new_acc + old_acc_len * baccGq_keep(l), baccGq_keep(l)))
        return ERR_MAX;

    s = proof + old_acc_len * baccGq_keep(l);

    baccHash(hash, l, old_acc, new_acc, old_acc_len, proof);

    memCopy(stack, old_acc, old_acc_len * baccGq_keep(l));

    code = baccMul(params, stack, old_acc_len, s);
    ERR_CALL_CHECK(code);

    most_a = stack + old_acc_len * baccGq_keep(l);
    memCopy(most_a, new_acc, old_acc_len * baccGq_keep(l));

    code = baccMul(params, most_a, old_acc_len, hash);
    ERR_CALL_CHECK(code)

    code = baccSum(stack, params, stack, most_a, old_acc_len);
    ERR_CALL_CHECK(code);

    return memEq(proof, stack, old_acc_len * baccGq_keep(l)) ? ERR_OK : ERR_MAX;
}


size_t baccDHDer(
    octet * pubkey,
    size_t l,
    const octet* acc,
    size_t acc_len,
    const octet* privkey
){
    err_t code;
    octet m[baccGq_keep(256)];
    bign_params params[1];
    size_t i;
    ASSERT(l==128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(memIsValid(params, sizeof (bign_params)));

    for (i = 0; i < acc_len; i++){
        code = bignDH(m, params, privkey, acc + i * baccGq_keep(l), baccGq_keep(l));
        if (code != ERR_OK)
            return SIZE_MAX;
        if (memEq(acc, m, baccGq_keep(l))){
            return bignDH(pubkey, params, privkey, acc, baccGq_keep(l))
                == ERR_OK ? i : SIZE_MAX;
        }
    }

    return SIZE_MAX;
}


size_t baccDHPrvDer_keep(size_t l, size_t acc_len){
    return acc_len * baccGq_keep(l);
}

size_t baccDHPrvDer_deep(size_t l, size_t old_acc_len){
    return old_acc_len * baccGq_keep(l) * 2;
}

err_t baccDHPrvDer(
    octet * proof,
    size_t l,
    const octet* acc,
    size_t acc_len,
    const octet* privkey,
    const octet* adata,
    size_t adata_size,
    gen_i rng,
    void* rng_state,
    void * stack
) {
    octet pubkey[baccGq_keep(256)];
    size_t i,j;
    octet* h;
    octet* s;
    octet ki[baccGq_keep(256)];
    octet hash[baccZq_keep(256)];
    word sum[8];
    word hu[8];
    octet mul1[baccGq_keep(256) * 2];
    octet mul2[baccGq_keep(256) * 2];
    void* state[4096];
    ec_o* ec;
    err_t code;
    bign_params params[1];

    ASSERT(l==128 || l == 192 || l == 256);
    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    ASSERT(memIsValid(proof, acc_len * 3*baccZq_keep(l) + baccGq_keep(l)));
    ASSERT(memIsValid(privkey, baccZq_keep(l)));
    ASSERT(memIsValid(acc, acc_len * baccGq_keep(l)));

    ASSERT(memIsValid(stack, baccDHPrvDer_deep(l, acc_len)));

    h = proof;
    s = proof + baccZq_keep(l)*acc_len;

    i = baccDHDer(pubkey,l, acc, acc_len, privkey);

    if (i == SIZE_MAX)
        return ERR_BAD_PUBKEY;

    for (j = 0; j < acc_len; j++) {
        if (j == i)
            continue;

        code = baccGenKey(params, h + j * baccZq_keep(l), 0, rng, rng_state);
        ERR_CALL_CHECK(code);
        code = baccGenKey(params, s + j * baccZq_keep(l), 0, rng, rng_state);
        ERR_CALL_CHECK(code);

        code = baccMul2(mul1, params, s + j * baccZq_keep(l), acc + j * baccGq_keep(l), acc);
        ERR_CALL_CHECK(code);

        code = baccMul2(mul2, params, h + j * baccZq_keep(l), acc, pubkey);
        ERR_CALL_CHECK(code);

        code = baccSum(stack + j * l, params, mul1, mul2, 2);
        ERR_CALL_CHECK(code);
    }

    code = baccGenKey(params, ki, 0, rng, rng_state);
    ERR_CALL_CHECK(code)

    code = baccMul2(stack + i * l, params, ki, acc + i * baccGq_keep(l), acc);
    ERR_CALL_CHECK(code);

    baccHash2(hash, acc, acc_len, stack, pubkey, adata, adata_size, params);

    code = bignStart(state, params);
    ERR_CALL_CHECK(code);

    ec = (ec_o*)state;

    memSetZero(sum, sizeof (sum));

    //sum(hj)
    for (j = 0; j < acc_len; j++) {
        if (j == i)
            continue;

        zzAddMod(
                sum,
                sum,(const word *) (h + j * baccZq_keep(l)),
                ec->order,ec->f->n
        );
    }

    //hi = hash(...) - sum(hj)
    zzSubMod(
            (word *) (h + i * baccZq_keep(l)),
            (const word*) hash,sum,
            ec->order,ec->f->n
    );


    ASSERT(memIsValid(stack, zzMulMod_deep(ec->f->n)));
    //hu mod q
    zzMulMod(
            hu,
            (const word *) privkey,
            (const word *) (h + i * baccZq_keep(l)),
            ec->order, ec->f->n,
            stack
    );
    // si = (ki - hu) mod q
    zzSubMod(
            (word *) (s + i * baccZq_keep(l)),
            (const word *) ki,
            hu,
            ec->order,ec->f->n
    );

    return ERR_OK;
}


size_t baccDHVfyDer_deep(size_t l, size_t old_acc_len){
    return baccDHPrvDer_deep(l,old_acc_len);
}

err_t baccDHVfyDer(
    size_t l,
    const octet* acc,
    size_t acc_len,
    const octet * pubkey,
    const octet* adata,
    size_t adata_size,
    const octet * proof,
    void* stack
) {

    const octet *h = proof;
    const octet *s = proof + acc_len * baccZq_keep(l);
    err_t code;
    octet hash[baccZq_keep(256)];
    ec_o* ec;
//    void* state[4096];
    word sum[8];
    bign_params params[1];
    size_t j;
    octet mul1[baccGq_keep(256) * 2];
    octet mul2[baccGq_keep(256) * 2];

    ASSERT(memIsValid(stack, baccDHVfyDer_deep(l,acc_len)));
    ASSERT(l==128 || l == 192 || l == 256);

    code = bignStdParams(params, curveOid(l));
    ERR_CALL_CHECK(code)

    for (j = 0; j< acc_len; j++){

        code = baccMul2(mul1, params, s + j * baccZq_keep(l), acc + j * baccGq_keep(l), acc);
        ERR_CALL_CHECK(code);
        code = baccMul2(mul2, params, h + j * baccZq_keep(l), acc, pubkey);
        ERR_CALL_CHECK(code);
        code = baccSum(stack + j * l, params,mul1,mul2, 2);
        ERR_CALL_CHECK(code)
    }

    baccHash2(hash, acc, acc_len, stack, pubkey, adata, adata_size, params);

    code = bignStart(stack, params);
    ERR_CALL_CHECK(code);

    ec = (ec_o*)stack;

    memSetZero(sum, sizeof (sum));

    for (j = 0; j< acc_len; j++){
        zzAddMod(
                sum,
                sum,(const word *) (h + j * baccZq_keep(l)),
                ec->order,ec->f->n
        );
    }

    return memEq(hash, sum, baccZq_keep(l)) ? ERR_OK : ERR_MAX;
}