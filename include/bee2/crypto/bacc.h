
// Слепой аккумулятор bacc
// https://eprint.iacr.org/2022/373.pdf

#ifndef __BEE2_BACC_H
#define __BEE2_BACC_H

#include <bee2/defs.h>

#define baccGq_keep(l) ((l)/2)
#define baccZq_keep(l) ((l)/4)

/** \brief Инициализация слепого аккумулятора

    Если [l/4]msg != NULL, то точка ЭК строится при помощи алгоритма bakeSWU.

    \precondition По адрессу acc выделено baccGq_keep(l) октетов памяти

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
 */
err_t baccDHInit(
    octet * acc,                    /*!< [out] аккумулятор */
    size_t l,                       /*!< [in]  уровень стойкости (128/192/256) */
    octet * msg,                    /*!< [in] сообщение */
    gen_i rng,                      /*!< [in]  ГСЧ */
    void* rng_state                 /*!< [in/out]  состояние ГСЧ */
);

/**
 * Число октетов, необходимое для размещения аккумулятора после добавления в него личного ключа
 * */
size_t baccDHAdd_keep(size_t l, size_t acc_len);

/** \brief Добавить личный ключ [l/4]privkey в аккумулятор [baccDHAdd_keep(l, acc_len)]acc

    \keep
        {acc} baccDHAdd_keep(l, acc_len)

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
 */
err_t baccDHAdd(
    size_t l,               /*!< уровень стойкости аккумулятора */
    octet * acc,            /*!< [in/out] аккумулятор */
    size_t acc_len,         /*!< [in] длина аккумулятора (кол-во добавленных ключей) */
    const octet* privkey    /*!< [in] личный ключ */
);

/** \brief Число октетов, необходимое для размещения доказательства proof в baccDHPrvAdd
 */
size_t baccDHPrvAdd_keep(size_t l, size_t old_acc_len);

/** \brief Создать доказательство [baccDHPrvAdd_keep(l,old_acc_len)]proof, что аккумулятор [baccGq_keep(l)*new_acc_len]new_acc
           получен из аккумулятора [baccGq_keep(l)*old_acc_len]old_acc путем добавления в него личного ключа [l/4]privkey

    \keep
        {proof} baccDHPrvAdd_keep(size_t l, size_t old_acc_len)

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
 */
err_t baccDHPrvAdd(
    octet * proof,              /*!< [out] доказательство */
    size_t l,                   /*!< уровень стойкости аккумулятора */
    const octet * old_acc,      /*!< [in] старый аккумулятор */
    const octet* new_acc,       /*!< [in] новый аккумулятор */
    size_t old_acc_len,         /*!< длина старого аккумулятора (кол-во добавленных ключей) */
    size_t new_acc_len,         /*!< длина нового аккумулятора (кол-во добавленных ключей) */
    const octet* privkey,       /*!< [in] личный ключ */
    gen_i rng,                  /*!< ГСЧ */
    void* rng_state             /*!< [in/out] состояние ГСЧ */
);

/** \brief Размер необходимой дополнительной памяти stack для baccDHVfyAdd */
size_t baccDHVfyAdd_deep(size_t l, size_t old_acc_len);

/** \brief Проверить доказательство proof, что аккумулятор [baccGq_keep(l)*new_acc_len]new_acc
           получен из аккумулятора [baccGq_keep(l)*old_acc_len]old_acc путем добавления некоторого личного ключа

    \deep
        {stack} baccDHVfyAdd_deep(l,old_acc_len)

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
 */
err_t baccDHVfyAdd(
    size_t l,                   /*!< уровень стойкости аккумулятора */
    const octet* proof,         /*!< [in] доказательство */
    const octet * old_acc,      /*!< [in] старый аккумулятор */
    const octet* new_acc,       /*!< [in] новый аккумулятор */
    size_t old_acc_len,         /*!< длина старого аккумулятора (кол-во добавленных ключей) */
    size_t new_acc_len,         /*!< длина нового аккумулятора (кол-во добавленных ключей) */
    void * stack                /*!< [in] вспомогательная память */
);

/** \brief Создать открытый ключ [l/2]pubkey для проверки доказательства добавления ключа [l/4]privkey
           в аккумулятор [baccGq_keep(l)*acc_len]acc
*/
size_t baccDHDer(
    octet * pubkey,             /*!< [out] открытый ключ */
    size_t l,                   /*!< уровень стойкости */
    const octet* acc,           /*!< [in] аккумулятор */
    size_t acc_len,             /*!< длина аккумулятора (кол-во добавленных ключей) */
    const octet* privkey        /*!< личный ключ */
);

/** \brief Число октетов, необходимое для размещения доказательства baccDHPrvDer
 */
size_t baccDHPrvDer_keep(size_t l, size_t acc_len);

/** \brief Количество вспомогательной памяти stack, необходимой для создания доказательства в baccDHPrvDer
 */
size_t baccDHPrvDer_deep(size_t l, size_t old_acc_len);

/** \brief Создать доказательство [baccDHPrvDer_keep(l,acc_len)]proof добавления
           личного ключа [l/4]privkey в аккумулятор [baccGq_keep(l)*acc_len]acc.

    \remark Если в функцию передается дополнительное сообщение [adata_size]adata,
           то proof также может выступать в качестве подписи сообщения adata,
           которая проверяется в алгоритме baccDHVfyDer.

    \keep
        {proof} baccDHPrvDer_keep(l,acc_len)

    \deep
        {stack} baccDHPrvDer_deep(l,acc_len)

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
*/
err_t baccDHPrvDer(
    octet * proof,              /*!< [out] доказательство */
    size_t l,                   /*!< уровень стойкости */
    const octet* acc,           /*!< [in] аккумулятор */
    size_t acc_len,             /*!< длина аккумулятора (кол-во добавленных ключей) */
    const octet* privkey,       /*!< личный ключ */
    const octet* adata,         /*!< [in] дополнительные данные (optional) */
    size_t adata_size,          /*!< длина дополнительных данных */
    gen_i rng,                  /*!< ГСЧ */
    void* rng_state,            /*!< [in/out] состояние ГСЧ */
    void* stack                 /*!< [in] вспомогательная память */
);

/** \brief Количество вспомогательной памяти stack, необходимой для проверки доказательства в baccDHVfyDer
 */
size_t baccDHVfyDer_deep(size_t l, size_t old_acc_len);

/** \brief Проверить доказательство [baccDHPrvDer_keep(l,acc_len)]proof добавления некоторого
           личного ключа, которым владеет создатель proof,  в аккумулятор [baccGq_keep(l)*acc_len]acc,
           используя открытый ключ [l/2]pubkey.

    \remark Если proof идет с дополнительными данными [adata_size]adata,
            то также проверяется подпись сообщения adata.

    \remark Передача adata обязательна (в случае наличия)

    \deep {stack} baccDHVfyDer_deep(l,acc_len)

    \return ERR_OK в услучае успеха, код ошибки в обратном случае
*/
err_t baccDHVfyDer(
    size_t l,                   /*!< уровень стойкости */
    const octet* acc,           /*!< [in] аккумулятор */
    size_t acc_len,             /*!< длина аккумулятора (кол-во добавленных ключей) */
    const octet * pubkey,       /*!< [out] открытый ключ */
    const octet* adata,         /*!< [in] дополнительные данные (опционально) */
    size_t adata_size,          /*!< длина дополнительных данных */
    const octet * proof,        /*!< [in]  доказательство */
    void* stack                 /*!< [in] вспомогательная память */
);

#endif //__BEE2_BACC_H
