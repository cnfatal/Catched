#include "apk_signature.h"
#include "syscall_wrapper.h"
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <android/log.h>

#define TAG "Catched"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

/*
 * APK 文件结构 (ZIP format):
 *
 * [Contents of ZIP entries]
 * [APK Signing Block]          <-- v2/v3 签名在这里
 * [Central Directory]
 * [End of Central Directory]   <-- EOCD, 文件末尾
 *
 * EOCD 包含 Central Directory 的偏移。
 * APK Signing Block 紧接在 Central Directory 之前。
 *
 * APK Signing Block 结构:
 *   - uint64: block size (不含此字段)
 *   - ID-value pairs:
 *       - uint64: pair length
 *       - uint32: ID (0x7109871a = v2, 0xf05368c0 = v3)
 *       - bytes:  value
 *   - uint64: block size (重复)
 *   - magic:  "APK Sig Block 42" (16 bytes)
 */

// APK Signing Block 魔数
static const uint8_t APK_SIG_BLOCK_MAGIC[16] = {
    'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
    'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};

// 签名方案 ID
#define APK_SIGNATURE_SCHEME_V2_ID 0x7109871a
#define APK_SIGNATURE_SCHEME_V3_ID 0xf05368c0

// EOCD 魔数
#define EOCD_SIGNATURE 0x06054b50
// EOCD 最小大小 (无 comment)
#define EOCD_MIN_SIZE 22
// EOCD 最大搜索范围 (含最大 comment 65535)
#define EOCD_MAX_SEARCH (EOCD_MIN_SIZE + 65535)

// ============================================================
// 内置 SHA-256 实现 (避免依赖 OpenSSL/mbedTLS)
// ============================================================

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct
{
    uint32_t state[8];
    uint64_t count;
    uint8_t buf[64];
} sha256_ctx;

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data)
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | data[i * 4 + 3];
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buflen = ctx->count & 63;
    ctx->count += len;

    if (buflen + len < 64)
    {
        memcpy(ctx->buf + buflen, data, len);
        return;
    }

    if (buflen > 0)
    {
        size_t fill = 64 - buflen;
        memcpy(ctx->buf + buflen, data, fill);
        sha256_transform(ctx, ctx->buf);
        data += fill;
        len -= fill;
    }

    while (len >= 64)
    {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0)
        memcpy(ctx->buf, data, len);
}

static void sha256_final(sha256_ctx *ctx, uint8_t *hash)
{
    uint64_t bits = ctx->count * 8;
    size_t buflen = ctx->count & 63;

    ctx->buf[buflen++] = 0x80;
    if (buflen > 56)
    {
        memset(ctx->buf + buflen, 0, 64 - buflen);
        sha256_transform(ctx, ctx->buf);
        buflen = 0;
    }
    memset(ctx->buf + buflen, 0, 56 - buflen);

    for (int i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - i * 8));

    sha256_transform(ctx, ctx->buf);

    for (int i = 0; i < 8; i++)
    {
        hash[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

// ============================================================
// 辅助：从 buffer 中读取小端整数
// ============================================================

static uint16_t read_le16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t read_le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

// ============================================================
// 通过 SVC 读取文件指定偏移的数据
// ============================================================

static ssize_t read_at(int fd, off_t offset, void *buf, size_t count)
{
    if (sg_lseek(fd, offset, 0 /* SEEK_SET */) < 0)
        return -1;

    size_t total = 0;
    while (total < count)
    {
        ssize_t n = sg_read(fd, (uint8_t *)buf + total, count - total);
        if (n <= 0)
            break;
        total += n;
    }
    return (ssize_t)total;
}

// ============================================================
// 查找 End of Central Directory (EOCD)
// ============================================================

static int find_eocd(int fd, off_t file_size, off_t *eocd_offset, uint32_t *cd_offset)
{
    if (file_size < EOCD_MIN_SIZE)
        return -1;

    // 从文件末尾向前搜索 EOCD 签名
    size_t search_size = (size_t)(file_size < EOCD_MAX_SEARCH ? file_size : EOCD_MAX_SEARCH);
    uint8_t *buf = (uint8_t *)sg_mmap(NULL, search_size, 3, 0x22, -1, 0);
    if (buf == (uint8_t *)-1)
        return -1;

    off_t search_start = file_size - (off_t)search_size;
    if (read_at(fd, search_start, buf, search_size) < (ssize_t)EOCD_MIN_SIZE)
    {
        sg_munmap(buf, search_size);
        return -1;
    }

    // 从后往前扫描 EOCD 魔数 (0x06054b50)
    int found = 0;
    for (ssize_t i = (ssize_t)search_size - EOCD_MIN_SIZE; i >= 0; i--)
    {
        if (read_le32(buf + i) == EOCD_SIGNATURE)
        {
            // 验证 comment length 与剩余大小一致
            uint16_t comment_len = read_le16(buf + i + 20);
            if ((size_t)i + EOCD_MIN_SIZE + comment_len == search_size)
            {
                *eocd_offset = search_start + i;
                *cd_offset = read_le32(buf + i + 16); // offset of central directory
                found = 1;
                break;
            }
        }
    }

    sg_munmap(buf, search_size);
    return found ? 0 : -1;
}

// ============================================================
// 解析 APK Signing Block
// ============================================================

/*
 * APK Signing Block v2 signer 结构:
 *   length-prefixed sequence of signers
 *     each signer:
 *       length-prefixed signed data
 *         length-prefixed sequence of digests
 *         length-prefixed sequence of certificates  <-- 我们要的
 *           each certificate: length-prefixed X.509 DER bytes
 *         length-prefixed sequence of additional attributes
 *       length-prefixed sequence of signatures
 *       length-prefixed public key
 */

static int parse_signer_cert(const uint8_t *data, size_t len, unsigned char *out_hash)
{
    if (len < 4)
        return -1;

    // signers sequence
    uint32_t signers_len = read_le32(data);
    if (signers_len + 4 > len)
        return -1;
    const uint8_t *signers = data + 4;

    // first signer
    if (signers_len < 4)
        return -1;
    uint32_t signer_len = read_le32(signers);
    if (signer_len + 4 > signers_len)
        return -1;
    const uint8_t *signer = signers + 4;

    // signed data (first field of signer)
    if (signer_len < 4)
        return -1;
    uint32_t signed_data_len = read_le32(signer);
    if (signed_data_len + 4 > signer_len)
        return -1;
    const uint8_t *signed_data = signer + 4;

    // digests sequence (skip)
    if (signed_data_len < 4)
        return -1;
    uint32_t digests_len = read_le32(signed_data);
    if (digests_len + 4 > signed_data_len)
        return -1;

    // certificates sequence
    const uint8_t *certs_ptr = signed_data + 4 + digests_len;
    uint32_t remaining = signed_data_len - 4 - digests_len;
    if (remaining < 4)
        return -1;
    uint32_t certs_len = read_le32(certs_ptr);
    if (certs_len + 4 > remaining)
        return -1;
    const uint8_t *certs = certs_ptr + 4;

    // first certificate
    if (certs_len < 4)
        return -1;
    uint32_t cert_len = read_le32(certs);
    if (cert_len + 4 > certs_len)
        return -1;
    const uint8_t *cert_der = certs + 4;

    // SHA-256 of the certificate DER bytes
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, cert_der, cert_len);
    sha256_final(&ctx, out_hash);

    LOGD("APK sig: parsed cert DER (%u bytes)", cert_len);
    return 0;
}

// ============================================================
// 主入口
// ============================================================

int apk_extract_cert_sha256(const char *apk_path, unsigned char *out_hash)
{
    if (!apk_path || !out_hash)
        return -1;

    int fd = sg_open(apk_path, O_RDONLY);
    if (fd < 0)
    {
        LOGD("APK sig: cannot open %s", apk_path);
        return -1;
    }

    // 获取文件大小
    off_t file_size = sg_lseek(fd, 0, 2 /* SEEK_END */);
    if (file_size <= 0)
    {
        sg_close(fd);
        return -1;
    }

    // 1. 查找 EOCD → 获取 Central Directory 偏移
    off_t eocd_offset;
    uint32_t cd_offset;
    if (find_eocd(fd, file_size, &eocd_offset, &cd_offset) != 0)
    {
        LOGD("APK sig: EOCD not found");
        sg_close(fd);
        return -2;
    }

    // 2. APK Signing Block 在 CD 之前
    // 末尾是: [block_size (8)] [magic (16)] → 共 24 字节
    if (cd_offset < 24)
    {
        sg_close(fd);
        return -3;
    }

    // 读取 signing block 尾部 24 字节
    uint8_t tail[24];
    if (read_at(fd, (off_t)cd_offset - 24, tail, 24) != 24)
    {
        sg_close(fd);
        return -3;
    }

    // 验证魔数
    if (memcmp(tail + 8, APK_SIG_BLOCK_MAGIC, 16) != 0)
    {
        LOGD("APK sig: signing block magic not found");
        sg_close(fd);
        return -3;
    }

    uint64_t block_size = read_le64(tail);
    // block 的起始位置 = cd_offset - block_size - 8 (前面的 size 字段)
    if (block_size > (uint64_t)cd_offset || block_size < 32)
    {
        sg_close(fd);
        return -3;
    }

    off_t block_start = (off_t)cd_offset - (off_t)block_size - 8;
    // 读取 block 开头的 size (交叉验证)
    uint8_t head[8];
    if (read_at(fd, block_start, head, 8) != 8)
    {
        sg_close(fd);
        return -3;
    }

    uint64_t head_size = read_le64(head);
    if (head_size != block_size)
    {
        LOGD("APK sig: block size mismatch (head=%llu tail=%llu)",
             (unsigned long long)head_size, (unsigned long long)block_size);
        sg_close(fd);
        return -3;
    }

    // 3. 读取整个 signing block 的 ID-value pairs
    // pairs 区域: block_start + 8 到 cd_offset - 24
    size_t pairs_size = (size_t)(block_size - 24); // 减去尾部 size+magic
    if (pairs_size > 4 * 1024 * 1024)
    {
        // 安全限制: 签名块不应超过 4MB
        sg_close(fd);
        return -3;
    }

    uint8_t *pairs_buf = (uint8_t *)sg_mmap(NULL, pairs_size, 3, 0x22, -1, 0);
    if (pairs_buf == (uint8_t *)-1)
    {
        sg_close(fd);
        return -3;
    }

    if (read_at(fd, block_start + 8, pairs_buf, pairs_size) != (ssize_t)pairs_size)
    {
        sg_munmap(pairs_buf, pairs_size);
        sg_close(fd);
        return -3;
    }
    sg_close(fd);

    // 4. 遍历 ID-value pairs，优先找 v3，回退 v2
    int result = -4;
    const uint8_t *v2_value = NULL;
    uint32_t v2_value_len = 0;

    size_t pos = 0;
    while (pos + 12 <= pairs_size)
    {
        uint64_t pair_len = read_le64(pairs_buf + pos);
        pos += 8;
        if (pair_len < 4 || pos + pair_len > pairs_size)
            break;

        uint32_t id = read_le32(pairs_buf + pos);
        const uint8_t *value = pairs_buf + pos + 4;
        uint32_t value_len = (uint32_t)(pair_len - 4);

        if (id == APK_SIGNATURE_SCHEME_V3_ID)
        {
            // v3 优先
            LOGD("APK sig: found v3 signing block (%u bytes)", value_len);
            result = parse_signer_cert(value, value_len, out_hash);
            if (result == 0)
                break;
        }
        else if (id == APK_SIGNATURE_SCHEME_V2_ID)
        {
            v2_value = value;
            v2_value_len = value_len;
        }

        pos += (size_t)pair_len;
    }

    // 如果 v3 没有成功，尝试 v2
    if (result != 0 && v2_value != NULL)
    {
        LOGD("APK sig: found v2 signing block (%u bytes)", v2_value_len);
        result = parse_signer_cert(v2_value, v2_value_len, out_hash);
    }

    sg_munmap(pairs_buf, pairs_size);

    if (result != 0)
    {
        LOGD("APK sig: no v2/v3 signature found");
    }
    return result;
}
