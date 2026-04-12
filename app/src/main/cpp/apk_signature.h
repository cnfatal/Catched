#ifndef CATCHED_APK_SIGNATURE_H
#define CATCHED_APK_SIGNATURE_H

/**
 * APK 签名块解析器
 *
 * 通过 SVC 直接读取 APK 文件，解析 APK Signing Block (v2/v3)，
 * 提取签名证书的 SHA-256 指纹。
 * 完全绕过 PackageManager Java API，防止 PM hook 伪造证书。
 */

/**
 * 从 APK 文件直接解析签名证书的 SHA-256 指纹
 *
 * @param apk_path   APK 文件路径 (来自 sourceDir)
 * @param out_hash   输出 SHA-256 哈希值 (32 bytes)
 * @return 0=成功, -1=文件错误, -2=非 ZIP, -3=签名块不存在, -4=证书解析失败
 */
int apk_extract_cert_sha256(const char *apk_path, unsigned char *out_hash);

#endif // CATCHED_APK_SIGNATURE_H
