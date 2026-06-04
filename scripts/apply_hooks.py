#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  SuKiSu Ultra Manual Hook Patcher
  Untuk: LG V60 ThinQ (timelm) — Linux kernel 4.19 non-GKI
═══════════════════════════════════════════════════════════════
  Script ini menambahkan "hook" ke beberapa file kernel agar
  SuKiSu Ultra / KernelSU bisa berjalan di kernel non-GKI.

  File yang di-patch:
    1. fs/exec.c              ← deteksi eksekusi program
    2. fs/open.c              ← intercept file access check
    3. fs/read_write.c        ← intercept baca file
    4. fs/stat.c              ← intercept stat file
    5. drivers/input/input.c  ← safe mode (penting!)
    6. fs/devpts/inode.c      ← perbaikan terminal
    7. fs/namespace.c         ← backport path_umount
═══════════════════════════════════════════════════════════════
"""

import os
import sys

# Ambil path kernel dari argumen, default "." (folder sekarang)
KERNEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."

# Counter hasil
hasil = {"berhasil": 0, "sudah_ada": 0, "gagal": 0}

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def path(relative):
    """Gabungkan kernel dir dengan path relatif."""
    return os.path.join(KERNEL_DIR, relative)

def baca(file_rel):
    """Baca file, return None jika tidak ada."""
    p = path(file_rel)
    if not os.path.exists(p):
        log_gagal(f"{file_rel}: FILE TIDAK DITEMUKAN")
        return None
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

def tulis(file_rel, konten):
    """Tulis konten ke file."""
    with open(path(file_rel), "w", encoding="utf-8") as f:
        f.write(konten)

def sudah_dipatch(konten):
    """Cek apakah file sudah pernah di-patch sebelumnya."""
    return konten is not None and "CONFIG_KSU" in konten

def log_ok(msg):
    hasil["berhasil"] += 1
    print(f"  ✅ {msg}")

def log_skip(msg):
    hasil["sudah_ada"] += 1
    print(f"  ⏭️  {msg} (sudah di-patch sebelumnya, skip)")

def log_gagal(msg):
    hasil["gagal"] += 1
    print(f"  ❌ {msg}")

def log_info(msg):
    print(f"  ℹ️  {msg}")


# ─────────────────────────────────────────────────────────────
# PATCH 1: fs/exec.c
# Tujuan: Intercept saat program dijalankan (execve)
# ─────────────────────────────────────────────────────────────
def patch_exec_c():
    FILE = "fs/exec.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    # Deklarasi fungsi eksternal yang akan kita panggil
    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern bool ksu_execveat_hook __read_mostly;\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
        "                               void *argv, void *envp, int *flags);\n"
        "extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,\n"
        "                                        void *argv, void *envp, int *flags);\n"
        "#endif\n"
    )

    # Kode hook yang akan dimasukkan
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_execveat_hook))\n"
        "\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
        "\telse\n"
        "\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);\n"
        "#endif\n"
        "\t"
    )

    # Cari fungsi target
    FUNGSI = "static int do_execveat_common("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi do_execveat_common tidak ditemukan")
        return

    # Tambahkan deklarasi sebelum definisi fungsi
    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    # Cari titik insert hook (sebelum return __do_execve_file)
    berhasil = False
    for anchor in ["return __do_execve_file(", "\t__do_execve_file("]:
        if anchor in c:
            c = c.replace(anchor, HOOK + anchor.lstrip(), 1)
            berhasil = True
            break

    if not berhasil:
        log_gagal(f"{FILE}: titik insert (__do_execve_file) tidak ditemukan")
        return

    tulis(FILE, c)
    log_ok(FILE)


# ─────────────────────────────────────────────────────────────
# PATCH 2: fs/open.c
# Tujuan: Intercept pengecekan akses file (faccessat)
# ─────────────────────────────────────────────────────────────
def patch_open_c():
    FILE = "fs/open.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
        "                               int *mode, int *flags);\n"
        "#endif\n"
    )
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "#endif\n"
        "\t"
    )

    # Coba do_faccessat (kernel >= 4.17) atau SYSCALL langsung
    FUNGSI_TARGET = None
    for fn in ["long do_faccessat(", "SYSCALL_DEFINE3(faccessat,"]:
        if fn in c:
            FUNGSI_TARGET = fn
            break

    if FUNGSI_TARGET is None:
        log_gagal(f"{FILE}: fungsi faccessat tidak ditemukan")
        return

    c = c.replace(FUNGSI_TARGET, DEKLARASI + FUNGSI_TARGET, 1)

    # Titik insert: sebelum "if (mode & ~S_IRWXO)"
    ANCHOR = "\tif (mode & ~S_IRWXO)"
    if ANCHOR in c:
        c = c.replace(ANCHOR, "\t" + HOOK.rstrip() + "\n" + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    # Fallback: setelah "unsigned int lookup_flags"
    ANCHOR2 = "\tunsigned int lookup_flags = LOOKUP_FOLLOW;"
    if ANCHOR2 in c:
        c = c.replace(ANCHOR2, ANCHOR2 + "\n\t" + HOOK.rstrip(), 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")


# ─────────────────────────────────────────────────────────────
# PATCH 3: fs/read_write.c
# Tujuan: Intercept operasi baca file (vfs_read)
# ─────────────────────────────────────────────────────────────
def patch_read_write_c():
    FILE = "fs/read_write.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern bool ksu_vfs_read_hook __read_mostly;\n"
        "extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,\n"
        "                               size_t *count_ptr, loff_t **pos);\n"
        "#endif\n"
    )
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_vfs_read_hook))\n"
        "\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);\n"
        "#endif\n"
        "\t"
    )

    FUNGSI = "ssize_t vfs_read("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi vfs_read tidak ditemukan")
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    # Titik insert: sebelum pengecekan pertama di dalam fungsi
    ANCHOR = "\tif (!(file->f_mode & FMODE_READ))"
    if ANCHOR in c:
        c = c.replace(ANCHOR, "\t" + HOOK.rstrip() + "\n" + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")


# ─────────────────────────────────────────────────────────────
# PATCH 4: fs/stat.c
# Tujuan: Intercept pengecekan info file (stat)
# ─────────────────────────────────────────────────────────────
def patch_stat_c():
    FILE = "fs/stat.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n"
        "                          int *flags);\n"
        "#endif\n"
    )

    # vfs_statx menggunakan 'flags', vfs_fstatat menggunakan 'flag'
    # Coba keduanya
    for fungsi, var_flags in [
        ("int vfs_statx(", "&flags"),
        ("int vfs_fstatat(", "&flag"),
    ]:
        if fungsi not in c:
            continue

        HOOK = (
            "#ifdef CONFIG_KSU\n"
            f"\tksu_handle_stat(&dfd, &filename, {var_flags});\n"
            "#endif\n"
            "\t"
        )

        c = c.replace(fungsi, DEKLARASI + fungsi, 1)

        # Titik insert: setelah pengecekan flag awal
        for anchor in [
            "\tint error = -EINVAL;\n",
            "\tunsigned int lookup_flags",
        ]:
            if anchor in c:
                c = c.replace(anchor, anchor + "\t" + HOOK.rstrip() + "\n", 1)
                tulis(FILE, c)
                log_ok(FILE)
                return

    log_gagal(f"{FILE}: fungsi vfs_statx/vfs_fstatat tidak ditemukan")


# ─────────────────────────────────────────────────────────────
# PATCH 5: drivers/input/input.c
# Tujuan: Safe mode — tekan kombinasi tombol untuk nonaktifkan root
#         PENTING: tanpa ini, jika root bermasalah, HP bisa bootloop
# ─────────────────────────────────────────────────────────────
def patch_input_c():
    FILE = "drivers/input/input.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern bool ksu_input_hook __read_mostly;\n"
        "extern int ksu_handle_input_handle_event(unsigned int *type,\n"
        "                                          unsigned int *code, int *value);\n"
        "#endif\n"
    )
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_input_hook))\n"
        "\t\tksu_handle_input_handle_event(&type, &code, &value);\n"
        "#endif\n"
        "\t"
    )

    FUNGSI = "static void input_handle_event("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi input_handle_event tidak ditemukan")
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    # Titik insert: setelah baris disposition, sebelum if pertama
    for anchor in [
        "\tif (disposition != INPUT_IGNORE_EVENT",
        "\tswitch (disposition)",
    ]:
        if anchor in c:
            c = c.replace(anchor, "\t" + HOOK.rstrip() + "\n" + anchor, 1)
            tulis(FILE, c)
            log_ok(FILE)
            return

    log_gagal(f"{FILE}: titik insert (disposition) tidak ditemukan")


# ─────────────────────────────────────────────────────────────
# PATCH 6: fs/devpts/inode.c
# Tujuan: Perbaikan agar terminal (shell) bisa berjalan normal
# ─────────────────────────────────────────────────────────────
def patch_devpts_c():
    FILE = "fs/devpts/inode.c"
    c = baca(FILE)
    if c is None: return
    if sudah_dipatch(c): log_skip(FILE); return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_devpts(struct inode*);\n"
        "#endif\n"
    )
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_devpts(dentry->d_inode);\n"
        "#endif\n"
        "\t"
    )

    FUNGSI = "void *devpts_get_priv("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi devpts_get_priv tidak ditemukan")
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    ANCHOR = "\tif (dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC)"
    if ANCHOR in c:
        c = c.replace(ANCHOR, "\t" + HOOK.rstrip() + "\n" + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")


# ─────────────────────────────────────────────────────────────
# PATCH 7: fs/namespace.c
# Tujuan: Backport fungsi path_umount (dibutuhkan oleh modul KSU)
#         Fungsi ini ada di kernel baru tapi tidak ada di 4.19
# ─────────────────────────────────────────────────────────────
def patch_namespace_c():
    FILE = "fs/namespace.c"
    c = baca(FILE)
    if c is None: return

    # Cek apakah path_umount sudah ada (mungkin sudah di-backport)
    if "int path_umount(" in c:
        log_skip(f"{FILE} (path_umount sudah ada)")
        return

    # Kode fungsi path_umount yang akan ditambahkan
    PATH_UMOUNT_CODE = """
/* KernelSU: backport path_umount dari kernel yang lebih baru */
static int can_umount(const struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);

\tif (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
\t\treturn -EINVAL;
\tif (!may_mount())
\t\treturn -EPERM;
\tif (path->dentry != path->mnt->mnt_root)
\t\treturn -EINVAL;
\tif (!check_mnt(mnt))
\t\treturn -EINVAL;
\tif (mnt->mnt.mnt_flags & MNT_LOCKED)
\t\treturn -EINVAL;
\tif (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
\t\treturn -EPERM;
\treturn 0;
}

int path_umount(struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);
\tint ret;

\tret = can_umount(path, flags);
\tif (!ret)
\t\tret = do_umount(mnt, flags);

\tdput(path->dentry);
\tmntput_no_expire(mnt);
\treturn ret;
}

"""

    # Masukkan sebelum ksys_umount atau SYSCALL umount
    for anchor in ["static int ksys_umount(", "SYSCALL_DEFINE2(umount,"]:
        if anchor in c:
            c = c.replace(anchor, PATH_UMOUNT_CODE + anchor, 1)
            tulis(FILE, c)
            log_ok(f"{FILE} (backport path_umount)")
            return

    # Jika anchor tidak ditemukan, ini warning saja (tidak fatal)
    log_info(f"{FILE}: ksys_umount tidak ditemukan, path_umount di-skip")
    hasil["berhasil"] -= 1  # jangan hitung sebagai berhasil


# ─────────────────────────────────────────────────────────────
# MAIN: Jalankan semua patch
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("═" * 55)
    print("  SuKiSu Ultra — Manual Hook Patcher")
    print(f"  Kernel dir: {os.path.abspath(KERNEL_DIR)}")
    print("═" * 55)
    print()

    print("Memulai patch...\n")

    patch_exec_c()
    patch_open_c()
    patch_read_write_c()
    patch_stat_c()
    patch_input_c()
    patch_devpts_c()
    patch_namespace_c()

    print()
    print("═" * 55)
    print(f"  Hasil: ✅ {hasil['berhasil']} berhasil  |  "
          f"⏭️  {hasil['sudah_ada']} di-skip  |  "
          f"❌ {hasil['gagal']} gagal")
    print("═" * 55)
    print()

    if hasil["gagal"] > 0:
        print("⚠️  PERINGATAN: Ada patch yang gagal!")
        print("   Kemungkinan struktur kode sumber berbeda dari yang diharapkan.")
        print("   Build mungkin tetap berhasil jika file yang gagal tidak kritis,")
        print("   tapi SuKiSu mungkin tidak berfungsi sempurna.")
        print()
        # Keluar dengan error agar GitHub Actions menampilkan status FAIL
        sys.exit(1)
    else:
        print("✅ Semua patch berhasil! Melanjutkan ke proses build...")
        print()
        sys.exit(0)
