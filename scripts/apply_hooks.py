#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  SukiSU Ultra Manual Hook Patcher
  Untuk: LG V60 ThinQ (timelm) — Linux kernel 4.19 non-GKI
  
  Perubahan dari versi sebelumnya:
  - FIX: Atomic write via temp file + os.replace()
  - FIX: Counter tidak dobel-increment saat baca() gagal
  - FIX: failed_files menggunakan set() untuk mencegah duplikasi
  - FIX: anchor replacement tidak menghilangkan indentasi
  - FIX: Backup .bak dihapus setelah write sukses
  - FIX: Encoding menggunakan surrogateescape untuk fidelitas byte
  - FIX: EXPORT_SYMBOL_GPL dihilangkan untuk kernel 4.19 non-GKI
═══════════════════════════════════════════════════════════════
"""

import os
import sys
import shutil
import tempfile

KERNEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."

hasil = {"berhasil": 0, "sudah_ada": 0, "gagal": 0}

# FIX: Gunakan set() untuk mencegah duplikasi entri failed_files
failed_files: set = set()

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def path(relative):
    return os.path.join(KERNEL_DIR, relative)

def baca(file_rel):
    """
    Baca file dan return kontennya sebagai string.
    Return None jika file tidak ditemukan atau error.
    FIX: Fungsi ini TIDAK memodifikasi counter hasil[] atau failed_files.
         Tanggung jawab tersebut ada di fungsi patch pemanggil.
    """
    p = path(file_rel)
    try:
        # FIX: Gunakan surrogateescape agar byte non-UTF8 dipreservasi
        # dengan benar saat file dibaca dan ditulis kembali.
        # errors='replace' sebelumnya bisa merusak binary content secara diam-diam.
        with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
            return f.read()
    except FileNotFoundError:
        print(f"  ❌ {file_rel}: FILE TIDAK DITEMUKAN")
        return None
    except Exception as e:
        print(f"  ❌ {file_rel}: Error membaca: {e}")
        return None

def tulis(file_rel, konten):
    """
    Tulis konten ke file secara atomic menggunakan temp file + os.replace().
    FIX: Atomic write mencegah file korup parsial jika proses diinterupsi.
    FIX: Backup .bak dihapus setelah write berhasil agar tidak polusi source tree.
    """
    p = path(file_rel)
    backup = p + ".bak"

    # Buat backup sebelum modifikasi
    if os.path.exists(p):
        shutil.copy2(p, backup)

    try:
        # FIX: Tulis ke temporary file dulu, lalu atomic rename
        # os.replace() adalah atomic di POSIX (single filesystem)
        dir_name = os.path.dirname(p)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            errors="surrogateescape",
            dir=dir_name,
            delete=False,
            suffix=".tmp"
        ) as tmp:
            tmp.write(konten)
            tmp_path = tmp.name

        os.replace(tmp_path, p)

        # FIX: Hapus backup setelah write sukses agar tidak polusi source tree
        if os.path.exists(backup):
            os.unlink(backup)

    except Exception as e:
        # Rollback dari backup jika ada exception
        if os.path.exists(backup):
            shutil.move(backup, p)
        # Bersihkan temp file yang mungkin tertinggal
        if 'tmp_path' in dir() and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise e

def sudah_dipatch(konten, marker):
    return konten is not None and marker in konten

def log_ok(msg):
    hasil["berhasil"] += 1
    print(f"  ✅ {msg}")

def log_skip(msg):
    hasil["sudah_ada"] += 1
    print(f"  ⏭️  {msg}")

def log_gagal(msg, file_rel=None):
    """
    FIX: log_gagal hanya dipanggil dari fungsi patch tingkat atas,
    bukan dari baca(). file_rel opsional untuk mencatat ke failed_files.
    """
    hasil["gagal"] += 1
    print(f"  ❌ {msg}")
    if file_rel:
        failed_files.add(file_rel)  # FIX: set.add() otomatis mencegah duplikasi

def log_info(msg):
    print(f"  ℹ️  {msg}")

# ─────────────────────────────────────────────────────────────
# PATCH 1: fs/exec.c
# ─────────────────────────────────────────────────────────────
def patch_exec_c():
    FILE = "fs/exec.c"
    c = baca(FILE)
    if c is None:
        # FIX: Counter dan failed_files dikelola di sini, bukan di baca()
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_execveat_hook"):
        log_skip(FILE)
        return

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

    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_execveat_hook))\n"
        "\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
        "\telse\n"
        "\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);\n"
        "#endif\n"
    )

    FUNGSI = "static int do_execveat_common("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi do_execveat_common tidak ditemukan", FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    berhasil = False
    # FIX: Insert HOOK sebelum anchor TANPA memodifikasi anchor itu sendiri.
    # Versi sebelumnya menggunakan anchor.lstrip() yang menghilangkan leading \t
    # dari anchor, menyebabkan do_execveat_common kehilangan indentasi.
    for anchor in ["\treturn __do_execve_file(", "\t__do_execve_file("]:
        if anchor in c:
            c = c.replace(anchor, HOOK + anchor, 1)
            berhasil = True
            break

    if not berhasil:
        log_gagal(f"{FILE}: titik insert tidak ditemukan", FILE)
        return

    tulis(FILE, c)
    log_ok(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 2: fs/open.c
# ─────────────────────────────────────────────────────────────
def patch_open_c():
    FILE = "fs/open.c"
    c = baca(FILE)
    if c is None:
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_handle_faccessat"):
        log_skip(FILE)
        return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
        "                               int *mode, int *flags);\n"
        "#endif\n"
    )

    # HOOK: #ifdef di kolom 0 (preprocessor convention), isi diindentasi 1 tab
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "#endif\n"
    )

    FUNGSI_TARGET = None
    for fn in ["long do_faccessat(", "SYSCALL_DEFINE3(faccessat,"]:
        if fn in c:
            FUNGSI_TARGET = fn
            break

    if FUNGSI_TARGET is None:
        log_gagal(f"{FILE}: fungsi faccessat tidak ditemukan", FILE)
        return

    c = c.replace(FUNGSI_TARGET, DEKLARASI + FUNGSI_TARGET, 1)

    # FIX: Insert HOOK sebelum anchor tanpa memodifikasi anchor
    for anchor in ["\tif (mode & ~S_IRWXO)", "\tunsigned int lookup_flags = LOOKUP_FOLLOW;"]:
        if anchor in c:
            c = c.replace(anchor, HOOK + anchor, 1)
            tulis(FILE, c)
            log_ok(FILE)
            return

    log_gagal(f"{FILE}: titik insert tidak ditemukan", FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 3: fs/read_write.c
# ─────────────────────────────────────────────────────────────
def patch_read_write_c():
    FILE = "fs/read_write.c"
    c = baca(FILE)
    if c is None:
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_vfs_read_hook"):
        log_skip(FILE)
        return

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
    )

    FUNGSI = "ssize_t vfs_read("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi vfs_read tidak ditemukan", FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    ANCHOR = "\tif (!(file->f_mode & FMODE_READ))"
    if ANCHOR in c:
        # FIX: Insert HOOK sebelum anchor tanpa memodifikasi anchor
        c = c.replace(ANCHOR, HOOK + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan", FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 4: fs/stat.c
# ─────────────────────────────────────────────────────────────
def patch_stat_c():
    FILE = "fs/stat.c"
    c = baca(FILE)
    if c is None:
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_handle_stat"):
        log_skip(FILE)
        return

    DEKLARASI = (
        "\n"
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n"
        "                          int *flags);\n"
        "#endif\n"
    )

    fungsi_anchor = None
    for fungsi, var_flags in [
        ("int vfs_statx(", "&flags"),
        ("int vfs_fstatat(", "&flag"),
    ]:
        if fungsi in c:
            fungsi_anchor = (fungsi, var_flags)
            break

    if fungsi_anchor is None:
        log_gagal(f"{FILE}: fungsi vfs_statx/vfs_fstatat tidak ditemukan", FILE)
        return

    fungsi, var_flags = fungsi_anchor

    HOOK = (
        "#ifdef CONFIG_KSU\n"
        f"\tksu_handle_stat(&dfd, &filename, {var_flags});\n"
        "#endif\n"
    )

    # FIX: Simpan c_original untuk rollback jika anchor tidak ditemukan
    # setelah DEKLARASI sudah di-insert (mencegah state korup in-memory)
    c_with_decl = c.replace(fungsi, DEKLARASI + fungsi, 1)

    for anchor in ["\tint error = -EINVAL;\n", "\tunsigned int lookup_flags"]:
        if anchor in c_with_decl:
            # FIX: Insert HOOK sebelum anchor tanpa memodifikasi anchor
            c_final = c_with_decl.replace(anchor, HOOK + anchor, 1)
            tulis(FILE, c_final)
            log_ok(FILE)
            return

    # FIX: Jika anchor tidak ditemukan, jangan tulis c yang sudah dimodifikasi
    log_gagal(f"{FILE}: titik insert tidak ditemukan setelah {fungsi}", FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 5: drivers/input/input.c (CRITICAL!)
# ─────────────────────────────────────────────────────────────
def patch_input_c():
    FILE = "drivers/input/input.c"
    c = baca(FILE)
    if c is None:
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_input_hook"):
        log_skip(FILE)
        return

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
    )

    FUNGSI = "static void input_handle_event("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi input_handle_event tidak ditemukan", FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    # FIX: Insert HOOK sebelum anchor tanpa memodifikasi anchor
    for anchor in ["\tif (disposition != INPUT_IGNORE_EVENT", "\tswitch (disposition)"]:
        if anchor in c:
            c = c.replace(anchor, HOOK + anchor, 1)
            tulis(FILE, c)
            log_ok(FILE)
            return

    log_gagal(f"{FILE}: titik insert tidak ditemukan", FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 6: fs/devpts/inode.c
# ─────────────────────────────────────────────────────────────
def patch_devpts_c():
    FILE = "fs/devpts/inode.c"
    c = baca(FILE)
    if c is None:
        log_gagal(f"{FILE}: FILE TIDAK DITEMUKAN", FILE)
        return

    if sudah_dipatch(c, "ksu_handle_devpts"):
        log_skip(FILE)
        return

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
    )

    FUNGSI = "void *devpts_get_priv("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi devpts_get_priv tidak ditemukan", FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    ANCHOR = "\tif (dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC)"
    if ANCHOR in c:
        # FIX: Insert HOOK sebelum anchor tanpa memodifikasi anchor
        c = c.replace(ANCHOR, HOOK + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan", FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 7: fs/namespace.c (Optional backport path_umount)
# ─────────────────────────────────────────────────────────────
def patch_namespace_c():
    FILE = "fs/namespace.c"
    c = baca(FILE)
    if c is None:
        # Namespace.c adalah optional patch — log info bukan gagal
        log_info(f"{FILE}: file tidak ditemukan, skip optional backport")
        return

    if "int path_umount(" in c:
        log_skip(f"{FILE} (path_umount sudah ada)")
        return

    # FIX (Kode Lama): EXPORT_SYMBOL_GPL dihilangkan karena:
    # 1. Kernel 4.19 non-GKI: KSU dikompilasi langsung ke kernel, bukan module
    # 2. EXPORT_SYMBOL_GPL di dalam #ifdef block dapat menyebabkan masalah
    #    visibility pada linker script kernel 4.19 tertentu
    # 3. Untuk forward compat, cukup deklarasi 'extern' di KSU source-nya sendiri
    PATH_UMOUNT_CODE = """
#ifdef CONFIG_KSU
/* KernelSU/SukiSU Ultra: backport path_umount untuk kernel 4.19 */
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
#endif /* CONFIG_KSU */

"""

    for anchor in ["static int ksys_umount(", "SYSCALL_DEFINE2(umount,"]:
        if anchor in c:
            c = c.replace(anchor, PATH_UMOUNT_CODE + anchor, 1)
            tulis(FILE, c)
            log_ok(f"{FILE} (backport path_umount)")
            return

    log_info(f"{FILE}: ksys_umount tidak ditemukan, path_umount tidak di-backport (optional)")

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("═" * 60)
    print("  SukiSU Ultra — Manual Hook Patcher")
    print(f"  Kernel dir: {os.path.abspath(KERNEL_DIR)}")
    print("═" * 60)
    print()

    patch_exec_c()
    patch_open_c()
    patch_read_write_c()
    patch_stat_c()
    patch_input_c()
    patch_devpts_c()
    patch_namespace_c()

    print()
    print("═" * 60)
    print(f"  Hasil: ✅ {hasil['berhasil']}  |  ⏭️ {hasil['sudah_ada']}  |  ❌ {hasil['gagal']}")
    print("═" * 60)
    print()

    CRITICAL_FILES = {"fs/exec.c", "fs/open.c", "drivers/input/input.c"}

    if hasil["gagal"] > 0:
        print("⚠️  Ada patch yang gagal:")
        # FIX: Sort untuk output konsisten; failed_files adalah set jadi tidak ada duplikasi
        for f in sorted(failed_files):
            is_critical = f in CRITICAL_FILES
            marker = "🔴 CRITICAL" if is_critical else "⚠️  OPTIONAL"
            print(f"   {marker}: {f}")

        critical_failed = bool(failed_files & CRITICAL_FILES)
        if critical_failed:
            print()
            print("❌ Critical patch gagal! Build akan error.")
            sys.exit(1)
        else:
            print()
            print("ℹ️  Hanya optional patch yang gagal, build mungkin tetap jalan.")
            sys.exit(0)
    else:
        print("✅ Semua patch berhasil!")
        sys.exit(0)
