#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  SukiSU Ultra Manual Hook Patcher
  Untuk: LG V60 ThinQ (timelm) — Linux kernel 4.19 non-GKI
═══════════════════════════════════════════════════════════════
"""

import os
import sys
import shutil

# Ambil path kernel dari argumen
KERNEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."

# Counter & tracking
hasil = {"berhasil": 0, "sudah_ada": 0, "gagal": 0}
failed_files = []

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def path(relative):
    """Gabungkan kernel dir dengan path relatif."""
    return os.path.join(KERNEL_DIR, relative)

def baca(file_rel):
    """Baca file, return None jika tidak ada."""
    p = path(file_rel)
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        log_gagal(f"{file_rel}: FILE TIDAK DITEMUKAN")
        failed_files.append(file_rel)
        return None
    except Exception as e:
        log_gagal(f"{file_rel}: Error membaca: {e}")
        failed_files.append(file_rel)
        return None

def tulis(file_rel, konten):
    """Tulis konten ke file dengan backup."""
    p = path(file_rel)
    
    # Backup file asli
    if os.path.exists(p):
        backup = p + ".bak"
        shutil.copy2(p, backup)
    
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(konten)
    except Exception as e:
        # Restore backup jika gagal
        if os.path.exists(p + ".bak"):
            shutil.move(p + ".bak", p)
        raise e

def sudah_dipatch(konten, marker):
    """Cek marker unik (lebih spesifik dari global CONFIG_KSU)."""
    return konten is not None and marker in konten

def log_ok(msg):
    hasil["berhasil"] += 1
    print(f"  ✅ {msg}")

def log_skip(msg):
    hasil["sudah_ada"] += 1
    print(f"  ⏭️  {msg}")

def log_gagal(msg):
    hasil["gagal"] += 1
    print(f"  ❌ {msg}")

def log_info(msg):
    print(f"  ℹ️  {msg}")

# ─────────────────────────────────────────────────────────────
# PATCH 1: fs/exec.c
# ─────────────────────────────────────────────────────────────
def patch_exec_c():
    FILE = "fs/exec.c"
    c = baca(FILE)
    if c is None: return
    
    # Cek dengan marker unik
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
        "\t"
    )

    FUNGSI = "static int do_execveat_common("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi do_execveat_common tidak ditemukan")
        failed_files.append(FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    berhasil = False
    for anchor in ["return __do_execve_file(", "\t__do_execve_file("]:
        if anchor in c:
            c = c.replace(anchor, HOOK + anchor.lstrip(), 1)
            berhasil = True
            break

    if not berhasil:
        log_gagal(f"{FILE}: titik insert tidak ditemukan")
        failed_files.append(FILE)
        return

    tulis(FILE, c)
    log_ok(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 2: fs/open.c
# ─────────────────────────────────────────────────────────────
def patch_open_c():
    FILE = "fs/open.c"
    c = baca(FILE)
    if c is None: return
    
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
    
    HOOK = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "#endif\n"
        "\t"
    )

    FUNGSI_TARGET = None
    for fn in ["long do_faccessat(", "SYSCALL_DEFINE3(faccessat,"]:
        if fn in c:
            FUNGSI_TARGET = fn
            break

    if FUNGSI_TARGET is None:
        log_gagal(f"{FILE}: fungsi faccessat tidak ditemukan")
        failed_files.append(FILE)
        return

    c = c.replace(FUNGSI_TARGET, DEKLARASI + FUNGSI_TARGET, 1)

    for anchor in ["\tif (mode & ~S_IRWXO)", "\tunsigned int lookup_flags = LOOKUP_FOLLOW;"]:
        if anchor in c:
            c = c.replace(anchor, "\t" + HOOK.rstrip() + "\n" + anchor, 1)
            tulis(FILE, c)
            log_ok(FILE)
            return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")
    failed_files.append(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 3: fs/read_write.c
# ─────────────────────────────────────────────────────────────
def patch_read_write_c():
    FILE = "fs/read_write.c"
    c = baca(FILE)
    if c is None: return
    
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
        "\t"
    )

    FUNGSI = "ssize_t vfs_read("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi vfs_read tidak ditemukan")
        failed_files.append(FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    ANCHOR = "\tif (!(file->f_mode & FMODE_READ))"
    if ANCHOR in c:
        c = c.replace(ANCHOR, "\t" + HOOK.rstrip() + "\n" + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")
    failed_files.append(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 4: fs/stat.c
# ─────────────────────────────────────────────────────────────
def patch_stat_c():
    FILE = "fs/stat.c"
    c = baca(FILE)
    if c is None: return
    
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

        for anchor in ["\tint error = -EINVAL;\n", "\tunsigned int lookup_flags"]:
            if anchor in c:
                c = c.replace(anchor, anchor + "\t" + HOOK.rstrip() + "\n", 1)
                tulis(FILE, c)
                log_ok(FILE)
                return

    log_gagal(f"{FILE}: fungsi vfs_statx/vfs_fstatat tidak ditemukan")
    failed_files.append(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 5: drivers/input/input.c (CRITICAL!)
# ─────────────────────────────────────────────────────────────
def patch_input_c():
    FILE = "drivers/input/input.c"
    c = baca(FILE)
    if c is None: return
    
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
        "\t"
    )

    FUNGSI = "static void input_handle_event("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi input_handle_event tidak ditemukan")
        failed_files.append(FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    for anchor in ["\tif (disposition != INPUT_IGNORE_EVENT", "\tswitch (disposition)"]:
        if anchor in c:
            c = c.replace(anchor, "\t" + HOOK.rstrip() + "\n" + anchor, 1)
            tulis(FILE, c)
            log_ok(FILE)
            return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")
    failed_files.append(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 6: fs/devpts/inode.c
# ─────────────────────────────────────────────────────────────
def patch_devpts_c():
    FILE = "fs/devpts/inode.c"
    c = baca(FILE)
    if c is None: return
    
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
        "\t"
    )

    FUNGSI = "void *devpts_get_priv("
    if FUNGSI not in c:
        log_gagal(f"{FILE}: fungsi devpts_get_priv tidak ditemukan")
        failed_files.append(FILE)
        return

    c = c.replace(FUNGSI, DEKLARASI + FUNGSI, 1)

    ANCHOR = "\tif (dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC)"
    if ANCHOR in c:
        c = c.replace(ANCHOR, "\t" + HOOK.rstrip() + "\n" + ANCHOR, 1)
        tulis(FILE, c)
        log_ok(FILE)
        return

    log_gagal(f"{FILE}: titik insert tidak ditemukan")
    failed_files.append(FILE)

# ─────────────────────────────────────────────────────────────
# PATCH 7: fs/namespace.c (Optional backport)
# ─────────────────────────────────────────────────────────────
def patch_namespace_c():
    FILE = "fs/namespace.c"
    c = baca(FILE)
    if c is None: return

    if "int path_umount(" in c:
        log_skip(f"{FILE} (path_umount sudah ada)")
        return

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

    CRITICAL_FILES = ["fs/exec.c", "fs/open.c", "drivers/input/input.c"]
    
    if hasil["gagal"] > 0:
        print("⚠️  Ada patch yang gagal:")
        for f in failed_files:
            is_critical = f in CRITICAL_FILES
            marker = "🔴 CRITICAL" if is_critical else "⚠️  OPTIONAL"
            print(f"   {marker}: {f}")
        
        # Exit 1 jika ada critical file yang gagal
        critical_failed = any(f in CRITICAL_FILES for f in failed_files)
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
