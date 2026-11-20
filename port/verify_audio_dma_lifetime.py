#!/usr/bin/env python3
"""Compile production ion, packet and SPF paths against a shared DMA model."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CASES = (
    "ion_first", "packet_first", "pending_close", "multiple_owners",
    "error_reply", "missing_reply", "wrong_token", "wrong_opcode",
    "truncated_reply", "send_failure", "missing_provider", "missing_service",
    "legacy_close", "secure_retention", "new_writer", "send_cleanup_race",
)
FILES = {
    "ION_SOURCE": "qcom/opensource/audio-kernel/dsp/msm_audio_ion.c",
    "SPF_SOURCE": "qcom/opensource/audio-kernel/dsp/spf-core.c",
    "PKT_SOURCE": "qcom/opensource/audio-kernel/ipc/audio-pkt.c",
}
FIXTURE_CASES = {
    "audio_ion": ("basic", "identity", "sharing", "ranges", "secure", "quarantine",
                  "faults", "cleanup", "crash_secure", "shared_secure", "providers",
                  "boundaries", "publication", "open_remove", "removal",
                  "retiring_provider", "retirement_timeout", "retirement_missing"),
    "audio_pkt": ("tx_lengths", "tx_headers", "tx_faults", "rx_headers", "rx_basic",
                  "regions_multiple", "regions_bounds", "regions_invalid", "reads",
                  "queues", "backups", "sessions", "withdrawal", "receive_wait",
                  "old_file", "open_remove", "failure_paths", "logger", "sync_callback",
                  "send_unbind", "publication", "register_publication", "singleton",
                  "initial_faults", "cleanup_remove"),
    "audio_spf": ("responses", "identities", "truncated", "children", "failures", "remove"),
}


def stripped(text):
    return re.sub(r"^#include .*?$", "", text, flags=re.M)


def materialize(staged, pre_fix=False, mutation=None):
    template = (HERE / "tests/audio_dma_lifetime.c").read_text()
    base = (HERE / "tests/audio_ion.c").read_text().split("/* UAPI */", 1)[0]
    base = base.replace("struct file {struct inode *f_inode;void *private_data;};",
                        "struct file {struct inode *f_inode;void *private_data;int f_flags;};")
    base = base.replace("struct file_operations {void *owner;", "struct file_operations {void *owner;"
                        "ssize_t (*read)(struct file *,char *,size_t,loff_t *);"
                        "ssize_t (*write)(struct file *,const char *,size_t,loff_t *);"
                        "unsigned (*poll)(struct file *,void *);")
    base = base.replace("struct device {atomic_uint refs;", "struct device {struct device_driver *driver;atomic_uint refs;")
    base = base.replace("static void mutex_lock(struct mutex *m)",
                        "static void model_mutex_acquired(struct mutex *m);\n"
                        "static void model_mutex_released(struct mutex *m);\n"
                        "static void mutex_lock(struct mutex *m)")
    base = base.replace("assert(!pthread_mutex_lock(&m->lock));}",
                        "assert(!pthread_mutex_lock(&m->lock));model_mutex_acquired(m);}", 1)
    base = base.replace("assert(!pthread_mutex_unlock(&m->lock));}",
                        "model_mutex_released(m);assert(!pthread_mutex_unlock(&m->lock));}", 1)
    base = base.replace("struct dma_buf {size_t size;", "struct dma_buf {atomic_bool dsp_writes;atomic_uint mapping_refs;size_t size;")
    base = base.replace("a->mapped=true;maps++;", "a->mapped=true;atomic_fetch_add(&a->buffer->mapping_refs,1);maps++;")
    base = base.replace("a->mapped=false;unmaps++;", "assert_dma_quiesced(a->buffer);a->mapped=false;atomic_fetch_sub(&a->buffer->mapping_refs,1);unmaps++;")
    base = base.replace("static void dma_buf_unmap_attachment_unlocked(",
                        "static void assert_dma_quiesced(struct dma_buf *b) {"
                        "if (atomic_load(&b->dsp_writes)) {"
                        "fputs(\"DSP DMA buffer unmapped while writes remain\\n\",stderr);abort();}}\n"
                        "static void dma_buf_unmap_attachment_unlocked(")
    base = base.replace("static struct dma_buf *dma_buf_get(int fd)",
                        "static void assert_packet_translation_guarded(void);\n"
                        "static struct dma_buf *dma_buf_get(int fd)")
    base = base.replace("if(fd<0||fd>=8||!fd_table[fd])return ERR_PTR(-EBADF);",
                        "assert_packet_translation_guarded();if(fd<0||fd>=8||!fd_table[fd])return ERR_PTR(-EBADF);")
    template = ("#define TEST_PRE_FIX " + str(int(pre_fix)) + "\n"
                "#define TEST_GATE_MUTANT " + str(int(mutation == "gate")) + "\n") + template
    template = template.replace("/* BASE_HOST */", base)
    headers = (
        "include/ipc/gpr-lite.h", "include/soc/audio_mod_devicetable.h",
        "include/bindings/qcom,gpr.h", "include/uapi/audio/linux/msm_audio.h",
        "include/dsp/msm_audio_ion.h", "include/dsp/spf-core.h",
    )
    root = staged / "qcom/opensource/audio-kernel"
    # Dependencies precede gpr-lite.h; the real declarations and UAPI are retained.
    order = (headers[1], headers[2], headers[0], *headers[3:])
    template = template.replace("/* HEADERS */", "\n".join(stripped((root / h).read_text()) for h in order))
    sources = {key: (staged / path).read_text() for key, path in FILES.items()}
    sources["ION_SOURCE"] = sources["ION_SOURCE"].split("static void msm_audio_ion_device_release(", 1)[0]
    sources["SPF_SOURCE"] = sources["SPF_SOURCE"].split("static int spf_core_probe(", 1)[0]
    sources["PKT_SOURCE"] = sources["PKT_SOURCE"].split("static void audio_pkt_alloc_backup(", 1)[0]
    if mutation == "gate":
        lock = "\tmutex_lock(&msm_audio_remote_lock);"
        unlock = "\tmutex_unlock(&msm_audio_remote_lock);"
        if sources["ION_SOURCE"].count(lock) != 1 or sources["ION_SOURCE"].count(unlock) != 1:
            raise RuntimeError("Remote lock mutation no longer matches production wrappers")
        sources["ION_SOURCE"] = sources["ION_SOURCE"].replace(lock, "", 1).replace(unlock, "", 1)
    elif mutation == "translation":
        block = """\t\tif (hdr->opcode == APM_CMD_SHARED_MEM_MAP_REGIONS) {
\t\t\tret = audio_pkt_update_regions(hdr, count, header);
\t\t\tif (ret)
\t\t\t\tgoto unlock;
\t\t}
"""
        anchor = "\tret = mutex_lock_interruptible(&priv->lock);"
        if block not in sources["PKT_SOURCE"] or anchor not in sources["PKT_SOURCE"]:
            raise RuntimeError("Translation-order mutation no longer matches production writer")
        sources["PKT_SOURCE"] = sources["PKT_SOURCE"].replace(block, "", 1)
        early = block.replace("goto unlock;", "goto free;")
        sources["PKT_SOURCE"] = sources["PKT_SOURCE"].replace(anchor, early + anchor, 1)
    for key, source in sources.items():
        if key == "SPF_SOURCE":
            source = "#define spf_cmd_basic_rsp spf_core_basic_rsp\n" + stripped(source) + "\n#undef spf_cmd_basic_rsp\n"
        template = template.replace(f"/* {key} */", stripped(source))
    if pre_fix:
        template = template.replace("/* PRE_FIX_ADAPTER */", """
int spf_core_apm_close_all_checked(void)
{
    struct spf_core_private *priv = spf_private_get();
    int result = -ENODEV;
    if (!priv) return result;
    mutex_lock(&priv->lock);
    if (priv->spf_core_drv && !priv->stopping)
        result = spf_run_command(priv->spf_core_drv, APM_CMD_CLOSE_ALL,
                                 Q6_CLOSE_ALL_TIMEOUT_MS);
    mutex_unlock(&priv->lock);
    spf_private_put(priv);
    return result;
}
void msm_audio_ion_remote_lock(void) {}
void msm_audio_ion_remote_unlock(void) {}
""")
    else:
        template = template.replace("/* PRE_FIX_ADAPTER */", "")
    return template


def materialize_fixture(staged, fixture):
    template = (HERE / f"tests/{fixture}.c").read_text()
    root = staged / "qcom/opensource/audio-kernel"
    if fixture == "audio_ion":
        template = template.replace("/* UAPI */", stripped((root / "include/uapi/audio/linux/msm_audio.h").read_text()))
        path = FILES["ION_SOURCE"]
    else:
        headers = ("include/soc/audio_mod_devicetable.h", "include/bindings/qcom,gpr.h", "include/ipc/gpr-lite.h")
        template = template.replace("/* HEADERS */", "\n".join(stripped((root / h).read_text()) for h in headers))
        path = FILES["SPF_SOURCE" if fixture == "audio_spf" else "PKT_SOURCE"]
    source = stripped((staged / path).read_text())
    source = re.sub(r"^(?:MODULE_|EXPORT_SYMBOL|module_platform_driver).*?$", "", source, flags=re.M)
    return "#define NATIVE 0\n" + template.replace("/* SOURCE */", source)


def compile_binary(source, binary, code):
    source.write_text(code)
    subprocess.run([
        "cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra",
        "-Wno-unused-function", "-Wno-unused-variable",
        "-Werror=implicit-function-declaration", "-pthread",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-fno-pie", "-no-pie", str(source), "-o", str(binary),
    ], check=True, capture_output=True, text=True)


def verify(staged, baseline=None):
    report = {}
    with tempfile.TemporaryDirectory(prefix="onyx-audio-dma-lifetime-") as directory:
        temp = Path(directory)
        for label, tree, pre_fix in (("fixed", staged, False), ("pre_fix", baseline, True)):
            if tree is None:
                continue
            source = temp / f"{label}.c"
            binary = temp / label
            compile_binary(source, binary, materialize(tree, pre_fix))
            if pre_fix:
                result = subprocess.run([str(binary), "ion_first"], capture_output=True, text=True, timeout=20)
                if result.returncode == 0 or "DSP DMA buffer unmapped while writes remain" not in result.stderr:
                    raise RuntimeError("Pre-fix source did not reproduce the intended DMA lifetime failure:\n" + result.stderr)
                report["pre_fix"] = {"detected_early_dma_unmap": True, "case": "ion_first"}
                continue
            for case in CASES:
                result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    raise RuntimeError(f"{case} failed:\n{result.stdout}{result.stderr}")
                report[case] = json.loads(result.stdout)
        for mutation, case, marker in (
            ("gate", "send_cleanup_race", "DSP packet referenced unmapped DMA"),
            ("translation", "ion_first", "Packet DMA translation ran outside the remote cleanup gate"),
        ):
            binary = temp / mutation
            compile_binary(temp / f"{mutation}.c", binary, materialize(staged, mutation=mutation))
            result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or marker not in result.stderr:
                raise RuntimeError(f"{mutation} mutation did not violate the intended invariant:\n{result.stderr}")
            report[f"{mutation}_negative"] = {"detected": True, "case": case, "invariant": marker}
        fixtures = {}
        for fixture, cases in FIXTURE_CASES.items():
            binary = temp / fixture
            compile_binary(temp / f"{fixture}.c", binary, materialize_fixture(staged, fixture))
            fixtures[fixture] = {}
            for case in cases:
                result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    raise RuntimeError(f"{fixture}/{case} failed:\n{result.stdout}{result.stderr}")
                fixtures[fixture][case] = json.loads(result.stdout)
    return {
        "cases": report,
        "existing_fixtures": fixtures,
        "source_sha256": {path: hashlib.sha256((staged / path).read_bytes()).hexdigest() for path in FILES.values()},
        "harness_sha256": hashlib.sha256((HERE / "tests/audio_dma_lifetime.c").read_bytes()).hexdigest(),
        "base_harness_sha256": hashlib.sha256((HERE / "tests/audio_ion.c").read_bytes()).hexdigest(),
        "fixture_sha256": {fixture: hashlib.sha256((HERE / f"tests/{fixture}.c").read_bytes()).hexdigest() for fixture in FIXTURE_CASES},
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"],
        "hardware_validated": False,
        "limits": [
            "DSP writes, GPR responses and DMA attachments are simulated; no hardware validation.",
            "Combined tests execute production data/lifetime paths with host-initialized providers; standalone fixtures execute the full driver source.",
            "Successful provider retirement reclaims DMA before simulated IOMMU detachment, preserving live owners of other providers.",
            "Failed-close removal fixtures retain the IOMMU binding explicitly; failed quiescence followed by actual platform-device deletion remains unsupported. Device references alone do not preserve that binding.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("staged", nargs="?", type=Path, default=HERE.parent / "modules")
    parser.add_argument("--pre-fix", type=Path, help="Verify the unchanged earlier production source fails the DMA invariant")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = json.dumps(verify(args.staged, args.pre_fix), indent=2) + "\n"
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr) from error
    if args.output:
        args.output.write_text(result)
    print(result, end="")
