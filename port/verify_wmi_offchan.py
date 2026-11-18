#!/usr/bin/env python3
"""Exercise production off-channel WMI ownership, decoding and registration."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
WMI = 'qca-wifi-host-cmn/wmi/'


def function(source, name):
    match = re.search(r'(?m)^[A-Za-z_][\w \t*]*\s+\b' + re.escape(name) +
                      r'\([^;{}]*\)\n\{', source)
    if not match:
        raise ValueError('Function not found: ' + name)
    return source[match.start():source.index('\n}', match.end()) + 2]


def struct(source, name):
    match = re.search(r'(?m)^struct ' + name + r' \{.*?^\};', source, re.S)
    if not match:
        raise ValueError('Struct not found: ' + name)
    return match.group()


def typedef(source, name, kind='struct'):
    end = source.index('} ' + name + ';') + len('} ' + name + ';')
    start = source.rindex('typedef ' + kind + ' {', 0, end)
    return source[start:end]


def verify(root):
    root = Path(root)
    paths = [root / WMI / 'src/wmi_unified_tlv.c',
             root / WMI / 'src/wmi_unified_api.c',
             root / WMI / 'inc/wmi_unified_param.h',
             root / WMI / 'inc/wmi_unified_priv.h',
             root / WMI / 'inc/wmi_unified_api.h',
             root / 'fw-api/fw/wmi_unified.h',
             root / 'fw-api/fw/wmi_tlv_defs.h',
             root / 'fw-api/fw/wmi_tlv_helper.h']
    source_bytes = [p.read_bytes() for p in paths]
    tlv, api, params, priv, public, wire, tags, helper = [body.decode() for body in source_bytes]
    # The decoder must be available in the handset build without WMI_AP_SUPPORT.
    assert (priv.index('(*send_offchan_data_tx_cmd)') <
            priv.index('(*extract_offchan_data_tx_compl_param)') <
            priv.index('(*send_modem_power_state_cmd)'))
    assert priv.count('(*extract_offchan_data_tx_compl_param)') == 1
    assert '.extract_offchan_data_tx_compl_param =' in tlv
    for name in ('wmi_extract_offchan_data_tx_compl_param',
                 'wmi_offchan_data_tx_completion_register',
                 'wmi_offchan_data_tx_completion_unregister'):
        assert name + '(' in public
    definitions = [
        next(line for line in params.splitlines()
             if line.startswith('#define WMI_HOST_PDEV_ID_INVALID ')),
        struct(params, 'tx_send_params'),
        struct(params, 'wmi_offchan_data_tx_params'),
        struct(params, 'wmi_host_offchan_data_tx_compl_event'),
        typedef(wire, 'wmi_tx_send_params'),
        typedef(wire, 'wmi_offchan_data_tx_send_cmd_fixed_param'),
        typedef(wire, 'wmi_offchan_data_tx_compl_event_fixed_param'),
        typedef(tags, 'WMITLV_TAG_ID', 'enum'),
        helper[helper.index('#define WMI_TLV_HDR_SIZE'):
               helper.index('/* Indicates whether the TLV is fixed size')],
        wire[wire.index('#define WMI_GET_BITS('):
             wire.index('#define WMI_APPEND_TWO_SET_BITS')],
        wire[wire.index('#define WMI_TX_SEND_PARAM_PWR_GET'):
             wire.index('/* TX_SEND flags:')],
        params[params.index('#ifndef CONFIG_HL_SUPPORT'):
               params.index('#define WMI_SMPS_MASK_LOWER_16BITS')],
        params[params.index('#ifdef BIG_ENDIAN_HOST'):
               params.index('/** macro to convert MAC address')],
    ]
    functions = [function(api, 'wmi_offchan_data_tx_pdev_id')]
    functions += [function(tlv, name) for name in (
        'populate_tx_send_params', 'send_offchan_data_tx_cmd_tlv',
        'extract_offchan_data_tx_compl_param_tlv')]
    functions += [function(api, name) for name in (
        'wmi_offchan_data_tx_cmd_send', 'wmi_extract_offchan_data_tx_compl_param',
        'wmi_offchan_data_tx_completion_register',
        'wmi_offchan_data_tx_completion_unregister')]
    harness = HERE / 'tests/wmi_offchan.c'
    harness_bytes = harness.read_bytes()
    runner_bytes = Path(__file__).read_bytes()
    code = harness_bytes.decode()
    code = code.replace('/* INSERT_DEFINITIONS */', '\n'.join(definitions))
    code = code.replace('/* INSERT_FUNCTIONS */', '\n'.join(functions))
    results = {}
    with tempfile.TemporaryDirectory(prefix='onyx-wmi-offchan-') as directory:
        path = Path(directory)
        source, exe = path / 'offchan.c', path / 'offchan'

        def run(body, flags=()):
            source.write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-sign-compare',
                            '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', '-fno-pie', '-no-pie',
                            *flags, str(source), '-o', str(exe)],
                           check=True, capture_output=True, text=True)
            return subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)

        for name, flags in {
            'dma32': (), 'dma37': ('-DHTT_PADDR64',),
            'dma32_big_endian': ('-DBIG_ENDIAN_HOST',),
            'dma37_big_endian': ('-DHTT_PADDR64', '-DBIG_ENDIAN_HOST'),
        }.items():
            result = run(code, flags)
            if result.returncode:
                raise AssertionError(name + ': ' + result.stderr[-4000:])
            results[name] = int(result.stdout.strip())

        validation_start = code.index('\tif (WMITLV_GET_TLVTAG(evt->tlv_header) !=')
        validation_end = code.index('\n\t\treturn QDF_STATUS_E_INVAL;', validation_start)
        validation_end += len('\n\t\treturn QDF_STATUS_E_INVAL;')
        mutations = {
            'ignore_map_error': ('if (QDF_IS_STATUS_ERROR(status)) {\n\t\twmi_err("offchan frame map failed");',
                                 'if (false) {\n\t\twmi_err("offchan frame map failed");'),
            'omit_failure_unmap': ('qdf_nbuf_unmap_single(param->qdf_ctx, param->tx_frame,\n\t\t\t\t     QDF_DMA_TO_DEVICE);',
                                   '/* Deliberately omit sender rollback. */'),
            'omit_default_metadata': ('WMITLV_SET_HDR(&((wmi_tx_send_params *)bufp)->tlv_header,\n\t\t\t      WMITLV_TAG_STRUC_wmi_tx_send_params,\n\t\t\t      WMITLV_GET_STRUCT_TLVLEN(wmi_tx_send_params));',
                                      '/* Deliberately omit mandatory metadata header. */'),
            'omit_tlv_validation': (code[validation_start:validation_end],
                                    '/* Deliberately omit fixed TLV validation. */'),
            'omit_service_gate': ('!wmi_service_enabled(wmi_handle, wmi_service_offchan_tx_wmi)',
                                  '(false && !wmi_service_enabled(wmi_handle, wmi_service_offchan_tx_wmi))'),
        }
        controls = []
        for name, (old, new) in mutations.items():
            if code.count(old) != 1:
                raise AssertionError('Mutation anchor count for ' + name + ': ' + str(code.count(old)))
            result = run(code.replace(old, new))
            if result.returncode == 0:
                raise AssertionError('Ineffective negative control: ' + name)
            controls.append(name)

    if source_bytes != [p.read_bytes() for p in paths] or harness_bytes != harness.read_bytes() or runner_bytes != Path(__file__).read_bytes():
        raise AssertionError('Source or fixture changed during validation')
    return {'status': 'PASS', 'scope': 'Host WMI transport ownership; no RF or firmware dwell validation',
            'assertions': results, 'sanitizers': ['address', 'undefined'],
            'negative_controls': controls,
            'source_stable_during_validation': True,
            'source_sha256': {str(p.relative_to(root)): hashlib.sha256(body).hexdigest()
                              for p, body in zip(paths, source_bytes)},
            'harness': 'port/tests/wmi_offchan.c',
            'harness_sha256': hashlib.sha256(harness_bytes).hexdigest(),
            'runner_sha256': hashlib.sha256(runner_bytes).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=HERE.parent / 'modules')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.root)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
