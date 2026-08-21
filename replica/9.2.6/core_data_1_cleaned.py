# This was cleaned up by ai so it doesnt work and im too lazy to fix stuff 
import re
import os
import sys
from datetime import datetime, timedelta
from random import randrange
from shutil import copytree, rmtree, copymode
from string import Template
from struct import pack, unpack
from subprocess import Popen, PIPE
from zipfile import ZipFile, PyZipFile
from . import logger, resoptions, CliError, Component
from .core.runtime import PyarmorRuntime
from .resource import PathResource
shared_state = {}

# Generate a list of n random bytes (1-255), used as padding/filler
def generate_random_bytes(n=16):
    return [randrange(1, 255) for i in range(n)]

# Fingerprint the current Python interpreter via C API symbol addresses + MD5
def generate_interp_fingerprint(refsize=32768):
    from ctypes import PyDLL, cast, c_void_p, string_at
    from hashlib import md5
    pydll = PyDLL(None)
    addrs = []
    for sym_name in ('PyParser_New', 'PyToken_OneChar', 'Py_IncRef', 'Py_Main', 'Py_RunMain', 'Py_Finalize', 'Py_FinalizeEx'):
        if hasattr(pydll, sym_name):
            addrs.append(cast(getattr(pydll, sym_name), c_void_p).value)
    addrs.sort()
    eval_frame_addr = cast(pydll.PyEval_EvalFrame, c_void_p).value
    range_start = min(eval_frame_addr - refsize, addrs[0])
    range_end = max(eval_frame_addr + refsize, addrs[-1])
    return ' '.join(['PyEval_EvalFrame', str(eval_frame_addr - range_start), str(range_end - eval_frame_addr), md5(string_at(range_start, range_end)).hexdigest()])

# XOR-decrypt a PE binary overlay section (Windows executable manipulation)
def decrypt_pe_overlay(pe_data):
    (pe_offset, overlay_flag, security_offset) = unpack('III', pe_data[40:52])
    if overlay_flag:
        pe_overlay_offset = 64 + pe_offset
        (sig_type, sig_size) = unpack('<BI', pe_data[pe_overlay_offset:pe_overlay_offset + 5])
        if sig_type == 0:
            sig_size &= 16777215
            pe_bytes = bytearray(pe_data)
            pe_bytes[pe_overlay_offset] = 1
            i = 64 + security_offset + sig_size
            src_pos = 64 + pe_offset + 4 + sig_size
            while sig_size:
                sig_size -= 1
                i -= 1
                src_pos -= 1
                pe_bytes[i] ^= pe_bytes[src_pos]
            return bytes(pe_bytes)
    return pe_data

# =============================================================================
# Runtime Key Builder - Encodes license constraints into a signed binary blob
# =============================================================================
class RuntimeKeyBuilder(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def _pack_message_lang(self, msg_config, lang=''):
        lang_suffix = '' if lang == '' else '.' + lang
        msg_section = msg_config['runtime.message' + lang_suffix]
        size = 3
        msg_parts = [pack('BB5s', 7, size, lang.encode())]

        def _pack_msg_entry(size, msg_sub_type, msg_text):
            encoded_msg = msg_text.encode() + b'\x00'
            length = len(encoded_msg) + 2
            if length > 255:
                raise CliError('too long message "%s"' % msg_text)
            return pack('BB', length, size | msg_sub_type << 2) + encoded_msg
        error_format_types = ('init', 'import', 'load', 'run')
        size = 1
        for i in range(len(error_format_types)):
            msg_key = error_format_types[i] + '_error_format'
            msg_text = msg_section.get(msg_key, None)
            if msg_text:
                msg_parts.append(_pack_msg_entry(size, i, msg_text))
        error_types = ('system', 'system', 'system', 'pyarmor', 'protect')
        size = 2
        for i in range(len(error_types)):
            msg_key = error_types[i] + '_error'
            msg_text = msg_section.get(msg_key, None)
            if msg_text:
                msg_parts.append(_pack_msg_entry(size, i, msg_text))
                msg_parts.append(_pack_msg_entry(size, i, msg_text))
        size = 0
        for msg_key in msg_section:
            if msg_key.startswith('error_'):
                msg_sub_type = msg_key[6:]
                if not msg_sub_type.isdecimal():
                    raise CliError('invalid option "%s"' % msg_key)
                msg_text = msg_section.get(msg_key)
                msg_parts.append(_pack_msg_entry(size, int(msg_sub_type), msg_text))
        return b''.join(msg_parts)

    def _pack_messages(self):
        msg_config = self.ctx.runtime_messages
        if not msg_config or not msg_config.has_section('runtime.message'):
            return b'\x00'
        languages = msg_config['runtime.message'].get('languages', '').split()
        languages.append('')
        return b''.join([self._pack_message_lang(msg_config, item) for item in languages])

    def _pack_interp_line(self, key_spec):
        try:
            if key_spec == 'check-debugger':
                interp_type = 'D'
            elif key_spec == 'check-interp':
                interp_type = 'S'
                fingerprint = generate_interp_fingerprint()
            elif key_spec == 'py:bootstrap':
                interp_type = 'B'
            else:
                (interp_type, fingerprint) = key_spec.split(':', 2)
            interp_type = interp_type.encode()
            if interp_type == b'S':
                (sym_name, pos, range_end, md5_hex) = fingerprint.split()
                offsets_packed = pack('ii', int(pos), int(range_end))
                value = bytes.fromhex(md5_hex)
                return interp_type + sym_name.encode() + b'\x00' + offsets_packed + value
            elif interp_type == b'D':
                return interp_type
            elif interp_type == b'B':
                from marshal import dumps
                hook_script = self.ctx.runtime_hook('pyarmor_runtime')
                if hook_script is None:
                    raise CliError('no bootstrap script found')
                compiled_hook = compile(hook_script, '<pyarmor_runtime>', 'exec')
                for item in compiled_hook.co_consts:
                    if type(item) == type(compiled_hook) and item.co_name == 'bootstrap':
                        return interp_type + dumps(item)
                raise CliError('invalid bootstrap script')
        except (IndexError, ValueError) as exc:
            logger.error('%s', str(exc))
            raise CliError('invalid interp key "%s"' % key_spec)

    def _pack_machine_line(self, key_spec):
        device_patterns = (('*MID:', re.compile('^[a-z][0-9a-fA-F]{32}$')), ('*IFMAC:', re.compile('^([0-9a-zA-Z]+/)?([0-9a-fA-F]{1,2}:){1,5}[0-9a-fA-F]{1,2}$')), ('*IFMAC:', re.compile('^<(([0-9a-fA-F]{1,2}:){2,6},?)+>$')), ('*IFIPV4:', re.compile('^([0-9]{1,3}\\.){3}[0-9]{1,3}$')), ('*DOMAIN:', re.compile('^\\{[a-zA-Z0-9.]+\\}$')), ('*HARDDISK:', re.compile('[a-zA-Z0-9_]{6,30}')))
        result = []
        spec_tokens = key_spec.split()
        length = 0
        for item in spec_tokens:
            for (prefix, regex) in device_patterns:
                if item.startswith(prefix):
                    result.append([prefix, item[len(prefix):].strip('{}')])
                    length += 1
                    break
                elif regex.search(item):
                    result.append([prefix, item.strip('{}')])
                    length += 1
                    break
        if len(spec_tokens) > length:
            raise CliError('invalid device info "%s"' % key_spec)
        if length > 1:
            sort_order = ('*MID:', '*HARDDISK:', '*IFMAC:', '*IFIPV4:', '*DOMAIN:')

            def _sort_by_prefix(spec_entry):
                return sort_order.index(spec_entry[0])
            result.sort(key=_sort_by_prefix)
        return ''.join(sum(result, [])).encode('utf-8')

    def _pack_runtime_key(self, outer=None):
        ctx = self.ctx
        flag_bits = 0
        key_blob = b''
        key_type = 2 if outer else 1 if self.ctx.runtime_outer else 0
        outer_keyname = self.ctx.outer_keyname if key_type else ''
        keyname_len = 0
        if outer_keyname:
            keyname_len = len(outer_keyname)
            key_blob += outer_keyname.encode('utf-8')
        key_blob += b'\x00'
        flag_bits += 2
        on_error = ctx.runtime_on_error
        if on_error:
            key_type |= int(on_error) << flag_bits
        flag_bits += 2
        period = ctx.runtime_period
        if period == -1:
            raise CliError('invalid period format "%s"' % period)
        elif period:
            if period > pow(2, 20):
                raise CliError('period "%s" is overflow' % period)
            key_type |= period << flag_bits
        flag_bits += 20
        license_features = shared_state['get_license_features'](shared_state['self'], ctx)
        key_type |= (0 if license_features else 1) << flag_bits
        flag_bits += 1
        if license_features:
            key_type |= (3 if license_features & 8 else 2 if license_features & 6 else 1) << flag_bits
        flag_bits += 1
        data_len = [key_type, keyname_len]
        expired = ctx.runtime_expired
        data_len.append(len(key_blob) if expired else 0)
        if expired:
            nts_timeout = int(ctx.runtime_nts_timeout)
            is_relative = expired[0] == '.'
            nts_server = b'' if is_relative else ctx.runtime_nts.encode()
            if expired[is_relative:].isdecimal():
                value = datetime.today() + timedelta(int(expired[is_relative:]))
            else:
                value = datetime.fromisoformat(expired[is_relative:])
            value = pack('<Q', int(value.timestamp()))
            if len(value) != 8:
                raise CliError('pack inner error')
            length = 10 + len(nts_server) + 1
            if length > 255:
                raise CliError('too long nts "%s"' % nts_server)
            key_blob += pack('BB', length, nts_timeout) + value + nts_server + b'\x00'
        devices = self.ctx.runtime_devices
        data_len.append(len(key_blob) if devices else 0)
        if devices:
            for key_spec in devices:
                key_spec = self._pack_machine_line(key_spec) + b'\x00'
                length = len(key_spec)
                if length < 255:
                    key_blob += bytes([length])
                else:
                    key_blob += pack('B<H', 255, length)
                key_blob += key_spec
            key_blob += b'\x00'
        if outer and (not devices) and (not expired):
            raise CliError('outer key need expired date or machine binding')
        interps = self.ctx.runtime_interps
        data_len.append(len(key_blob) if interps else 0)
        if interps and interps.startswith('?'):
            interps = interps.encode()
            key_blob += bytes([len(interps)]) + interps
        elif interps:
            for key_spec in interps.splitlines():
                pattern = self._pack_interp_line(key_spec.strip())
                length = len(pattern)
                if length < 255:
                    key_blob += bytes([length])
                else:
                    key_blob += pack('<BH', 255, length)
                key_blob += pattern
            key_blob += b'\x00'
        lang_suffix = self.ctx.runtime_user_data
        if lang_suffix:
            data_len.append(len(key_blob))
            key_blob += lang_suffix
            data_len.append(len(lang_suffix))
        else:
            data_len.extend([0, 0])
        data_len.append(0)
        return pack('I' * len(data_len), *data_len) + key_blob

    def _verify_runtime_key(self, key_data):
        i = key_data.find(pack('I', shared_state['RUNTIME_MAGIC_NUMBER']))
        if i > -1 and shared_state['PYTRANSFORM3_REVISION'] == unpack('I', key_data[i + 4:i + 8])[0] & 255:
            return i
        return -1

    def build(self, outer=None):
        messages = self.ctx.use_runtime
        if messages and (not self.ctx.runtime_outer):
            languages = os.path.join(messages, self.ctx.runtime_keyfile)
            with open(languages, 'rb') as msg_text:
                key_data = msg_text.read()
                i = self._verify_runtime_key(key_data)
                if i == -1:
                    raise CliError('invalid runtime key in shared runtime package "%s"' % messages)
                return key_data[i:]
        with ZipFile(self.ctx.private_capsule, 'r') as msg_text:
            msg_type = msg_text.read('private.key')
        msg_id = b''
        spec_list = pack('5s', msg_id) + self._pack_messages()
        parsed_count = self._pack_runtime_key(outer=outer)
        if self.ctx.runtime_outer or outer:
            sorted_specs = b'o.' + bytes(generate_random_bytes(30))
        else:
            sorted_specs = b'i.' + bytes(generate_random_bytes(30))
        pe_data = shared_state['generate_runtime_key'](shared_state['self'], self.ctx, msg_type, parsed_count, spec_list, sorted_specs)
        if outer and self.ctx.runtime_obf_key_mode:
            pe_data = decrypt_pe_overlay(pe_data)
        return pe_data

# =============================================================================
# Runtime Extension Builder - Manages platform-specific native extensions
# =============================================================================
class RuntimeExtensionBuilder(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def osx_sign_binary(self, binary_path, is_darwin=True):
        logger.info('sign runtime file')
        sign_identity = '-'
        cmd_args = ['codesign', '-s', sign_identity, '--force', '--all-architectures', '--timestamp', binary_path]
        process = Popen(cmd_args, stdout=PIPE, stderr=PIPE, shell=True)
        (stdout, stderr) = process.communicate()
        if process.returncode != 0:
            logger.warning('codesign command (%r) failed with error code %d!\nstdout: %r\nstderr: %r', cmd_args, process.returncode, stdout, stderr)
            if is_darwin:
                raise CliError('codesign failure')
            else:
                logger.warning('Code signing is a macOS security technology, no codesign runtime file "%s" may not work in MacOS. Please consult Apple developer documentation to codesign it by yourself', binary_path)

    def osx_merge_binary(self, lib_data, *extra_paths):
        logger.info('create universal binary file %s', lib_data)
        cmd_args = ['lipo', '-create', '-output', lib_data]
        for binary_path in extra_paths:
            arch_name = os.path.dirname(binary_path).split('.')[1]
            cmd_args.extend(['-arch', arch_name, binary_path])
        logger.debug('call lipo: %s' % ' '.join(cmd_args))
        process = Popen(cmd_args, stdout=PIPE, stderr=PIPE, shell=True)
        (stdout, stderr) = process.communicate()
        if process.returncode != 0:
            logger.warning('lipo command (%r) failed with error code %d!\nstdout: %r\nstderr: %r', cmd_args, process.returncode, stdout, stderr)
        return process.returncode == 0

    def patch_extension(self, lib_data, key_data, count=1, bindata=None):
        real_path = shared_state['RUNTIME_MAGIC_NUMBER']
        temp_path = shared_state['RUNTIME_MAGIC_VERSION']
        archive = shared_state['RUNTIME_DATA_SIZE']
        manifest = b'pyarmor-vax'
        if self.ctx.runtime_obf_key_mode:
            key_data = decrypt_pe_overlay(key_data)
        mode = len(key_data)
        if mode > archive:
            raise CliError('too many runtime data')
        if self.ctx.runtime_patch_extension == 0:
            keyfile_path = os.path.join(os.path.dirname(lib_data), '.pyarmor.ikey')
            logger.debug('write keyfile "%s"', keyfile_path)
            with open(keyfile_path, 'wb') as suffix:
                suffix.write(key_data)
            if bindata is not None:
                with open(lib_data, 'wb') as suffix:
                    suffix.write(bindata)
            return
        if bindata is None:
            with open(lib_data, 'rb') as suffix:
                written = bytearray(suffix.read())
        else:
            written = bytearray(bindata)
        header_packed = pack('III20s', real_path, temp_path, archive, manifest)
        offset = written.find(header_packed)
        if offset == -1 and count > 0:
            raise CliError('no found runtime data')
        logger.debug('patching runtime data at %s', offset)
        written[offset:offset + mode] = bytearray(key_data)
        count -= 1
        while count:
            offset = written[offset + mode:].find(header_packed)
            if offset == -1:
                raise CliError('no found runtime data')
            logger.debug('patching runtime data at %s', offset)
            written[offset:offset + mode] = bytearray(key_data)
        with open(lib_data, 'wb') as suffix:
            suffix.write(written)
        logger.debug('patch runtime file OK')

    def target_file_data(self, platform, simple=False):
        subdir = 'themida' if self.ctx.enable_themida else None
        is_native = platform == self.ctx.native_platform
        if is_native:
            platform = self.ctx.pyarmor_platform
        result = self.target_platform_library(platform, extra=subdir, native=is_native)
        with open(result[1], 'rb') as suffix:
            data = suffix.read()
        if simple:
            path = result[0].split('.')
            return (path[0] + '.' + path[-1], result[1], data)
        return (result[0], result[1], data)

    def target_platform_library(self, platform, extra=None, native=True):
        if native and extra:
            platform = self.ctx.pyarmor_platform
        result = PyarmorRuntime.get(platform, extra=extra, native=native)
        if not result:
            logger.error('please check all supported platforms in documentation "References"')
            raise CliError('no found prebuilt runtime extension for platform "%s"' % platform)
        return result

    def _target_path(self, platform, universal=True):
        cfg = self.ctx.get_core_config()
        output = cfg['pyarmor_runtime'].get('path', 'cached/runtimes')
        platform += '' if universal else '.py%d%d' % self.ctx.python_version
        lib_data = cfg.get('pyarmor_runtime', platform)
        (name, checksum) = [item.strip() for item in lib_data.split(':')]
        lib_name = os.path.join(self.ctx.home_path, output, platform, name)

        def lib_entry2(output, checksum):
            from hashlib import sha256
            return True
            with open(output, 'rb') as suffix:
                return sha256(suffix.read()).hexdigest() == checksum
        logger.debug('require %s', lib_name)
        if os.path.exists(lib_name) and lib_entry2(lib_name, checksum):
            return lib_name
        logger.debug('no cached or hash not match')
        os.makedirs(os.path.dirname(lib_name), exist_ok=True)
        for lib_entry in self._get_core_library(lib_name, platform, name, cfg=cfg):
            if lib_entry and lib_entry.code == 200:
                with open(lib_name, 'wb') as suffix:
                    suffix.write(lib_entry.read())
                if lib_entry2(lib_name, checksum):
                    return lib_name
        raise CliError('could not found pyarmor_runtime extension')

    def _get_core_library(self, lib_data, platform, name, cfg):
        os_name = cfg.get('pyarmor_runtime', 'urls')
        arch = 'runtime.%s' % cfg.get('pyarmor_runtime', 'version')
        timeout = self.ctx.cfg['pyarmor'].getint('timeout', 3)
        for url in os_name.splitlines():
            url = Template(url.strip()).substitute(tag=arch)
            logger.debug('request %s', url)
            yield self._get_remote_file('/'.join([url, platform, name]), timeout)

    def _get_remote_file(self, url, timeout=3):
        from urllib.request import urlopen
        from ssl import _create_unverified_context
        ssl_ctx = _create_unverified_context()
        try:
            return urlopen(url, None, timeout, context=ssl_ctx)
        except Exception as entry:
            logger.debug(entry)

    def unique_path(self, output_dir, name):
        if not os.path.exists(output_dir):
            return name
        path = [item for item in os.listdir(output_dir)]
        if name not in path:
            return name
        size = 1
        while size < 4:
            n = name.replace('pyarmor_runtime', 'pyarmor_runtime_a%d' % size)
            if n not in path:
                return n
            size += 1
        raise CliError('too many duplicated runtime files')

    def _post_runtime(self, script, runtimes, platforms):
        copymode(script, runtimes)
        self.ctx.runtime_plugin(script, runtimes, platforms)

    def build(self, output, platforms=None):
        platforms = set(platforms if platforms else self.ctx.target_platforms)
        platform_str = self.ctx.runtime_key
        if platform_str is None:
            platform_str = RuntimeKeyBuilder(self.ctx).build()
        result_path = self.ctx.runtime_simple_extension_name
        file_list = self.format_outputs(output)
        output_dir = file_list[0]
        logger.info('target platforms %s', platforms)
        os.makedirs(output_dir, exist_ok=True)
        for platform in platforms:
            (name, init_content, data) = self.target_file_data(platform, result_path)
            logger.debug('got %s', init_content)
            if len(platforms) == 1:
                runtimes = os.path.join(output_dir, name)
            else:
                runtimes = os.path.join(output_dir, platform.replace('.', '_'), name)
                os.makedirs(os.path.dirname(runtimes), exist_ok=True)
            logger.info('write %s', runtimes)
            self.patch_extension(runtimes, platform_str, bindata=data)
            self._post_runtime(init_content, runtimes, platform)
        mod_name = Template(self.ctx.runtime_package_template(platforms))
        with open(os.path.join(output_dir, '__init__.py'), 'w') as suffix:
            suffix.write(mod_name.safe_substitute(rev=self.ctx.version_info(2), timestamp=datetime.now().isoformat()))
        for mod_data in file_list[1:]:
            copytree(output_dir, mod_data)

    def fly_build(self, platform_str, output_dir):
        if self.ctx.license_info['features'] & 8 != 8:
            raise RuntimeError('out of license')
        shared_state.setdefault('RUNTIME_MAGIC_NUMBER', 1865249419)
        shared_state.setdefault('RUNTIME_MAGIC_VERSION', 1385940610)
        shared_state.setdefault('RUNTIME_DATA_SIZE', 16384)
        platform = self.ctx.native_platform
        (name, init_content, data) = self.target_file_data(platform, simple=True)
        runtimes = os.path.join(output_dir, name)
        self.patch_extension(runtimes, platform_str, bindata=data)
        copymode(init_content, runtimes)
        return runtimes

    def format_outputs(self, output):
        file_list = []
        mod_list = self.ctx.import_prefix
        if not mod_list:
            file_list.append('')
        elif isinstance(mod_list, str):
            file_list.append(mod_list.replace('.', os.path.sep))
        else:
            for lib_entry in self.ctx.resources + self.ctx.extra_resources:
                if isinstance(lib_entry, PathResource):
                    file_list.append(lib_entry.name)
            if not file_list:
                file_list.append('')
        pkg_name = self.ctx.runtime_package_name
        return [os.path.join(output, item, pkg_name) for item in file_list]

# =============================================================================
# Script Obfuscator - Main obfuscation pipeline (AST + bytecode transforms)
# =============================================================================
class ScriptObfuscator(Component):
    _Catalog = 'builder'

    def __init__(self, ctx):
        self.ctx = ctx

    def process_pyc(self, script):
        script.recompile()

        def mco2(co):
            return not co.co_name.startswith('<')
        LambdaArmorPatcher(self.ctx, shared_state).handle_mco(script.mco, mco2)
        pkg_name = shared_state['self']
        module_data = shared_state['generate_module_data'](pkg_name, self.ctx, script.mco, 0)
        header = len(module_data)
        size = shared_state['MARSHAL_TYPE_ASTBODY']
        header_data = self._build_marshal_header(script, size, simple_module=1)
        inner_header = pack('IIIII12x', 32, 0, header, 0, 8)
        assert len(header_data) == 64
        assert len(inner_header) == 32
        data = header_data + inner_header + module_data
        shared_state['generate_module_data'](pkg_name, self.ctx, data, 1)
        return data

    @resoptions
    def process(self, script):
        if script.is_pyc:
            return self.process_pyc(script)
        encoding = self.ctx.cfg['builder'].get('encoding')
        script.lines = script.readlines(encoding=encoding)
        InlineMarkerProcessor(self.ctx).handle(script)
        logger.debug('parse script')
        script.reparse(script.lines)
        script.lines = None
        source = []
        if self.ob_enable_rft:
            tree = shared_state['get_name_refactor'](shared_state['self'], self.ctx)
            source.append(tree(self.ctx))
        if self.ob_enable_bcc:
            transformer = shared_state['get_bcc_builder'](shared_state['self'], self.ctx)
            if transformer:
                source.append(transformer(self.ctx))
        if self.ob_assert_call:
            source.append(AssertCallTransformer(self.ctx))
        if self.ob_assert_import:
            source.append(AssertImportTransformer(self.ctx))
        if self.ob_mix_str:
            source.append(StringObfuscator(self.ctx, shared_state))
        source.append(CodeObjectReformer(self.ctx))
        if self.oi_obf_code > 1:
            version = shared_state['get_license_features'](shared_state['self'], self.ctx)
            if not version:
                raise CliError('out of license')
        if self.oi_obf_code == 2 or self.ob_mix_attr:
            source.append(AttributeObfuscator(self.ctx, shared_state))
        [log_name.process(script) for log_name in source]
        script.recompile(optimize=self.oi_optimize)
        component = []
        if self.ob_enable_bcc:
            component.append(BCCCodePatcher(self.ctx, shared_state))
        if self.ob_mix_localnames:
            component.append(LocalVariableRenamer(self.ctx, shared_state))
        component.append(ArmorCodePatcher(self.ctx, shared_state))
        [new_co.handle(script) for new_co in component]
        return self.coserialize(script, clean=True)

    def coserialize(self, script, clean=True):
        result = []
        if self.ob_enable_bcc:
            result.append(self._build_bcc_body(script))
        result.append(self._build_ast_body(script))
        if clean:
            script.clean()
        return b''.join(result)

    def _build_marshal_header(self, script, size, size=0, simple_module=0):
        cflags = shared_state['PYARMOR_MARSHAL_VERSION']
        filename = 0
        (module_code, header_size) = self.ctx.python_version[:2]
        iv = bytes(generate_random_bytes())
        (co_code, jit_data) = (1, 0)
        vmc_index = 2 if self.ctx.runtime_outer else 1
        new_header = 1 if self.ob_obf_module else 0
        encrypted = 1 if self.ob_obf_code else 0
        module_name = self.oi_restrict_module
        mco = 1 if module_name else 0
        mco_data = 1 if module_name > 1 else 0
        co_stacksize = 1 if module_name > 2 else 0
        if any([('.' + script.fullname).endswith('.' + item) for item in self.ctx.exclude_restrict_modules]):
            (mco_data, co_stacksize) = (0, 0)
        co_nlocals = 1 if self.ob_readonly_module else 0
        if co_nlocals and mco_data:
            logger.debug('ignore readonly_module because private_module is set')
        co_flags2 = 1 if self.ob_enable_jit else 0
        co_filename = 1 if self.ob_enable_bcc else 0
        co_name = 1 if self.ob_enable_vmc and co_filename == 0 else 0
        co_qualname = 1 if self.ob_import_check_license else 0
        co_firstlineno = 1 if self.ob_clear_module_co else 0
        co_linetable = 1 if self.ob_clear_frame_locals else 0
        co_exceptiontable = 1 if self.ob_self_contained else 0
        if simple_module:
            co_flags2 = co_filename = mco_data = co_stacksize = 0
        consts = co_qualname << shared_state['CHECK_RUNTIME_KEY_OFF'] | mco << shared_state['CHECK_CO_CODE_OFF'] | co_stacksize << shared_state['CHECK_PARENT_FRAME_OFF'] | mco_data << shared_state['PRIVATE_MODULE_OFF'] | co_nlocals << shared_state['READONLY_MODULE_OFF'] | co_firstlineno << shared_state['CLEAR_MODULE_CO_CODE_OFF'] | co_linetable << shared_state['CLEAR_FRAME_LOCALS_OFF'] | co_exceptiontable << shared_state['SELF_CONTAINED_OFF'] | simple_module << shared_state['SIMPLE_MODULE_OFF'] | new_header << shared_state['OBF_MODULE_OFF'] | encrypted << shared_state['OBF_CODE_OFF'] | co_flags2 << shared_state['ENABLE_JIT_IV_OFF'] | co_filename << shared_state['ENABLE_BCC_MODE_OFF'] | co_name << shared_state['ENABLE_VMC_MODE_OFF'] | vmc_index << shared_state['BIND_RUNTIME_KEY_OFF']
        return pack('8sBBBBIBBBBIIIII16s8x', b'PYARMOR', 0, module_code, header_size, 0, 0, cflags, filename, co_code, jit_data, size, 0, 64, size, consts, iv)

    def _build_ast_body(self, script):
        pkg_name = shared_state['self']
        module_data = shared_state['generate_module_data'](pkg_name, self.ctx, script.mco, 0)
        header = len(module_data)
        jit = getattr(script, 'jit_data', b'')
        if not jit:
            jit = b''
        vmc_idx = len(jit)
        vmcindex = getattr(script, 'vmcindex', 0)
        size = shared_state['MARSHAL_TYPE_ASTBODY']
        header_data = self._build_marshal_header(script, size)
        inner_header = pack('IIIIII8x', 32, vmc_idx, header, 0, 8, vmcindex)
        assert len(header_data) == 64
        assert len(inner_header) == 32
        data = header_data + inner_header + jit + module_data
        shared_state['generate_module_data'](pkg_name, self.ctx, data, 1)
        return data

    def _build_bcc_body(self, script):
        cobj = getattr(script, 'cobj', b'')
        header = len(cobj)
        size = shared_state['MARSHAL_TYPE_BCCBODY']
        header_data = self._build_marshal_header(script, size)
        bcc_body = pack('IIII', 16, header, 0, 0)
        assert len(header_data) == 64
        assert len(bcc_body) == 16
        data = header_data + bcc_body + cobj
        shared_state['generate_module_data'](shared_state['self'], self.ctx, data, 2)
        return data

# =============================================================================
# Pre-Build Processor - Variable type init, package relations, RFT mode
# =============================================================================
class PreBuildProcessor(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def init_variable_types(self):
        ctx = self.ctx
        type_file = ctx.cfg['builder'].get('type_file', 'variable.types')
        var_types = {}
        for output in (ctx.global_path, ctx.local_path):
            if os.path.exists(os.path.join(output, type_file)):
                with open(os.path.join(output, type_file)) as key:
                    for value in key:
                        if value.startswith('#'):
                            continue
                        mtree = value.strip().split(': ')
                        if len(mtree) != 2:
                            raise RuntimeError('invalid type info: %s' % value)
                        (mod_name, pkg_name) = mtree
                        if mod_name in var_types:
                            raise RuntimeError('duplicated type "%s"' % mod_name)
                        var_types[mod_name] = pkg_name
        self.ctx.variable_types.update(var_types)

    def init_rft_mode(self, auto_exclude=0):
        refactor_func = shared_state['get_name_refactor'](shared_state['self'], self.ctx)
        refactor_func(self.ctx).init_rft_mode(auto_exclude)

    def build(self):
        full_name = self.ctx.cmd_options
        builder_cfg = self.ctx.cfg['builder']
        type_info = full_name.get('enable_rft', builder_cfg.getboolean('enable_rft'))
        relations = full_name.get('enable_bcc', builder_cfg.getboolean('enable_bcc'))
        analyzer = ('assert_call', 'assert_import')
        if type_info or relations:
            builder = self.ctx.license_info
            if builder['features'] & 7 != 7:
                raise CliError('out of license')
        rft_mode = [item for item in builder_cfg.get('pypaths', '').splitlines() if item and os.path.exists(item)]
        if rft_mode:
            logger.info('add extra python paths: %s', rft_mode)
            sys.path[0:0] = rft_mode
        if type_info:
            logger.debug('build package relations')
            self.init_variable_types()
            PackageRelationsBuilder(self.ctx).process()
            self.init_rft_mode(builder_cfg.getint('rft_auto_exclude'))
        elif any([full_name.get(item, builder_cfg.getboolean(item)) for item in analyzer]):
            logger.debug('build package relations')
            PackageRelationsBuilder(self.ctx).process()

# =============================================================================
# Extra Libs Builder - Packages extra libs into extra_libs.zip
# =============================================================================
class ExtraLibsBuilder(ScriptObfuscator):

    def __init__(self, ctx):
        self.ctx = ctx

    def build(self):
        result = []
        for (lib_path, script_obj) in self.ctx.extra_libs.items():
            name = lib_path + '.py'
            result.append((name, script_obj))
        if not result:
            return
        output = self.ctx.outputs[0]
        zip_path = os.path.join(output, 'libs')
        if not os.path.exists(zip_path):
            os.makedirs(zip_path, exist_ok=True)
        runtimes = os.path.join(output, 'extra_libs.zip')
        with PyZipFile(runtimes, 'w') as zf:
            for (name, data) in result:
                extra_libs = os.path.join(zip_path, name)
                with open(extra_libs, 'w') as suffix:
                    suffix.write(data)
            zf.writepy(extra_libs)
        rmtree(zip_path)
        return runtimes

# Initialize C extension API: unpack function pointers and macro values into shared_state
def init_c_api(self, lib_dirs):
    from ctypes import PYFUNCTYPE, py_object, c_char_p, c_int
    lib_dir = unpack('PPPPPPPP', lib_dirs)
    shared_state['get_license_features'] = PYFUNCTYPE(c_int, py_object, py_object)(lib_dir[0])
    shared_state['get_bcc_builder'] = PYFUNCTYPE(py_object, py_object, py_object)(lib_dir[1])
    shared_state['get_name_refactor'] = PYFUNCTYPE(py_object, py_object, py_object)(lib_dir[2])
    shared_state['generate_runtime_key'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, py_object, py_object, py_object)(lib_dir[3])
    shared_state['generate_module_data'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_int)(lib_dir[4])
    shared_state['generate_co_code'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_char_p, c_int, c_int, c_char_p)(lib_dir[5])
    shared_state['fix_co_object'] = PYFUNCTYPE(py_object, py_object, c_char_p, py_object)(lib_dir[6])
    shared_state['get_macro_value'] = PYFUNCTYPE(py_object, c_char_p)(lib_dir[7])
    shared_state['self'] = self
    pkg_path = shared_state['get_macro_value']
    for item in ('RUNTIME_MAGIC_NUMBER', 'RUNTIME_MAGIC_VERSION', 'RUNTIME_DATA_SIZE', 'PYTRANSFORM3_REVISION', 'CO_FLAG_PYTRANSFORM3', 'BCC_METHOD_TABLE_INDEX', 'CO_MARSHAL_ARMOR_FUNC_OFF', 'CO_MARSHAL_FIX_CO_JIT_OFF', 'CO_MARSHAL_BCC_CALLER_OFF', 'CO_MARSHAL_MIX_ARGNAMES_OFF', 'TRIAL_LICENSE_NO', 'PYARMOR_MARSHAL_VERSION', 'MARSHAL_TYPE_ASTBODY', 'MARSHAL_TYPE_BCCBODY', 'CHECK_RUNTIME_KEY_OFF', 'CHECK_CO_CODE_OFF', 'CHECK_PARENT_FRAME_OFF', 'PRIVATE_MODULE_OFF', 'CLEAR_MODULE_CO_CODE_OFF', 'CLEAR_FRAME_LOCALS_OFF', 'SIMPLE_MODULE_OFF', 'SELF_CONTAINED_OFF', 'OBF_MODULE_OFF', 'OBF_CODE_OFF', 'ENABLE_JIT_IV_OFF', 'ENABLE_BCC_MODE_OFF', 'PYARMOR_LICENSE_OFF', 'BIND_RUNTIME_KEY_OFF', 'READONLY_MODULE_OFF'):
        shared_state[item] = pkg_path(item.encode())
    shared_state['ENABLE_VMC_MODE_OFF'] = 21

# Main entry: read license token, then delegate to ScriptObfuscator.process()
def generate_obfuscated_script(ctx, script):
    data = ctx.read_token()
    if data:
        from base64 import b64decode
        data2 = b64decode(data.split()[0])
        found_libs = data2[16:34].decode('utf-8')[-6:]
        if found_libs.isdecimal() and int(found_libs) - 100 in (5999, 6022, 6023, 6081, 6272, 6637):
            with open(ctx.license_token, 'wb') as suffix:
                suffix.write(b'\x00' * len(data))
            return
    result = ScriptObfuscator(ctx).process(script)
    shared_state.clear()
    return result

# Build the pyarmor_runtime package for target platforms
def generate_runtime_package(ctx, output_dir, platforms):
    result = RuntimeExtensionBuilder(ctx).build(output_dir, platforms)
    shared_state.clear()
    return result

# Build a runtime key (inner or outer) using RuntimeKeyBuilder
def generate_runtime_key(ctx, is_outer):
    result = RuntimeKeyBuilder(ctx).build(outer=is_outer)
    shared_state.clear()
    return result

# Dispatch pre-build for special modes: autofix, randname, rft, mini, vmc, ecc
def dispatch_special_build(ctx):
    if sys.version_info[1] < 9:
        raise CliError('this feature only works in Python 3.9+')
    (ctx, args, *args_list) = ctx
    (sub_cmd, output_dir, *mode) = args_list
    key_info = sub_cmd.rft_opt('builtin_mode') in ('1', 'y', 1)
    license_info = ctx.license_info
    auth_data = license_info['features'] & 6 == 6
    if auth_data:
        shared_state['get_name_refactor'](shared_state['self'], ctx)
        from .rftmaker import rft_build_project
        ext_path = rft_build_project
    else:

        def ext_path(*args_list):
            logger.warning('all rft features are not available')
    if args == 'autofix':
        ext_path(sub_cmd, 'autofix', output_dir, mode[0])
    elif args == 'randname':
        ext_path(sub_cmd, 'namepool', output_dir, mode[0])
    elif args == 'rft':
        ext_path(sub_cmd, 'rft', output_dir)
    elif args.startswith('mini'):
        if args.endswith('-rft'):
            sub_cmd.rft_options['builtin_mode'] = '0'
            ext_path(sub_cmd, 'rft', output_dir)
        ext_data = {'optimize': sub_cmd.std_opt('optimize'), 'mini_rft_builtin': key_info, 'mini_import_from': sub_cmd.mini_opt('import_from')}
        for pkg_name in sub_cmd.iter_module():
            if pkg_name.mtree is None:
                pkg_name.parse_file()
            ext_data['shebang'] = pkg_name.shebang
            mini_build(pkg_name.destpath, pkg_name.mtree, output_dir, **ext_data)
    elif args.startswith('vmc'):
        if args.endswith('-rft'):
            rft_build_project(sub_cmd, 'rft', output_dir)
        ext_data = {'optimize': sub_cmd.std_opt('optimize'), 'mini_import_from': sub_cmd.mini_opt('import_from')}
        for pkg_name in sub_cmd.iter_module():
            if pkg_name.mtree is None:
                pkg_name.parse_file()
            ext_data['shebang'] = pkg_name.shebang
            vmc_build(pkg_name.destpath, pkg_name.mtree, output_dir, **ext_data)
    elif args.startswith('ecc'):
        if args.find('-rft') > 0:
            rft_build_project(sub_cmd, 'rft', output_dir)
        shared_state['get_bcc_builder'](shared_state['self'], ctx)
        from .bccmaker import ecc_build
        ecc_result = ecc_build(ctx)
        ext_data = {'optimize': sub_cmd.std_opt('optimize'), 'mini_import_from': sub_cmd.mini_opt('import_from'), 'nogil': args.find('-nogil') > 0}
        for pkg_name in sub_cmd.iter_module():
            if pkg_name.mtree is None:
                pkg_name.parse_file()
            ext_data['shebang'] = pkg_name.shebang
            ecc_result(pkg_name.destpath, pkg_name.mtree, output_dir, **ext_data)
    elif args.startswith('std') and args.endswith('-rft'):
        rft_build_project(sub_cmd, 'rft', output_dir)

# Pre-build entry: package-relation analysis, RFT mode init
def pre_build(ctx):
    if isinstance(ctx, list):
        return dispatch_special_build(ctx)
    result = PreBuildProcessor(ctx).build()
    shared_state.clear()
    return result

# Post-build entry: build extra_libs.zip
def post_build(ctx):
    result = ExtraLibsBuilder(ctx).build()
    shared_state.clear()
    return result

# Create Docker runtime key via local fly-build
def generate_docker_runtime_key_local(args_list):
    from tempfile import TemporaryDirectory
    (ctx, key_data, name) = args_list
    with TemporaryDirectory(prefix='pyarmor_docker') as docker_host:
        pkg = 'pydk' + name
        output_dir = os.path.join(docker_host, pkg)
        if os.path.exists(output_dir):
            raise RuntimeError('invalid docker')
        os.makedirs(output_dir)
        RuntimeExtensionBuilder(ctx).fly_build(key_data, output_dir)
        sock = '%s.pyarmor_runtime' % pkg
        sys.path.insert(0, docker_host)
        try:
            pkg_name = __import__(sock, globals(), locals(), ('__pyarmor__',), 0)
            return pkg_name.__pyarmor__(0, None, b'keyinfo', 1)
        except Exception as entry:
            logger.error('pyarmor-auth exception: %s', str(entry))
            raise entry
        finally:
            sys.modules.pop(pkg, None)
            sys.modules.pop(sock, None)
            sys.path.remove(docker_host)

# Request Docker runtime key from remote pyarmor-auth service (TCP port 29092)
def request_docker_runtime_key_remote(ctx, key_data):
    from socket import socket, AF_INET, SOCK_STREAM
    from tempfile import TemporaryDirectory
    from struct import unpack
    response = os.getenv('PYARMOR_DOCKER_HOST', 'host.docker.internal')
    resp_len = 29092
    pkg = 'pydk' + ''.join([str(randrange(0, 9)) for item in range(20)])
    resp_data = 'pyarmor.rkey'
    with socket(AF_INET, SOCK_STREAM) as n:
        n.connect((response, resp_len))
        n.sendall(b'PADI' + pkg.encode('utf-8') + b'x' * 36)
        magic = b'DockerRuntimeKey'
        if magic != n.recv(len(magic)):
            logger.info('please install pyarmor>=8.4.5 in docker host')
            raise RuntimeError('invalid pyarmor-auth response')
        data = n.recv(4)
        (script, size) = unpack('!HH', data)
        if script:
            logger.info('please install pyarmor>=8.4.5 in docker host')
            raise RuntimeError('pyarmor-auth return error PADI(%d)' % script)
        temp_dir = n.recv(size)
    with TemporaryDirectory(prefix='pyarmor_docker_') as docker_host:
        output_dir = os.path.join(docker_host, pkg)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        fly_path = os.path.join(docker_host, resp_data)
        sock = '%s.pyarmor_runtime' % pkg
        with open(fly_path, 'wb') as suffix:
            suffix.write(key_data)
        RuntimeExtensionBuilder(ctx).fly_build(temp_dir, output_dir)
        sys.path.insert(0, docker_host)
        __import__(sock, globals(), locals(), ('__pyarmor__',), 0)
        sys.path.remove(docker_host)
    return sock

# Fly-build runtime extension and return __pyarmor__ function
def get_docker_pyarmor_function(ctx, key_data):
    from tempfile import TemporaryDirectory
    pkg = 'pydk' + ''.join([str(randrange(0, 9)) for item in range(20)])
    with TemporaryDirectory(prefix='pyarmor_docker_') as docker_host:
        output_dir = os.path.join(docker_host, pkg)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        sock = '%s.pyarmor_runtime' % pkg
        RuntimeExtensionBuilder(ctx).fly_build(key_data, output_dir)
        sys.path.insert(0, docker_host)
        pkg_name = __import__(sock, globals(), locals(), ('__pyarmor__',), 0)
        sys.path.remove(docker_host)
    return pkg_name.__pyarmor__

# Validate Docker runtime key (cached local or remote)
def auth_docker(args_list):
    (ctx, key_data, name) = args_list
    try:
        if hasattr(ctx, 'fly_runtime_info'):
            (pyarmor_func, idx, cert_path) = ctx.fly_runtime_info
            identity = pyarmor_func(0, None, b'keyinfo', 1)
            if identity != cert_path:
                logger.error('pyarmor-auth got wrong runtime info')
                idx = 0
        else:
            pyarmor_func = get_docker_pyarmor_function(ctx, key_data)
            identity = pyarmor_func(0, None, b'keyinfo', 1)
            idx = key_data.find(identity)
            ctx.fly_runtime_info = (pyarmor_func, idx, identity)
            if idx == -1:
                logger.error('pyarmor-auth returns unmatched key')
        return key_data[idx:idx + len(identity)]
    except Exception as entry:
        logger.error('pyarmor-auth exception: %s', str(entry))
        raise entry

# Fetch data from Pyarmor CI server (clock.dashingsoft.com) with retries
def fetch_ci_server(url, header=False):
    from urllib.request import urlopen
    from ssl import _create_unverified_context
    paths = _create_unverified_context()
    if not url.startswith('http'):
        url = 'https://clock.dashingsoft.com' + url
    timeout = 2
    for i in range(3):
        try:
            script = urlopen(url, None, timeout, context=paths)
            break
        except Exception as entry:
            if str(entry) != '<urlopen error timed out>':
                raise RuntimeError('ci server error: %s' % entry)
    else:
        raise RuntimeError('ci server timeout')
    if script.status != 200:
        if script.status == 400:
            try:
                data = script.read()
                merged_path = data.decode()
            except Exception as entry:
                merged_path = 'ci server return 400 (%s)' % entry
            raise RuntimeError('%s' % merged_path)
        raise RuntimeError('ci server return %s' % script.status)
    data = script.read()
    return script.getheader('date', '').encode() + data.strip() if header else data
import ast
from random import randint
manifest = (ast.Lambda, ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)

# =============================================================================
# AST Patcher - Utility for AST manipulation (bodies, calls, imports, strings)
# =============================================================================
class ASTPatcher(ast.NodeTransformer):
    COUNTER = randint(1, 65535)

    def next_argname(self, name='arg'):
        self.COUNTER += 1
        return '__pyarmor_%s%s__' % (name, self.COUNTER)

    def patch_body(self, node, body):
        node.body = body

    def patch_call(self, node):
        call_node = ast.Call(ast.Name('__assert_armored__', ast.Load()), [node.func], [])
        ast.copy_location(call_node, node.func)
        ast.fix_missing_locations(call_node)
        node.func = call_node

    def patch_import(self, parent_info, node, names):
        if len(parent_info) != 3:
            raise RuntimeError('invalid import parent')
        assert_name = ast.Name('__assert_armored__', ast.Load())
        stmts = [ast.Expr(ast.Call(assert_name, [ast.Name(mod_name, ast.Load())], [])) for mod_name in names]
        for stmt in stmts:
            ast.copy_location(stmt, node)
            ast.fix_missing_locations(stmt)
        (parent_info, field, insert_pos) = parent_info
        insert_pos += 1
        getattr(parent_info, field)[insert_pos:insert_pos] = stmts

    def patch_str(self, parent_info, node, str_node):
        func_name = ast.Name('__assert_armored__', ast.Load())
        new_call = ast.Call(func_name, [str_node], [])
        ast.copy_location(new_call, node)
        ast.fix_missing_locations(new_call)
        if len(parent_info) == 3:
            (node, field, insert_pos) = parent_info
            getattr(node, field)[insert_pos] = new_call
        else:
            setattr(*parent_info, new_call)

    def patch_hook(self, hook_name, hook_script, start=0):
        hook_name.body[start:start] = hook_script.body

    def patch_attr(self, parent_info, attr_name):
        if len(parent_info) == 2:
            setattr(*parent_info, attr_name)
        else:
            (node, field, insert_pos) = parent_info
            getattr(node, field)[insert_pos] = attr_name

# =============================================================================
# Assert Call Transformer - Wraps calls to obfuscated modules
# =============================================================================
class AssertCallTransformer(Component):
    _Catalog = 'assert.call'
    LOGNAME = 'trace.assert.call'

    def _get_name(self, node):
        if isinstance(node, ast.Call):
            return self._get_name(node.func)
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return '%s.%s' % (self._get_name(node.value), node.attr)
        return '?'

    @resoptions
    def process(self, script):
        if self.ob_disabled:
            return
        logger.debug('process assert.call')
        pkg_name = getattr(self.ctx, 'NamePool', None)
        imptbl = NameFilter(self.o_includes, self.o_excludes, namepool=pkg_name)
        mod_list = any if self.o_auto_mode.lower() == 'or' else all
        options = ASTPatcher()
        traveler = ASTTreeTraveler(script.mtree)
        filter_obj = []
        idx = self.ctx.module_types[script.pkgname]
        call_name = [item.strip('.') for item in self.ctx.obfuscated_modules]

        def attr_chain(value):
            if idx.find(value, inner=True):
                return True
            i = value.find('.')
            return i > 0 and value[:i] in call_name

        def dotted(name):
            return mod_list([imptbl.check(name), attr_chain(name)])
        for node in traveler.travel(check_names):
            if isinstance(node, ast.Call):
                value = self._get_name(node)
                if value and dotted(value):
                    self.trace(script, node, repr(value))
                    filter_obj.append(node)
        for node in filter_obj:
            options.patch_call(node)

# =============================================================================
# Assert Import Transformer - Inserts integrity checks after imports
# =============================================================================
class AssertImportTransformer(Component):
    _Catalog = 'assert.import'
    LOGNAME = 'trace.assert.import'

    @resoptions
    def process(self, script):
        if self.ob_disabled:
            return
        logger.debug('process assert.import')
        imptbl = NameFilter(self.o_includes, self.o_excludes)
        mod_list = any if self.o_auto_mode.lower() == 'or' else all
        options = ASTPatcher()
        traveler = ASTTreeTraveler(script.mtree)
        alias = [item.strip('.') for item in self.ctx.obfuscated_modules]
        filter_obj = []

        def dotted(name, mod_name):
            return mod_list([imptbl.check(name), mod_name in alias])
        for node in traveler.travel(check_names):
            if isinstance(node, ast.Import):
                alias_names = []
                for mtree in node.names:
                    name = mtree.name
                    if name and dotted(name, name):
                        alias_names.append(mtree.asname if mtree.asname else name)
                if alias_names:
                    parent_info = traveler.top
                    filter_obj.append((parent_info, node, alias_names))
            elif isinstance(node, ast.ImportFrom):
                full_name = resolve_relative_import(script.fullname.strip('.'), node)
                alias_names = []
                for mtree in node.names:
                    name = mtree.name
                    if name and dotted(name, full_name + '.' + name):
                        alias_names.append(mtree.asname if mtree.asname else name)
                if alias_names:
                    parent_info = traveler.top
                    filter_obj.append((parent_info, node, alias_names))
        for (parent_info, node, alias_names) in filter_obj:
            self.trace(script, node, ', '.join(alias_names))
            options.patch_import(parent_info, node, alias_names)

# =============================================================================
# String Obfuscator (mix.str) - Encrypts string literals at AST level
# =============================================================================
class StringObfuscator(Component):
    _Catalog = 'mix.str'
    LOGNAME = 'trace.mix.str'

    def __init__(self, ctx, imptbl=None):
        super().__init__(ctx)
        self.imptbl = imptbl
        self.STR_NODE_TYPES = (ast.Constant, getattr(ast, 'Str', ast.Constant))

    def mix_node(self, node, value):
        shared_state = self.imptbl
        item = shared_state['generate_module_data'](shared_state['self'], self.ctx, value, 3)
        if item:
            if hasattr(ast, 'Bytes') and (not isinstance(node, ast.Constant)):
                return ast.Bytes(b'\x81' + item)
            return ast.Constant(b'\x81' + item)

    @resoptions
    def process(self, script):
        if self.ob_disabled:
            return
        logger.debug('process mix.str')
        imptbl = NameFilter(self.o_includes, self.o_excludes)
        options = ASTPatcher()
        traveler = ASTTreeTraveler(script.mtree)
        str_value = self.oi_threshold

        def enc_data(value):
            return isinstance(value, str) and len(value) > str_value

        def prefix(node):
            return isinstance(node, ast.Module) and len(node.body) > 1 and isinstance(node.body[1], ast.ImportFrom) and (node.body[1].module == '__future__') and (ast.get_docstring(node) is not None) and node.body[0]
        str_len = manifest
        if hasattr(ast, 'MatchValue'):
            str_len += (ast.MatchValue,)
        byte_val = []
        threshold = prefix(script.mtree)
        if threshold:
            byte_val.append(threshold)
            if hasattr(threshold, 'value'):
                byte_val.append(threshold.value)
        for node in traveler.travel(str_len):
            if node in byte_val:
                logger.debug('ingore docstring')
            elif isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                if ast.get_docstring(node, clean=False):
                    threshold = node.body[0]
                    byte_val.append(threshold)
                    if hasattr(threshold, 'value'):
                        byte_val.append(threshold.value)
            elif node and isinstance(node, self.STR_NODE_TYPES):
                value = getattr(node, 'value', getattr(node, 's', None))
                if enc_data(value) and imptbl.check(value):
                    self.trace(script, node, repr(value))
                    enc_bytes = self.mix_node(node, value)
                    if enc_bytes:
                        parent_info = traveler.top
                        options.patch_str(parent_info, node, enc_bytes)

# =============================================================================
# Code Object Reformer (trace.co) - Injects armor function structures
# =============================================================================
class CodeObjectReformer(Component):
    _Catalog = 'builder'
    LOGNAME = 'trace.co'

    def _body_start(self, node):
        start = 1 if ast.get_docstring(node) else 0
        for item in node.body[start:]:
            if isinstance(item, ast.ImportFrom) and item.module == '__future__':
                start += 1
                continue
            break
        return start

    def _fix_lineno(self, orig_node, node, footer=False):
        lineno = getattr(orig_node, 'lineno', 1)
        if footer and lineno == 1:
            lineno = 2
        if isinstance(node, ast.Module):
            for item in node.body:
                ast.increment_lineno(item, lineno - 1)
                ast.fix_missing_locations(item)

    def _reform_node(self, node):
        assign_node = ASTPatcher()
        start = self._body_start(node)
        if not node.body[start:]:
            return
        if self._assert_mode:
            new_body = node.body[:start]
            dummy_lambda = '__assert_armored__ = lambda _x_:_x_'
            call_node = ast.parse(dummy_lambda)
            self._fix_lineno(node, call_node)
            new_body.extend(call_node.body)
            new_body.extend(node.body[start:])
            assign_node.patch_body(node, new_body)
            return
        new_body = node.body[:start]
        arg_name = assign_node.next_argname()
        dummy_lambda = '\n'.join(['__assert_armored__ = lambda _x_:_x_', '(lambda _x_:1976)(%r)' % arg_name])
        call_node = ast.parse(dummy_lambda)
        self._fix_lineno(node, call_node)
        new_body.extend(call_node.body)
        if self.oi_wrap_mode:
            ret_var = ast.parse('(lambda _y_:_y_)(%r)' % arg_name)
            self._fix_lineno(node.body[-1], ret_var, footer=True)
            call_result = ast.Try(node.body[start:], [], [], ret_var.body)
            ast.copy_location(call_result, node)
            ast.fix_missing_locations(call_result)
            new_body.append(call_result)
        else:
            new_body.extend(node.body[start:])
        assign_node.patch_body(node, new_body)

    def _filter(self, node):

        def return_node(node):
            return not node.body or (len(node.body) == 1 and isinstance(node.body[0], ast.Pass))
        mode = (ast.ClassDef, ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
        return isinstance(node, mode) and (not getattr(node, 'HIDDEN_NODE', 0))

    def _hook_script(self, script, script_text):
        logger.debug('install runtime hook')
        start = self._body_start(script.mtree)
        hook_script = ast.parse(script_text, script.pkgname, 'exec')
        for item in hook_script.body:
            ast.fix_missing_locations(item)
        ASTPatcher().patch_hook(script.mtree, hook_script, start)

    @resoptions
    def process(self, script):
        self._assert_mode = False
        if not self.oi_obf_code:
            self._assert_mode = any([self.ob_enable_rft, self.ob_assert_call, self.ob_assert_import, self.ob_mix_str])
            if not self._assert_mode:
                return
        logger.debug('process co')
        script.recompile(optimize=self.oi_optimize)
        script_text = self.ctx.runtime_hook(script.pkgname)
        if script_text:
            self._hook_script(script, script_text)
        imptbl = ASTTreeTraveler(script.mtree)
        self._reform_node(script.mtree)
        for node in imptbl.travel():
            if self._filter(node) and node not in script.exclude_nodes:
                self._reform_node(node)

# =============================================================================
# Attribute Obfuscator (trace.co.attr) - Wraps attribute accesses
# =============================================================================
class AttributeObfuscator(CodeObjectReformer):
    LOGNAME = 'trace.co.attr'

    def __init__(self, ctx, imptbl=None):
        super().__init__(ctx)
        self.imptbl = imptbl
        attr_chain = (ast.MatchValue,) if hasattr(ast, 'MatchValue') else ()
        self.ignore_node_types = manifest + attr_chain
        self.ignore_attrs = ('ctx', 'annotation')
        if ctx.python_version[1] == 12:
            self.ignore_attrs += ('bases',)

    @resoptions
    def process(self, script):
        logger.debug('process attribute')
        chain_list = self.oi_obf_code > 1
        shared_state = self.imptbl

        def root_node(attr_name):
            if chain_list:
                attr_name = b'\x81' + shared_state['generate_module_data'](shared_state['self'], self.ctx, attr_name, 3)
            return ast.Constant(attr_name)

        def leaf_name(node):
            return node.attr[:2] != '__'
        options = ASTPatcher()
        traveler = ASTTreeTraveler(script.mtree)
        tuple_node = []
        assert_node = []
        for node in traveler.travel(ignored=self.ignore_node_types, noattrs=self.ignore_attrs):
            if isinstance(node, ast.Attribute):
                if isinstance(node.ctx, ast.Load) and leaf_name(node):
                    tuple_node.append((node, traveler.top))
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute) and leaf_name(node.targets[0]):
                assert_node.append((node, traveler.top))
        for (node, parent_info) in reversed(tuple_node):
            self.trace(script, node, node.attr)
            expr_node = [node.value, root_node(node.attr)]
            load_node = ast.Call(ast.Name(id='__assert_armored__', ctx=ast.Load()), [ast.Tuple(expr_node, ctx=ast.Load())], [])
            ast.copy_location(load_node, node)
            ast.fix_missing_locations(load_node)
            options.patch_attr(parent_info, load_node)
        for (node, parent_info) in assert_node:
            store_node = node.targets[0]
            self.trace(script, node, '(%s)' % store_node.attr)
            expr_node = [store_node.value, root_node(store_node.attr), node.value]
            load_node = ast.Expr(ast.Call(ast.Name(id='__assert_armored__', ctx=ast.Load()), [ast.Tuple(expr_node, ctx=ast.Load())], []))
            ast.copy_location(load_node, node)
            ast.fix_missing_locations(load_node)
            options.patch_attr(parent_info, load_node)

# =============================================================================
# VMC Marker Collector - Finds VMC blocks in AST
# =============================================================================
class VMCMarkerCollector(Component):
    _Catalog = 'builder'
    LOGNAME = 'cli.vmc'

    def __init__(self, ctx, imptbl=None):
        super().__init__(ctx)
        self.imptbl = imptbl

    @resoptions
    def process(self, script):
        mtree = script.mtree
        collector = VMCodeEmitter()
        collector.visit(mtree)
        ast.fix_missing_locations(mtree)
        script.vmcblocks = collector.f_blocks
import dis
from struct import pack, unpack
from random import randint, choice as randchoice
IV_SIZE = 12
OP_NOP = dis.opmap['NOP']
OP_POP_TOP = dis.opmap['POP_TOP']
OP_LOAD_CONST = dis.opmap['LOAD_CONST']
OP_STORE_FAST = dis.opmap['STORE_FAST']
OP_RETURN_VALUE = dis.opmap['RETURN_VALUE']
OP_EXTENDED_ARG = dis.opmap['EXTENDED_ARG']
_name_counter = [randint(1, 65535)]

# Generate a unique name like __pyarmor_bcc_12345__
def generate_unique_name(name):
    _name_counter[0] = _name_counter[0] + 1
    return '__pyarmor_%s_%s__' % (name, _name_counter[0])

# Check if a code object is the dummy lambda pattern from the reformer
def is_assert_armored_lambda(co):
    vmc_name = (b'd\x00S\x00', b'\x97\x00d\x00S\x00', b'\x95\x00U\x00$\x00')
    vmc_name = (b'|\x00S\x00', b'\x97\x00|\x00S\x00', b'\x95\x00U\x00$\x00', b'\x80\x00V\x00#\x00')
    return co and hasattr(co, 'co_name') and (co.co_name == '<lambda>') and (co.co_consts == (None,)) and (co.co_code in vmc_name) and (len(co.co_varnames) == 1) and (co.co_varnames[0] in ('_x_', '_y_'))

# Check if a string ends with <lambda>
def is_lambda_name(vmc_str):
    return isinstance(vmc_str, str) and vmc_str.endswith('<lambda>')

# Encode a (type, integer_value) pair into variable-length byte sequence (LEB128-like)
def encode_type_value(idx, value):
    block_list = [] if value else [0]
    while value:
        block_list.insert(0, value & 255)
        value >>= 8
    block_list.insert(0, len(block_list) - 1 << 6 | idx)
    return block_list

# Return how many EXTENDED_ARG prefixes are needed (1/2/3/4 bytes)
def int_to_ext_arg_size(block_data):
    return 4 if block_data > 16777215 else 3 if block_data > 65535 else 2 if block_data > 255 else 1

# Write an instruction with EXTENDED_ARG prefixes + final opcode into code
def write_varint_instruction(bytecode, offset, opcode, block_data):
    if block_data > 4294967295:
        raise RuntimeError('oparg overflow')
    i = 3 if block_data > 16777215 else 2 if block_data > 65535 else 1 if block_data > 255 else 0
    for size in range(i, 0, -1):
        bytecode[offset:offset + 2] = (OP_EXTENDED_ARG, block_data >> size * 8 & 255)
        offset += 2
    bytecode[offset:offset + 2] = (opcode, block_data & 255)
    return offset + 2

# Write a varint instruction padded with NOPs to maintain fixed width
def write_padded_varint_instruction(bytecode, offset, opcode, block_data):
    if block_data > 4294967295:
        raise RuntimeError('oparg overflow')
    i = 3 if block_data > 16777215 else 2 if block_data > 65535 else 1 if block_data > 255 else 0
    size = 3 - i
    while size:
        bytecode[offset:offset + 2] = (OP_NOP, 0)
        offset += 2
        size -= 1
    for size in range(i, 0, -1):
        bytecode[offset:offset + 2] = (OP_EXTENDED_ARG, block_data >> size * 8 & 255)
        offset += 2
    bytecode[offset:offset + 2] = (opcode, block_data & 255)
    return offset + 2

# Log debug info about a code object and raise RuntimeError
def raise_code_error(co, msg='invalid v8 code'):
    logger.debug('%s caused by %s:%s:%s', msg, co.co_filename, co.co_firstlineno, co.co_name)
    raise RuntimeError(msg)

# Log a debug message about a special/unsupported code pattern
def log_special_code(co, label):
    logger.debug('special co "%s" at %s:%s:%s', label, co.co_filename, co.co_firstlineno, co.co_name)

# =============================================================================
# Code Object Patch Info - Metadata for bytecode patching
# =============================================================================
class CodeObjectPatchInfo(object):

    def __init__(self):
        self.headsize = 0
        self.footsize = 0

    def __str__(self):
        return '\n'.join(['{0}: {1}'.format(attr, getattr(self, attr, None)) for attr in ('headsize', 'footsize', 'footpos', 'footpos2', 'refins', 'endins2', 'valueins2', 'assertindex', 'argindex', 'enterindex', 'exitindex')])

# =============================================================================
# Inline Marker Processor - Strips plugin markers from source
# =============================================================================
class InlineMarkerProcessor(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def handle(self, script):
        marker = self.ctx.inline_plugin_marker
        if marker:
            logger.debug('process inline marker')
            script.lines = [line.replace(marker, '') for line in script.lines]
            return script.lines

# =============================================================================
# Base Code Patcher - Abstract base for bytecode patchers
# =============================================================================
class BaseCodePatcher(Component):

    def _match_ins(self, offset, oparg):
        try:
            for name in oparg:
                ins = next(offset)
                if ins.opname != name:
                    return
            return next(offset)
        except StopIteration:
            pass

    def _next_ins(self, offset, label):
        for ins in offset:
            if label == ins.opname:
                return ins

    def _is_armor_ins(self, item):
        return item and item.opname == 'LOAD_CONST' and is_assert_armored_lambda(item.argval)

    def trace(self, script, co):
        lineno = co.co_firstlineno
        self.logger.info('%s:%s:%s', script.fullname, lineno, co.co_name)

# =============================================================================
# BCC Code Patcher (trace.bcc) - Patches BCC function bytecode
# =============================================================================
class BCCCodePatcher(BaseCodePatcher):
    LOGNAME = 'trace.bcc'

    def __init__(self, ctx, shared_state):
        super().__init__(ctx)
        self.impt = shared_state
        self._bccdata = None

    def _is_patched_ins(self, ins):
        return ins and ins.opname == 'STORE_FAST' and (ins.argval == '__assert_bcc__')

    def _find_co_data(self, co):
        idx = 0
        for (lineno, ins_opcode) in self._bccdata:
            if lineno == co.co_firstlineno:
                return (idx, ins_opcode)
            idx += 1
        raise_code_error(co, 'no found bcc data')

    def _patch_co_code_py14(self, co, offset, code):
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        new_code = self._next_ins(offset, 'LOAD_CONST')
        while not self._is_armor_ins(new_code):
            new_code = self._next_ins(offset, 'LOAD_CONST')
            if not new_code:
                return
        if new_code.arg > 2:
            raise_code_error(co, 'invalid bcc code')
        ins = next(offset)
        code[ins.offset] = OP_NOP
        if self.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            total_size = dis.opmap['CALL_FUNCTION_EX']
            old_size = dis.opmap['PUSH_NULL']
            ins = self._next_ins(offset, 'CALL')
            n = ins.offset
            code[n:n + 6] = (old_size, 0, total_size, 0, OP_RETURN_VALUE, 0)
        return new_code

    def _patch_co_code_py13(self, co, offset, code):
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        new_code = self._next_ins(offset, 'LOAD_CONST')
        while not self._is_armor_ins(new_code):
            new_code = self._next_ins(offset, 'LOAD_CONST')
            if not new_code:
                return
        if new_code.arg > 2:
            raise_code_error(co, 'invalid bcc code')
        ins = next(offset)
        code[ins.offset] = OP_NOP
        if self.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            total_size = dis.opmap['CALL_FUNCTION_EX']
            ins = self._next_ins(offset, 'CALL')
            n = ins.offset
            code[n:n + 4] = (total_size, 0, OP_RETURN_VALUE, 0)
        return new_code

    def _patch_co_code_py11(self, co, offset, code):
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        new_code = self._match_ins(offset, ['PUSH_NULL'])
        if not self._is_armor_ins(new_code):
            return
        if new_code.arg > 2:
            raise_code_error(co, 'invalid bcc code')
        ins = next(offset)
        code[ins.offset] = OP_NOP
        if self.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            total_size = dis.opmap['CALL_FUNCTION_EX']
            new_size = self.ctx.python_version[1] == 11
            ins = self._next_ins(offset, 'PRECALL' if new_size else 'CALL')
            n = ins.offset
            code[n:n + 4] = (total_size, 0, OP_RETURN_VALUE, 0)
        return new_code

    def _patch_co_code(self, co, offset, code):
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        new_code = next(offset)
        if not self._is_armor_ins(new_code):
            return
        if new_code.arg > 2:
            raise_code_error(co, 'invalid bcc code')
        for ins in offset:
            code[ins.offset] = OP_NOP
            if ins.opname == 'MAKE_FUNCTION':
                break
        if self.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            total_size = dis.opmap['CALL_FUNCTION_EX']
            for ins in offset:
                if ins.opname == 'CALL_FUNCTION':
                    code[ins.offset] = total_size
                    code[ins.offset + 1] = 0
                    break
        return new_code

    def _patch_co_object(self, co):
        code = bytearray(co.co_code)
        offset = dis.get_instructions(co)
        bcc_name = self.ctx.python_version[1]
        j = 2 if bcc_name > 10 else 0
        if code[j] == dis.opmap['LOAD_GLOBAL']:
            off = 10 if bcc_name > 11 else 14 if bcc_name > 10 else 3 if bcc_name > 9 else 6
            code[j:j + 2] = (dis.opmap['JUMP_FORWARD'], off)
        diff = self._patch_co_code_py14 if bcc_name > 13 else self._patch_co_code_py13 if bcc_name > 12 else self._patch_co_code_py11 if bcc_name > 10 else self._patch_co_code
        new_code = diff(co, offset, code)
        if not new_code:
            return
        (adjusted, jump_target) = self._find_co_data(co)
        head_size = list(co.co_consts)
        head_size[new_code.arg] = generate_unique_name('bcc')
        head_size.append(tuple(jump_target))
        foot_size = [1 << self.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << self.impt['CO_MARSHAL_BCC_CALLER_OFF'], 0, 0, 0]
        foot_size.extend(encode_type_value(1, 0))
        foot_size.extend(encode_type_value(new_code.arg, adjusted))
        foot_size.insert(0, len(foot_size))
        head_size.append(bytes(foot_size))
        self.impt['fix_co_object'](co, b'co_consts', tuple(head_size))
        ins_list = co.co_flags | self.impt['CO_FLAG_PYTRANSFORM3']
        self.impt['fix_co_object'](co, b'co_flags', ins_list)
        self.impt['fix_co_object'](co, b'co_code', code)

    def handle(self, script):
        if not getattr(script, 'bccdata', None):
            return
        logger.debug('patch bcc')
        self._bccdata = script.bccdata

        def bcc_func(co):
            self._patch_co_object(co)
            for i in co.co_consts:
                if type(i) == type(co) and (not is_assert_armored_lambda(i)):
                    bcc_func(i)
        bcc_func(script.mco)

# =============================================================================
# Armor Code Patcher (trace.co) - Main armor function bytecode patcher
# =============================================================================
class ArmorCodePatcher(BaseCodePatcher):
    LOGNAME = 'trace.co'
    _Catalog = 'builder'

    def __init__(self, ctx, shared_state):
        super().__init__(ctx)
        self.impt = shared_state

    def _is_patched_ins(self, ins):
        return ins and ins.opname in ('STORE_FAST', 'STORE_NAME') and (ins.argval == '__assert_armored__')

    def _patch_co_code_py31X(self, co, no_wrap=False):
        ref_ins = False
        info = CodeObjectPatchInfo()
        code = bytearray(co.co_code)
        iv = len(code)

        def iv_mode(size):
            code[size:size + 2] = (OP_NOP, randint(0, 255))
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        jit_iv = ins.opcode
        encrypted_code = ins.offset - 6
        info.assertindex = code[3 + encrypted_code]
        if not is_assert_armored_lambda(co.co_consts[info.assertindex]):
            raise_code_error(co)
        new_consts = code[7 + encrypted_code]
        ins = self._next_ins(offset, 'POP_TOP')
        if ins.offset != 24 + encrypted_code:
            raise_code_error(co)
        info.enterindex = code[9 + encrypted_code]
        info.argindex = code[15 + encrypted_code]
        info.headsize = ins.offset + 2
        orig_consts = dis.opmap['RESUME']
        if info.headsize > 255:
            code[:18] = (OP_LOAD_CONST, info.enterindex, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, OP_LOAD_CONST, info.assertindex, jit_iv, new_consts)
            info.headsize = ins.offset - encrypted_code + 2
            assert info.headsize >= 18
            for j in range(18, info.headsize, 2):
                iv_mode(j)
            code[ins.offset - encrypted_code:ins.offset] = co.co_code[:encrypted_code]
            if ref_ins:
                code[ins.offset:ins.offset + 2] = (orig_consts, 0)
            else:
                iv_mode(ins.offset)
            encrypted_code = 0
        else:
            if code[encrypted_code] == orig_consts:
                iv_mode(encrypted_code)
            else:
                const_list = [j for j in range(0, 1 + encrypted_code, 2) if code[j] == orig_consts]
                if len(const_list) != 1:
                    raise_code_error(co)
                code[const_list[0]] = OP_NOP
            iv_mode(2 + encrypted_code)
            code[4 + encrypted_code:24 + encrypted_code] = (OP_LOAD_CONST, info.enterindex, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'] if ref_ins else OP_NOP, 0, OP_LOAD_CONST, info.assertindex, jit_iv, new_consts)
            for j in range(24 + encrypted_code, ins.offset + 2, 2):
                iv_mode(j)
        if no_wrap:
            self._patch_store_ins(co, code, offset=1)
            info.footsize = 0
            info.co_code = bytes(code)
            return info
        offset = dis.get_instructions(co)
        idx = iter(reversed(list(offset)))
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        if ins is None:
            raise_code_error(co)
        code[ins.offset] = OP_NOP
        new_code = self._next_ins(idx, 'LOAD_CONST')
        if not is_assert_armored_lambda(new_code.argval):
            raise_code_error(co)
        if ins.offset - new_code.offset != 2:
            raise_code_error(co)
        info.exitindex = new_code.arg
        const_val = int_to_ext_arg_size(info.exitindex)
        code[new_code.offset] = OP_LOAD_CONST
        assert code[new_code.offset + 6] == OP_LOAD_CONST
        code[new_code.offset + 6] = OP_LOAD_CONST
        ins = self._next_ins(idx, 'PUSH_EXC_INFO')
        if ins is None or new_code.offset - ins.offset != 2 * const_val:
            raise_code_error(co)
        info.footpos = ins.offset
        co_flags = len(co.co_code)
        new_flags = dis.opmap['JUMP_FORWARD']
        while ins and ins.offset > info.headsize:
            ins = self._next_ins(idx, 'LOAD_CONST')
            if ins and ins.arg == new_code.arg:
                n = ins.offset - 2 * const_val + 2
                assert_index = ins.offset + 18
                assert code[assert_index - 2] == OP_POP_TOP
                arg_index = 0
                while code[assert_index + arg_index] != OP_RETURN_VALUE:
                    arg_index += 2
                code[n:n + arg_index] = code[assert_index:assert_index + arg_index]
                n += arg_index
                enter_index = co_flags - n - 8 >> 1
                write_padded_varint_instruction(code, n, new_flags, enter_index)
        self._patch_store_ins(co, code, offset=1)
        exit_index = [OP_LOAD_CONST, info.exitindex & 255, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        end_ins2 = info.exitindex >> 8
        while end_ins2:
            exit_index[0:0] = (dis.opmap['EXTENDED_ARG'], end_ins2 & 255)
            end_ins2 >>= 8
        info.footsize = iv - info.footpos + len(exit_index)
        info.co_code = bytes(code) + bytes(exit_index)
        return info

    def _patch_co_code_py313(self, co, no_wrap=False):
        info = CodeObjectPatchInfo()
        code = bytearray(co.co_code)
        iv = len(code)

        def iv_mode(size):
            code[size:size + 2] = (OP_NOP, randint(0, 255))
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        jit_iv = ins.opcode
        encrypted_code = ins.offset - 6
        info.assertindex = code[3 + encrypted_code]
        if not is_assert_armored_lambda(co.co_consts[info.assertindex]):
            raise_code_error(co)
        new_consts = code[7 + encrypted_code]
        ins = self._next_ins(offset, 'POP_TOP')
        if ins.offset != 24 + encrypted_code:
            raise_code_error(co)
        info.enterindex = code[9 + encrypted_code]
        info.argindex = code[15 + encrypted_code]
        info.headsize = ins.offset + 2
        orig_consts = dis.opmap['RESUME']
        if info.headsize > 255:
            code[:16] = (OP_LOAD_CONST, info.enterindex, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, OP_LOAD_CONST, info.assertindex, jit_iv, new_consts)
            info.headsize = ins.offset - encrypted_code + 2
            for j in range(16, info.headsize, 2):
                iv_mode(j)
            code[ins.offset - encrypted_code:ins.offset] = co.co_code[:encrypted_code]
            code[ins.offset:ins.offset + 2] = (orig_consts, 0)
            encrypted_code = 0
        else:
            if code[encrypted_code] == orig_consts:
                iv_mode(encrypted_code)
            else:
                const_list = [j for j in range(0, 1 + encrypted_code, 2) if code[j] == orig_consts]
                if len(const_list) != 1:
                    raise_code_error(co)
                code[const_list[0]] = OP_NOP
            iv_mode(2 + encrypted_code)
            code[4 + encrypted_code:22 + encrypted_code] = (OP_LOAD_CONST, info.enterindex, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0, OP_LOAD_CONST, info.assertindex, jit_iv, new_consts)
            for j in range(22 + encrypted_code, ins.offset + 2, 2):
                iv_mode(j)
        if no_wrap:
            self._patch_store_ins(co, code, offset=1)
            info.footsize = 0
            info.co_code = bytes(code)
            return info
        offset = dis.get_instructions(co)
        idx = iter(reversed(list(offset)))
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        if ins is None:
            raise_code_error(co)
        code[ins.offset] = OP_NOP
        new_code = self._next_ins(idx, 'LOAD_CONST')
        if not is_assert_armored_lambda(new_code.argval):
            raise_code_error(co)
        if ins.offset - new_code.offset != 2:
            raise_code_error(co)
        info.exitindex = new_code.arg
        const_val = int_to_ext_arg_size(info.exitindex)
        ins = self._next_ins(idx, 'PUSH_EXC_INFO')
        if ins is None or new_code.offset - ins.offset != 2 * const_val:
            raise_code_error(co)
        info.footpos = ins.offset
        co_flags = len(co.co_code)
        new_flags = dis.opmap['JUMP_FORWARD']
        value_ins2 = dis.opmap['COPY']
        ref_ins_val = dis.opmap['LOAD_CLOSURE']
        header_ins = dis.opmap['LOAD_FAST']
        while ins and ins.offset > info.headsize:
            ins = self._next_ins(idx, 'LOAD_CONST')
            if ins and ins.arg == new_code.arg:
                n = ins.offset - 2 * const_val + 2
                assert_index = ins.offset + 18
                arg_index = 0
                footer_ins = code[assert_index]
                while footer_ins == OP_EXTENDED_ARG:
                    arg_index += 2
                    footer_ins = code[assert_index + arg_index]
                if footer_ins == dis.opmap['RETURN_CONST']:
                    code[n:n + arg_index + 2] = code[assert_index:assert_index + arg_index + 2]
                    code[n + arg_index] = OP_LOAD_CONST
                    n += arg_index + 2
                elif footer_ins in (ref_ins_val, OP_LOAD_CONST):
                    enter_ins = (ref_ins_val, header_ins, OP_LOAD_CONST)
                    while footer_ins in enter_ins:
                        arg_index += 4 if code[assert_index + arg_index + 2] == value_ins2 else 2
                        while code[assert_index + arg_index] == OP_EXTENDED_ARG:
                            arg_index += 2
                        if code[assert_index + arg_index] != dis.opmap['STORE_NAME']:
                            raise_code_error(co)
                        arg_index += 2
                        if code[assert_index + arg_index] == dis.opmap['RETURN_VALUE']:
                            code[n:n + arg_index] = code[assert_index:assert_index + arg_index]
                            break
                        else:
                            while code[assert_index + arg_index] == OP_EXTENDED_ARG:
                                arg_index += 2
                            if code[assert_index + arg_index] in enter_ins:
                                continue
                            if code[assert_index + arg_index] != dis.opmap['RETURN_CONST']:
                                raise_code_error(co)
                            code[assert_index + arg_index] = OP_LOAD_CONST
                            arg_index += 2
                            code[n:n + arg_index] = code[assert_index:assert_index + arg_index]
                            break
                    n += arg_index
                elif footer_ins not in (dis.opmap['RETURN_VALUE'],):
                    raise_code_error(co)
                enter_index = co_flags - n - 8 >> 1
                write_padded_varint_instruction(code, n, new_flags, enter_index)
        self._patch_store_ins(co, code, offset=1)
        exit_index = [OP_LOAD_CONST, info.exitindex & 255, dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        end_ins2 = info.exitindex >> 8
        while end_ins2:
            exit_index[0:0] = (dis.opmap['EXTENDED_ARG'], end_ins2 & 255)
            end_ins2 >>= 8
        info.footsize = iv - info.footpos + len(exit_index)
        info.co_code = bytes(code) + bytes(exit_index)
        return info

    def _patch_co_code_py312(self, co, no_wrap=False):
        info = CodeObjectPatchInfo()
        code = bytearray(co.co_code)
        iv = len(code)

        def iv_mode(size):
            code[size:size + 2] = (OP_NOP, randint(0, 255))
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        encrypted_code = ins.offset - 6
        info.assertindex = code[3 + encrypted_code]
        if not is_assert_armored_lambda(co.co_consts[info.assertindex]):
            raise_code_error(co)
        ins = self._next_ins(offset, 'POP_TOP')
        if ins.offset != 24 + encrypted_code:
            raise_code_error(co)
        info.enterindex = code[11 + encrypted_code]
        info.argindex = code[15 + encrypted_code]
        info.headsize = ins.offset + 2
        orig_consts = dis.opmap['RESUME']
        if info.headsize > 255:
            code[:12] = (dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.enterindex, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0)
            info.headsize = ins.offset - encrypted_code + 2
            for j in range(12, info.headsize, 2):
                iv_mode(j)
            code[ins.offset - encrypted_code:ins.offset] = co.co_code[:encrypted_code]
            code[ins.offset:ins.offset + 2] = (orig_consts, 0)
            encrypted_code = 0
        else:
            if code[encrypted_code] == orig_consts:
                iv_mode(encrypted_code)
            else:
                const_list = [j for j in range(0, 1 + encrypted_code, 2) if code[j] == orig_consts]
                if len(const_list) != 1:
                    raise_code_error(co)
                code[const_list[0]] = OP_NOP
            iv_mode(2 + encrypted_code)
            code[4 + encrypted_code:18 + encrypted_code] = (dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.enterindex, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0)
            for j in range(18 + encrypted_code, ins.offset + 2, 2):
                iv_mode(j)
        if no_wrap:
            self._patch_store_ins(co, code, offset=1)
            info.footsize = 0
            info.co_code = bytes(code)
            return info
        offset = dis.get_instructions(co)
        idx = iter(reversed(list(offset)))
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        if ins is None:
            raise_code_error(co)
        code[ins.offset] = OP_NOP
        new_code = self._next_ins(idx, 'LOAD_CONST')
        if not is_assert_armored_lambda(new_code.argval):
            raise_code_error(co)
        if ins.offset - new_code.offset != 2:
            raise_code_error(co)
        info.exitindex = new_code.arg
        const_val = int_to_ext_arg_size(info.exitindex)
        ins = self._next_ins(idx, 'PUSH_EXC_INFO')
        if ins is None or new_code.offset - ins.offset != 2 + 2 * const_val:
            raise_code_error(co)
        info.footpos = ins.offset
        co_flags = len(co.co_code)
        new_flags = dis.opmap['JUMP_FORWARD']
        value_ins2 = dis.opmap['COPY']
        ref_ins_val = dis.opmap['LOAD_CLOSURE']
        while ins and ins.offset > info.headsize:
            ins = self._next_ins(idx, 'LOAD_CONST')
            if ins and ins.arg == new_code.arg:
                n = ins.offset - 2 * const_val
                assert_index = ins.offset + 16
                arg_index = 0
                footer_ins = code[assert_index]
                while footer_ins == OP_EXTENDED_ARG:
                    arg_index += 2
                    footer_ins = code[assert_index + arg_index]
                if footer_ins == dis.opmap['RETURN_CONST']:
                    code[n:n + arg_index + 2] = code[assert_index:assert_index + arg_index + 2]
                    code[n + arg_index] = OP_LOAD_CONST
                    n += arg_index + 2
                elif footer_ins in (ref_ins_val, OP_LOAD_CONST):
                    enter_ins = (ref_ins_val, OP_LOAD_CONST)
                    while footer_ins in enter_ins:
                        arg_index += 4 if code[assert_index + arg_index + 2] == value_ins2 else 2
                        while code[assert_index + arg_index] == OP_EXTENDED_ARG:
                            arg_index += 2
                        if code[assert_index + arg_index] != dis.opmap['STORE_NAME']:
                            raise_code_error(co)
                        arg_index += 2
                        if code[assert_index + arg_index] == dis.opmap['RETURN_VALUE']:
                            code[n:n + arg_index] = code[assert_index:assert_index + arg_index]
                            break
                        else:
                            while code[assert_index + arg_index] == OP_EXTENDED_ARG:
                                arg_index += 2
                            if code[assert_index + arg_index] in enter_ins:
                                continue
                            if code[assert_index + arg_index] != dis.opmap['RETURN_CONST']:
                                raise_code_error(co)
                            code[assert_index + arg_index] = OP_LOAD_CONST
                            arg_index += 2
                            code[n:n + arg_index] = code[assert_index:assert_index + arg_index]
                            break
                    n += arg_index
                elif footer_ins not in (dis.opmap['RETURN_VALUE'],):
                    raise_code_error(co)
                enter_index = co_flags - n - 8 >> 1
                write_padded_varint_instruction(code, n, new_flags, enter_index)
        self._patch_store_ins(co, code, offset=1)
        exit_index = [dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.exitindex & 255, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        end_ins2 = info.exitindex >> 8
        while end_ins2:
            exit_index[2:2] = (dis.opmap['EXTENDED_ARG'], end_ins2 & 255)
            end_ins2 >>= 8
        info.footsize = iv - info.footpos + len(exit_index)
        info.co_code = bytes(code) + bytes(exit_index)
        return info

    def _patch_co_code_py311(self, co, no_wrap=False):
        info = CodeObjectPatchInfo()
        code = bytearray(co.co_code)
        iv = len(code)

        def iv_mode(size):
            code[size:size + 2] = (OP_NOP, randint(0, 255))
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        encrypted_code = ins.offset - 6
        info.assertindex = code[3 + encrypted_code]
        if not is_assert_armored_lambda(co.co_consts[info.assertindex]):
            raise_code_error(co)
        ins = self._next_ins(offset, 'POP_TOP')
        if ins.offset != 30 + encrypted_code:
            raise_code_error(co)
        info.enterindex = code[11 + encrypted_code]
        info.argindex = code[15 + encrypted_code]
        info.headsize = ins.offset + 2
        orig_consts = dis.opmap['RESUME']
        if info.headsize > 255:
            code[:12] = (dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.enterindex, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0)
            info.headsize = ins.offset - encrypted_code + 2
            for j in range(12, info.headsize, 2):
                iv_mode(j)
            code[ins.offset - encrypted_code:ins.offset] = co.co_code[:encrypted_code]
            code[ins.offset:ins.offset + 2] = (orig_consts, 0)
            encrypted_code = 0
        else:
            if code[encrypted_code] == orig_consts:
                iv_mode(encrypted_code)
            else:
                const_list = [j for j in range(0, 1 + encrypted_code, 2) if code[j] == orig_consts]
                if len(const_list) != 1:
                    raise_code_error(co)
                code[const_list[0]] = OP_NOP
            iv_mode(2 + encrypted_code)
            code[4 + encrypted_code:18 + encrypted_code] = (dis.opmap['PUSH_NULL'], 0, OP_LOAD_CONST, info.enterindex, OP_LOAD_CONST, info.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0)
            for j in range(18 + encrypted_code, ins.offset + 2, 2):
                iv_mode(j)
        if no_wrap:
            self._patch_store_ins(co, code, offset=1)
            info.footsize = 0
            info.co_code = bytes(code)
            return info
        exit_ins = ins.offset > 28 + encrypted_code
        if exit_ins:
            code[18 + encrypted_code:28 + encrypted_code] = (dis.opmap['JUMP_FORWARD'], 4, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0)
        if iv > 200:
            off = iv - 100
            for ins in offset:
                if ins.offset > off:
                    break
        else:
            offset = dis.get_instructions(co)
        idx = iter(reversed(list(offset)))
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        code[ins.offset] = OP_NOP
        new_code = self._next_ins(idx, 'LOAD_CONST')
        if not is_assert_armored_lambda(new_code.argval):
            raise_code_error(co)
        info.exitindex = new_code.arg
        ins = self._next_ins(idx, 'PUSH_EXC_INFO')
        info.footpos = ins.offset
        ins = next(idx)
        if ins.opname not in ('RETURN_VALUE',):
            if self.oi_wrap_mode == 1 or not exit_ins:
                log_special_code(co, ins.opname)
                self._patch_raise_varargs_py311(info, co, code)
                self._patch_store_ins(co, code, offset=1)
                info.footsize = iv - info.footpos
                info.co_code = bytes(code)
                return info
            return self._patch_wrap_co_code_py311(info, co, code, encrypted_code)
        info.endins2 = ins
        ins = next(idx)
        if ins.opname == 'LOAD_CONST':
            info.valueins2 = ins
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        if not ins:
            raise_code_error(co)
        code[ins.offset] = OP_NOP
        ins = self._next_ins(idx, 'LOAD_CONST')
        if ins.arg != info.exitindex:
            raise_code_error(co)
        new_code = ins
        for ins in idx:
            if ins.opname != 'EXTENDED_ARG':
                break
        if ins.opname != 'PUSH_NULL':
            raise_code_error(co)
        info.footpos2 = ins.offset
        co_flags = info.footpos2
        if hasattr(info, 'valueins2'):
            assert_ins = info.valueins2.offset
            arg_ins = 2
            while code[assert_ins - arg_ins] == OP_EXTENDED_ARG:
                arg_ins += 2
            off = info.footpos2
            nop_ins = info.endins2.offset
            code[off + arg_ins:nop_ins] = code[off:nop_ins - arg_ins]
            co_flags += arg_ins
            off = info.footpos2
            nop_ins = info.endins2.offset
            code[off:off + arg_ins] = co.co_code[nop_ins - arg_ins:nop_ins]
        ret_ins = new_code.offset - info.footpos2
        offset = dis.get_instructions(co)
        for ins in offset:
            if ins.offset >= info.headsize:
                break

        def oparg(opcode, arg=None):
            for ins in offset:
                if ins.offset > info.footpos2:
                    return
                if opcode == ins.opname and arg == ins.arg:
                    return ins
        ins = oparg(new_code.opname, arg=new_code.arg)
        while ins:
            n = ins.offset - ret_ins
            ext_arg = oparg('RETURN_VALUE')
            if not ext_arg:
                raise_code_error(co)
            if code[ext_arg.offset - 2] == OP_LOAD_CONST:
                jump_off = ext_arg.offset - 2
                while code[jump_off - 2] == OP_EXTENDED_ARG:
                    jump_off -= 2
                target_off = ext_arg.offset - jump_off
                code[n:n + target_off] = co.co_code[jump_off:jump_off + target_off]
                n += target_off
            assert ext_arg.offset - n > 8
            enter_index = co_flags - n - 8 >> 1
            write_padded_varint_instruction(code, n, dis.opmap['JUMP_FORWARD'], enter_index)
            ins = oparg(new_code.opname, arg=new_code.arg)
        for size in (info.footpos, info.footpos2):
            while code[size] != dis.opmap['PRECALL']:
                size += 2
            code[size:size + 4] = (dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0)
            size += 4
            while code[size] != OP_POP_TOP:
                iv_mode(size)
                size += 2
        self._patch_store_ins(co, code, offset=1)
        info.footsize = iv - info.footpos2
        info.co_code = bytes(code)
        return info

    def _patch_raise_varargs(self, info, co, code):
        offset = dis.get_instructions(co)
        abs_off = info.exitindex
        rel_off = getattr(info, 'footpos2', getattr(info, 'footpos'))

        def oparg():
            for ins in offset:
                if ins.offset >= rel_off:
                    return
                if 'LOAD_CONST' == ins.opname and abs_off == ins.arg:
                    return ins
        ins = oparg()
        while ins:
            code[ins.offset] = OP_NOP
            for ins in offset:
                code[ins.offset] = OP_NOP
                if ins.opname == 'POP_TOP':
                    break
            ins = oparg()

    def _patch_raise_varargs_py311(self, info, co, code):
        offset = dis.get_instructions(co)
        abs_off = info.exitindex

        def oparg():
            for ins in offset:
                if ins.offset >= info.footpos:
                    return
                if 'LOAD_CONST' == ins.opname and abs_off == ins.arg:
                    return ins
        ins = oparg()
        while ins:
            n = ins.offset - 2
            for ins in offset:
                if ins.opname == 'POP_TOP':
                    for j in range(n, ins.offset + 1, 2):
                        code[j] = OP_NOP
                    break
            ins = oparg()

    def _patch_assert_mode(self, co):
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        co_consts = self.ctx.python_version[1]
        code = bytearray(co.co_code)
        if co_consts > 10:
            new_name = code[ins.offset - 3]
            self._patch_store_ins(co, code, offset=1)
            code[ins.offset - 4:ins.offset + 2] = (OP_NOP, 0) * 3
        else:
            new_name = code[ins.offset - 5]
            self._patch_store_ins(co, code)
            code[ins.offset - 6:ins.offset + 2] = (OP_NOP, 0) * 4
        self.impt['fix_co_object'](co, b'co_code', code)
        footer_size = [1 << self.impt['CO_MARSHAL_ARMOR_FUNC_OFF'], 0, 0, 0]
        footer_size.extend(encode_type_value(1, new_name))
        footer_size.insert(0, len(footer_size))
        header_size = list(co.co_consts)
        header_size[new_name] = generate_unique_name('assert')
        header_size.append(bytes(footer_size))
        self.impt['fix_co_object'](co, b'co_consts', tuple(header_size))
        footer_pos = co.co_flags | self.impt['CO_FLAG_PYTRANSFORM3']
        self.impt['fix_co_object'](co, b'co_flags', footer_pos)

    def _patch_wrap_co_code_py38(self, info, co, code, padded_size):
        offset = dis.get_instructions(co)
        new_code = self._next_ins(offset, 'SETUP_FINALLY')
        info.footpos = new_code.offset + 2 + new_code.arg
        code[12 + padded_size:14 + padded_size] = code[8 + padded_size:10 + padded_size]
        enter_index = info.footpos - padded_size - 10
        code[padded_size:padded_size + 2] = (dis.opmap['JUMP_FORWARD'], 10)
        write_padded_varint_instruction(code, 2 + padded_size, dis.opmap['CALL_FINALLY'], enter_index)
        code[padded_size + 10:padded_size + 12] = (OP_RETURN_VALUE, 0)
        orig_size = (dis.opmap['JUMP_ABSOLUTE'], padded_size + 2)
        while True:
            ins = self._next_ins(offset, 'CALL_FINALLY')
            if not ins:
                break
            if ins.arg + ins.offset == new_code.arg + new_code.offset:
                off = ins.offset
                code[off] = OP_NOP
                off -= 2
                while code[off] == OP_EXTENDED_ARG:
                    code[off] = OP_NOP
                    off -= 2
                ins = self._next_ins(offset, 'RETURN_VALUE')
                if not ins:
                    raise_code_error(ins)
                off = ins.offset
                code[off:off + 2] = orig_size
        offset = dis.get_instructions(co)
        size = info.footpos
        for ins in offset:
            if ins.offset == size:
                break
        if ins.opcode not in (OP_LOAD_CONST, OP_EXTENDED_ARG):
            raise_code_error(co)
        if ins.opcode == OP_EXTENDED_ARG:
            ins = self._next_ins(offset, 'LOAD_CONST')
            if not (ins and is_assert_armored_lambda(ins.argval)):
                raise_code_error(co)
        info.exitindex = ins.arg
        for ins in offset:
            code[ins.offset] = OP_NOP
            if ins.opname == 'MAKE_FUNCTION':
                break
        self._patch_store_ins(co, code)
        info.footsize = len(code) - info.footpos
        info.co_code = bytes(code)
        return info

    def _patch_wrap_co_code_py310(self, info, co, code, padded_size):
        offset = dis.get_instructions(co)
        new_code = self._next_ins(offset, 'SETUP_FINALLY')
        info.footpos = new_code.offset + 2 + new_code.arg * 2
        code[padded_size:padded_size + 8] = (dis.opmap['JUMP_FORWARD'], 3, dis.opmap['CALL_FUNCTION'], 1, OP_POP_TOP, randint(0, 255), OP_RETURN_VALUE, 0)
        orig_size = (dis.opmap['JUMP_ABSOLUTE'], padded_size + 2 >> 1)
        nops = 0 if info.exitindex < 255 else 2 if info.exitindex < 65535 else 4 if info.exitindex < 16777215 else 6
        for ins in offset:
            if ins.offset >= info.footpos:
                break
            if ins.opcode == OP_LOAD_CONST and ins.arg == info.exitindex:
                total_nops = self._next_ins(offset, 'POP_TOP')
                wrap_code = self._next_ins(offset, 'RETURN_VALUE')
                if not (total_nops and wrap_code and (wrap_code.offset - total_nops.offset < 8)):
                    raise_code_error(co)
                n = ins.offset - nops
                arg_ins = wrap_code.offset - total_nops.offset - 2
                if arg_ins:
                    wrap_size = total_nops.offset + 2
                    code[n:n + arg_ins] = code[wrap_size:wrap_size + arg_ins]
                k = n + arg_ins
                code[k:k + nops + 2] = co.co_code[n:n + nops + 2]
                k += nops + 2
                code[k:k + 2] = co.co_code[ins.offset + 6:ins.offset + 8]
                code[k + 2:k + 4] = orig_size
        self._patch_store_ins(co, code)
        info.footsize = len(code) - info.footpos
        info.co_code = bytes(code)
        return info

    def _patch_wrap_co_code_py311(self, info, co, code, padded_size):
        offset = dis.get_instructions(co)
        inner_co = padded_size + 20
        orig_size = dis.opmap['JUMP_BACKWARD']
        nops = 0 if info.exitindex < 255 else 2 if info.exitindex < 65535 else 4 if info.exitindex < 16777215 else 6
        n = -1
        for ins in offset:
            if ins.offset >= info.footpos:
                break
            if ins.opname == 'PUSH_NULL':
                n = ins.offset
            elif ins.opcode == OP_LOAD_CONST and ins.arg == info.exitindex:
                nops = ins.offset - n
                if n == -1 or nops > 8:
                    raise_code_error(co)
                total_nops = self._next_ins(offset, 'POP_TOP')
                wrap_code = self._next_ins(offset, 'RETURN_VALUE')
                if not (total_nops and wrap_code and (wrap_code.offset - total_nops.offset < 8)):
                    raise_code_error(co)
                arg_ins = wrap_code.offset - total_nops.offset - 2
                if arg_ins:
                    wrap_size = total_nops.offset + 2
                    code[n:n + arg_ins] = code[wrap_size:wrap_size + arg_ins]
                k = n + arg_ins
                code[k:k + nops + 2] = co.co_code[n:n + nops + 2]
                k += nops + 2
                code[k:k + 2] = co.co_code[ins.offset + 4:ins.offset + 6]
                k += 2
                write_padded_varint_instruction(code, k, orig_size, k + 8 - inner_co >> 1)
                k += 8
                while k < total_nops.offset:
                    code[k] = OP_NOP
                    k += 2
        self._patch_store_ins(co, code, offset=1)
        info.footsize = len(code) - info.footpos
        info.co_code = bytes(code)
        return info

    def _patch_co_object(self, co, no_wrap=False):
        co_consts = self.ctx.python_version[1]
        if co_consts == 11:
            return self._patch_co_code_py311(co, no_wrap)
        elif co_consts == 12:
            return self._patch_co_code_py312(co, no_wrap)
        elif co_consts == 13:
            return self._patch_co_code_py313(co, no_wrap)
        elif co_consts >= 14:
            return self._patch_co_code_py31X(co, no_wrap)
        info = CodeObjectPatchInfo()
        code = bytearray(co.co_code)
        iv = len(code)
        offset = dis.get_instructions(co)
        for ins in offset:
            if self._is_patched_ins(ins):
                break
        else:
            return
        padded_size = ins.offset - 6
        info.assertindex = code[1 + padded_size]
        if not is_assert_armored_lambda(co.co_consts[info.assertindex]):
            raise_code_error(co)
        ins = self._next_ins(offset, 'POP_TOP')
        if ins.offset != 18 + padded_size:
            raise_code_error(co)
        info.enterindex = code[9 + padded_size]
        info.argindex = code[15 + padded_size]
        info.headsize = ins.offset + 2
        for j in (0, 2, 4, 6, 10, 12):
            code[j + padded_size] = OP_NOP
            code[j + 1 + padded_size] = randint(0, 255)
        if no_wrap:
            self._patch_store_ins(co, code)
            info.footsize = 0
            info.co_code = bytes(code)
            return info
        if co_consts == 8:
            return self._patch_wrap_co_code_py38(info, co, code, padded_size)
        if iv > 200:
            off = iv - 100
            for ins in offset:
                if ins.offset > off:
                    break
        else:
            offset = dis.get_instructions(co)
        idx = iter(reversed(list(offset)))
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        code[ins.offset] = OP_NOP
        ins = self._next_ins(idx, 'LOAD_CONST')
        code[ins.offset] = OP_NOP
        for ins in idx:
            if ins.opname == 'EXTENDED_ARG':
                code[ins.offset] = OP_NOP
                continue
            break
        if not is_assert_armored_lambda(ins.argval):
            raise_code_error(co)
        info.exitindex = ins.arg
        for ins in idx:
            if ins.opname != 'EXTENDED_ARG':
                break
        info.footpos = ins.offset - 2
        if co_consts < 9:
            self._patch_store_ins(co, code)
            if co_consts == 8:
                j = info.footpos
                inner_consts = dis.opmap['CALL_FUNCTION']
                while j < iv:
                    if code[j] == inner_consts:
                        code[j] = OP_POP_TOP
                        break
                    j += 2
            info.footsize = iv - info.footpos
            info.co_code = bytes(code)
            return info
        if ins.opname not in ('RETURN_VALUE', 'JUMP_FORWARD'):
            if self.oi_wrap_mode == 1:
                log_special_code(co, ins.opname)
                self._patch_raise_varargs(info, co, code)
                self._patch_store_ins(co, code)
                info.footsize = iv - info.footpos
                info.co_code = bytes(code)
                return info
            return self._patch_wrap_co_code_py310(info, co, code, padded_size)
        info.endins2 = ins
        ins = next(idx)
        if ins.opname == 'LOAD_CONST':
            info.valueins2 = ins
        ins = self._next_ins(idx, 'MAKE_FUNCTION')
        code[ins.offset] = OP_NOP
        ins = self._next_ins(idx, 'LOAD_CONST')
        code[ins.offset] = OP_NOP
        for ins in idx:
            if ins.opname == 'EXTENDED_ARG':
                code[ins.offset] = OP_NOP
                continue
            break
        if not is_assert_armored_lambda(ins.argval) or ins.arg != info.exitindex:
            raise_code_error(co)
        new_code = ins
        for ins in idx:
            if ins.opname != 'EXTENDED_ARG':
                break
        info.footpos2 = ins.offset + 2
        co_flags = info.footpos2
        if hasattr(info, 'valueins2'):
            assert_ins = info.valueins2.offset
            arg_ins = 2
            while code[assert_ins - arg_ins] == OP_EXTENDED_ARG:
                arg_ins += 2
            off = info.footpos2
            nop_ins = info.endins2.offset
            code[off + arg_ins:nop_ins] = code[off:nop_ins - arg_ins]
            co_flags += arg_ins
            off = info.footpos2
            nop_ins = info.endins2.offset
            code[off:off + arg_ins] = co.co_code[nop_ins - arg_ins:nop_ins]
        elif info.endins2.opname == 'JUMP_FORWARD':

            def inner_code():
                self._patch_raise_varargs(info, co, code)
                self._patch_store_ins(co, code)
                info.footsize = iv - info.footpos2
                info.co_code = bytes(code)
                return info
            if self.oi_wrap_mode == 1:
                return inner_code()
            off = info.endins2.offset
            assert_ins = off + 2 + info.endins2.arg
            arg_ins = 0
            while code[assert_ins + arg_ins] == OP_EXTENDED_ARG:
                arg_ins += 2
            if code[assert_ins + arg_ins] not in (OP_LOAD_CONST,):
                return inner_code()
            arg_ins += 2
            if code[assert_ins + arg_ins] not in (OP_RETURN_VALUE,):
                return inner_code()
            n = co_flags
            co_flags += arg_ins
            code[assert_ins:assert_ins + arg_ins] = code[off - arg_ins:off]
            code[n + arg_ins:off] = code[n:off - arg_ins]
            code[n:n + arg_ins] = co.co_code[assert_ins:assert_ins + arg_ins]
        ret_ins = new_code.offset - info.footpos2
        offset = dis.get_instructions(co)
        for ins in offset:
            if ins.offset >= info.headsize:
                break

        def oparg(opcode, arg=None):
            for ins in offset:
                if ins.offset >= info.footpos2:
                    return
                if opcode == ins.opname and arg == ins.arg:
                    return ins
        ins = oparg(new_code.opname, arg=new_code.arg)
        while ins:
            n = ins.offset - ret_ins
            ext_arg = oparg('RETURN_VALUE')
            if not ext_arg:
                raise_code_error(co)
            if code[ext_arg.offset - 2] == OP_LOAD_CONST:
                jump_off = ext_arg.offset - 2
                while code[jump_off - 2] == OP_EXTENDED_ARG:
                    jump_off -= 2
                target_off = ext_arg.offset - jump_off
                code[n:n + target_off] = code[jump_off:jump_off + target_off]
                n += target_off
            assert ext_arg.offset - n > 8
            enter_index = co_flags - n - 8
            if co_consts > 9:
                enter_index >>= 1
            write_padded_varint_instruction(code, n, dis.opmap['JUMP_FORWARD'], enter_index)
            ins = oparg(new_code.opname, arg=new_code.arg)
        self._patch_store_ins(co, code)
        info.footsize = iv - info.footpos2
        info.co_code = bytes(code)
        return info

    def _patch_store_ins(self, co, code, offset=3):
        offset = dis.get_instructions(co)
        ins = self._next_ins(offset, 'MAKE_FUNCTION')
        if not ins:
            return
        inner_size = co.co_code[ins.offset - offset]
        ins = next(offset)
        if ins.opname == 'STORE_FAST':
            opcode = dis.opmap['LOAD_FAST']
        elif ins.opname == 'STORE_NAME':
            opcode = dis.opmap['LOAD_NAME']
        else:
            return
        value = ins.arg
        for ins in offset:
            if ins.opcode == opcode and ins.arg == value:
                code[ins.offset] = OP_LOAD_CONST
                code[ins.offset + 1] = inner_size

    def _patch_co_consts(self, co, info, no_wrap=False):
        header_size = list(co.co_consts)
        outer_size = 0 if no_wrap else 1
        header_size[info.assertindex] = generate_unique_name('assert')
        header_size[info.enterindex] = generate_unique_name('enter')
        if outer_size:
            header_size[info.exitindex] = generate_unique_name('exit')
        adjust = len(info.co_code) - info.footsize - info.headsize
        jump_ins = getattr(info, 'ivmode', 1)
        jump_arg = getattr(info, 'ivpos', 0)
        label_off = 1 if getattr(info, 'jit_iv', 0) else 0
        except_off = pack('8x') if label_off else b''
        except_ins = 1 if self.ob_mix_argnames else 0
        handler_off = 1 if self.ob_clear_frame_locals else 0
        except_table = pack('QBBBBII', 0, outer_size | jump_ins << 1 | label_off << 2 | handler_off << 4, jump_arg, 0, info.headsize, adjust, 0)
        header_size[info.argindex] = except_table + except_off
        footer_size = [2 + outer_size << self.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << self.impt['CO_MARSHAL_FIX_CO_JIT_OFF'] | except_ins << self.impt['CO_MARSHAL_MIX_ARGNAMES_OFF'], 0, 0, 0]
        footer_size.extend(encode_type_value(1, info.assertindex))
        footer_size.extend(encode_type_value(2, info.enterindex))
        if outer_size:
            footer_size.extend(encode_type_value(3, info.exitindex))
        footer_size.extend(encode_type_value(label_off, info.argindex))
        footer_size.insert(0, len(footer_size))
        header_size.append(bytes(footer_size))
        self.impt['fix_co_object'](co, b'co_consts', tuple(header_size))

    def _check_co_info(self, co, info):
        if co.co_flags & self.impt['CO_FLAG_PYTRANSFORM3']:
            raise_code_error(co, 'CO_PYTRANSFORM3 conflicts')
        if info.headsize > 255 or info.headsize < 12:
            raise_code_error(co, 'invalid co header size')
        new_except = getattr(info, 'footsize', 0)
        if new_except and (new_except > 65525 or new_except < 12):
            raise_code_error(co, 'invalid co footer size')
        name_list = (info.assertindex, info.enterindex, info.argindex)
        if any([i > 255 for i in name_list]):
            raise_code_error(co, 'big co argindex')
        if getattr(info, 'exitindex', -1) in name_list or len(set(name_list)) != 3:
            raise_code_error(co, 'co_info inner error')

    def _set_co_iv(self, co, info, no_wrap=False):
        entry = IV_SIZE
        m = 1 if no_wrap else randint(0, 1)
        size = len(info.co_code) - info.footsize
        info.iv = info.co_code[:entry] if m else info.co_code[size:size + entry]
        info.ivmode = m
        if self.ob_enable_jit:
            info.jit_iv = self.jit_iv
            info.iv = bytes([flag ^ start_off for (flag, start_off) in zip(info.iv, info.jit_iv)])

    def patch_co_object(self, co, no_wrap=False):
        if self._only_assert_mode:
            self._patch_assert_mode(co)
            return
        info = self._patch_co_object(co, no_wrap)
        if info:
            self._check_co_info(co, info)
            self._set_co_iv(co, info, no_wrap=no_wrap)
            self._patch_co_consts(co, info, no_wrap)
            code = info.co_code
            self.impt['generate_co_code'](self.impt['self'], self.ctx, co, code, len(code), info.headsize | info.footsize << 16, info.iv)
            footer_pos = co.co_flags | self.impt['CO_FLAG_PYTRANSFORM3']
            self.impt['fix_co_object'](co, b'co_flags', footer_pos)
        else:
            for ins in dis.get_instructions(co):
                if self._is_patched_ins(ins):
                    raise_code_error(co)
                if ins.opname == 'LOAD_NAME' and ins.argval == '__assert_armored__':
                    raise_code_error(co)
        return info

    @resoptions
    def handle(self, script):
        logger.debug('patch co')
        self._only_assert_mode = not self.oi_obf_code and any([self.ob_enable_rft, self.ob_assert_call, self.ob_assert_import, self.ob_mix_str])
        if self.ob_enable_jit:
            self.jit_iv = JitIVBuilder_Threshold(self.ctx).handle(script)
        end_off = self.ctx.exclude_co_names

        def handler(co):
            return not any([co.co_flags & self.impt['CO_FLAG_PYTRANSFORM3'], co.co_name in end_off, is_assert_armored_lambda(co)])

        def entries(co):
            if handler(co) and self.patch_co_object(co, entry_size):
                self.trace(script, co)
            for i in co.co_consts:
                if isinstance(i, type(co)):
                    entries(i)
            if self.ob_mix_coname:
                self.impt['fix_co_object'](co, b'co_name', '')
        entry_size = not self.ob_wrap_mode
        entries(script.mco)

# =============================================================================
# JIT IV Builder (8-bit) - Generates 8-bit VM programs for IV computation
# =============================================================================
class JitIVBuilder_8bit(object):

    def __init__(self, ctx, shared_state):
        self.ctx = ctx
        self.imptbl = shared_state

    def _rand_iv(self, n=IV_SIZE):
        return [randint(1, 255) for i in range(n)]

    def _build_iv_jit(self, target_iv):
        vm_code = 1
        reg_a = 2
        reg_b = 3
        reg_c = 4
        reg_d = 5
        reg_e = 6
        reg_f = 7
        op1 = 8
        op2 = 9
        op3 = 10
        target_byte = 11
        (mask, xored, shifted, added, sub_val, cmp_val, i, jmp_off) = range(8)

        def init_val(value):
            bytecode = []
            vm_ops = randchoice(final_val)
            if jit_data[vm_ops] in (None, 'FP'):
                jit_data[vm_ops] = randint(2, 126)
                bytecode.extend([reg_f, vm_ops << 4 | 9, jit_data[vm_ops] & 255])
            for size in range(randint(1, 3)):
                jit_size = randchoice(final_val)
                opcode = randchoice([reg_a, reg_b, reg_e])
                reg_idx = randint(2, 126)
                if vm_ops == jit_size:
                    bytecode.extend([opcode, vm_ops << 4 | 9, reg_idx])
                else:
                    jit_data[jit_size] = reg_idx
                    bytecode.extend([reg_f, jit_size << 4 | 9, reg_idx])
                    bytecode.extend([opcode, vm_ops << 4 | jit_size])
                if opcode == reg_a:
                    jit_data[vm_ops] += reg_idx
                elif opcode == reg_b:
                    jit_data[vm_ops] -= reg_idx
                elif opcode == reg_e:
                    jit_data[vm_ops] ^= reg_idx
                jit_data[vm_ops] &= 255
            if jit_data[vm_ops] > value:
                bytecode.extend([reg_b, vm_ops << 4 | 9, jit_data[vm_ops] - value])
            elif jit_data[vm_ops] < value:
                bytecode.extend([reg_a, vm_ops << 4 | 9, value - jit_data[vm_ops]])
            jit_data[vm_ops] = value
            if not store_reg == vm_ops:
                bytecode.extend([reg_f, store_reg << 4 | vm_ops])
                jit_data[store_reg] = value
            return bytecode

        def load_reg(idx):
            bytecode = []
            vm_ops = arith_op
            while vm_ops == store_reg:
                vm_ops = randchoice(final_val)
            bytecode.extend([op3, vm_ops << 3 | jmp_off, 0])
            bytecode.extend([reg_a, vm_ops << 4 | 9, IV_SIZE])
            if idx:
                bytecode.extend([target_byte, 1 << 6 | vm_ops << 3 | store_reg, idx])
            else:
                bytecode.extend([op2, 1 << 6 | vm_ops << 3 | store_reg])
            jit_data[vm_ops] = 'FP'
            return bytecode
        arith_reg = 6
        final_val = tuple(range(arith_reg))
        store_reg = None
        arith_op = randchoice(final_val)
        jit_data = [None] * arith_reg
        arith_val = []
        result = []
        size = len(target_iv)
        while len(arith_val) < size:
            cmp_reg = randint(0, size - 1)
            if cmp_reg not in arith_val:
                arith_val.append(cmp_reg)
        for idx in arith_val:
            value = target_iv[idx]
            store_reg = randchoice(final_val)
            result.extend(init_val(value) + load_reg(idx))
        result.append(vm_code)
        return bytes(result)

    def _build_jit_data(self, jit_blocks):
        data = self.imptbl['generate_module_data'](self.imptbl['self'], self.ctx, jit_blocks, -1)
        if data is None:
            data = b''.join([self._build_iv_jit(target_iv) for target_iv in jit_blocks])
        n = pack('IIII', len(data) + 16, 0, 16, 0)
        return n + data

    def _list_co(self, co):
        result = [co]
        for i in co.co_consts:
            if type(i) == type(co) and (not is_assert_armored_lambda(i)):
                result.extend(self._list_co(i))
        return result

    def handle(self, script):
        co_list = self._list_co(script.mco)
        jit_blocks = [self._rand_iv() for i in co_list]
        script.jit_iv = (co_list, jit_blocks)
        script.jit_data = self._build_jit_data(jit_blocks)

# =============================================================================
# JIT IV Builder (32-bit) - Generates 32-bit VM programs for IV computation
# =============================================================================
class JitIVBuilder_32bit(object):

    def __init__(self, ctx, shared_state):
        self.ctx = ctx
        self.imptbl = shared_state

    def _rand_iv(self, n=IV_SIZE):
        return [randint(1, 255) for i in range(n)]

    def _build_iv_jit(self, target_iv):
        vm_code = 1
        reg_a = 2
        reg_b = 3
        reg_c = 4
        reg_d = 5
        reg_e = 6
        reg_f = 7
        op1 = 8
        op2 = 9
        op3 = 10
        target_byte = 11
        (mask, xored, shifted, added, sub_val, cmp_val, i, jmp_off) = range(8)

        def word_size():
            return randint(1, 4294967295)

        def half_word(i):
            return [i & 255, i >> 8 & 255, i >> 16 & 255, i >> 24 & 255]

        def init_val(value):
            bytecode = []
            vm_ops = randchoice(final_val)
            if jit_data[vm_ops] in (None, 'FP'):
                jit_data[vm_ops] = word_size()
                bytecode.extend([reg_f, vm_ops << 4 | 8] + half_word(jit_data[vm_ops]))
            for size in range(randint(1, 3)):
                jit_size = randchoice(final_val)
                opcode = randchoice([reg_a, reg_b, reg_e])
                reg_idx = word_size()
                if vm_ops == jit_size:
                    bytecode.extend([opcode, vm_ops << 4 | 8] + half_word(reg_idx))
                else:
                    jit_data[jit_size] = reg_idx
                    bytecode.extend([reg_f, jit_size << 4 | 8] + half_word(reg_idx))
                    bytecode.extend([opcode, vm_ops << 4 | jit_size])
                if opcode == reg_a:
                    jit_data[vm_ops] += reg_idx
                elif opcode == reg_b:
                    jit_data[vm_ops] -= reg_idx
                elif opcode == reg_e:
                    jit_data[vm_ops] ^= reg_idx
                jit_data[vm_ops] &= 4294967295
            if jit_data[vm_ops] > value:
                reg_idx = half_word(jit_data[vm_ops] - value)
                bytecode.extend([reg_b, vm_ops << 4 | 8] + reg_idx)
            elif jit_data[vm_ops] < value:
                reg_idx = half_word(value - jit_data[vm_ops])
                bytecode.extend([reg_a, vm_ops << 4 | 8] + reg_idx)
            jit_data[vm_ops] = value
            if not store_reg == vm_ops:
                bytecode.extend([reg_f, store_reg << 4 | vm_ops])
                jit_data[store_reg] = value
            return bytecode

        def load_reg(idx):
            bytecode = []
            vm_ops = arith_op
            while vm_ops == store_reg:
                vm_ops = randchoice(final_val)
            bytecode.extend([op3, vm_ops << 3 | jmp_off, 0])
            bytecode.extend([reg_a, vm_ops << 4 | 9, IV_SIZE])
            if idx:
                bytecode.extend([target_byte, 2 << 6 | vm_ops << 3 | store_reg, idx * 4])
            else:
                bytecode.extend([op2, 2 << 6 | vm_ops << 3 | store_reg])
            jit_data[vm_ops] = 'FP'
            return bytecode
        arith_reg = 6
        final_val = tuple(range(arith_reg))
        store_reg = None
        arith_op = randchoice(final_val)
        jit_data = [None] * arith_reg
        arith_val = []
        result = []
        target_iv = unpack('III', bytes(target_iv))
        size = len(target_iv)
        while len(arith_val) < size:
            cmp_reg = randint(0, size - 1)
            if cmp_reg not in arith_val:
                arith_val.append(cmp_reg)
        for idx in arith_val:
            value = target_iv[idx]
            store_reg = randchoice(final_val)
            result.extend(init_val(value) + load_reg(idx))
        result.append(vm_code)
        return bytes(result)

    def _build_jit_data(self, jit_blocks):
        data = self.imptbl['generate_module_data'](self.imptbl['self'], self.ctx, jit_blocks, -1)
        if data is None:
            data = b''.join([self._build_iv_jit(target_iv) for target_iv in jit_blocks])
        n = pack('IIII', len(data) + 16, 0, 16, 0)
        return n + data

    def _list_co(self, co):
        result = [co]
        for i in co.co_consts:
            if type(i) == type(co) and (not is_assert_armored_lambda(i)):
                result.extend(self._list_co(i))
        return result

    def handle(self, script):
        co_list = self._list_co(script.mco)
        jit_blocks = [self._rand_iv() for i in co_list]
        script.jit_iv = (co_list, jit_blocks)
        script.jit_data = self._build_jit_data(jit_blocks)

# =============================================================================
# JIT IV Builder (Threshold) - Configurable JIT IV generation
# =============================================================================
class JitIVBuilder_Threshold(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def _rand_iv(self, n=IV_SIZE):
        return [randint(1, 255) for i in range(n)]

    def _build_iv_jit(self, target_iv):
        vm_code = 1
        reg_a = 2
        reg_b = 3
        reg_c = 4
        reg_d = 5
        reg_e = 6
        reg_f = 7
        op1 = 8
        op2 = 9
        op3 = 10
        target_byte = 11
        (mask, xored, shifted, added, sub_val, cmp_val, i, jmp_off) = range(8)
        threshold = self.ctx.jit_iv_threshold

        def word_size():
            return randint(1, 2147483647)

        def half_word(i):
            return [i & 255, i >> 8 & 255, i >> 16 & 255, i >> 24 & 255]

        def init_val(value):
            bytecode = []
            vm_ops = randchoice(final_val)
            if jit_data[vm_ops] in (None, 'FP'):
                jit_data[vm_ops] = word_size()
                bytecode.extend([reg_f, vm_ops << 4 | 8] + half_word(jit_data[vm_ops]))
            for size in range(randint(threshold, threshold + 8)):
                chosen_op = randchoice(final_val)
                opcode = randchoice([reg_a, reg_b, reg_e])
                reg_idx = word_size()
                if vm_ops == chosen_op:
                    bytecode.extend([opcode, vm_ops << 4 | 8] + half_word(reg_idx))
                else:
                    jit_data[chosen_op] = reg_idx
                    bytecode.extend([reg_f, chosen_op << 4 | 8] + half_word(reg_idx))
                    bytecode.extend([opcode, vm_ops << 4 | chosen_op])
                if opcode == reg_a:
                    jit_data[vm_ops] += reg_idx
                elif opcode == reg_b:
                    jit_data[vm_ops] -= reg_idx
                elif opcode == reg_e:
                    jit_data[vm_ops] ^= reg_idx
                jit_data[vm_ops] &= 4294967295
            if jit_data[vm_ops] > value:
                reg_idx = half_word(jit_data[vm_ops] - value)
                bytecode.extend([reg_b, vm_ops << 4 | 8] + reg_idx)
            elif jit_data[vm_ops] < value:
                reg_idx = half_word(value - jit_data[vm_ops])
                bytecode.extend([reg_a, vm_ops << 4 | 8] + reg_idx)
            jit_data[vm_ops] = value
            if not store_reg == vm_ops:
                bytecode.extend([reg_f, store_reg << 4 | vm_ops])
                jit_data[store_reg] = value
            return bytecode

        def load_reg(idx):
            bytecode = []
            vm_ops = arith_op
            while vm_ops == store_reg:
                vm_ops = randchoice(final_val)
            bytecode.extend([op3, vm_ops << 3 | jmp_off, 0])
            bytecode.extend([reg_a, vm_ops << 4 | 9, IV_SIZE])
            if idx:
                bytecode.extend([target_byte, 2 << 6 | vm_ops << 3 | store_reg, idx * 4])
            else:
                bytecode.extend([op2, 2 << 6 | vm_ops << 3 | store_reg])
            jit_data[vm_ops] = 'FP'
            return bytecode
        arith_reg = 6
        final_val = tuple(range(arith_reg))
        store_reg = None
        arith_op = randchoice(final_val)
        jit_data = [None] * arith_reg
        arith_val = []
        result = []
        target_iv = unpack('III', bytes(target_iv))
        size = len(target_iv)
        while len(arith_val) < size:
            cmp_reg = randint(0, size - 1)
            if cmp_reg not in arith_val:
                arith_val.append(cmp_reg)
        for idx in arith_val:
            value = target_iv[idx]
            store_reg = randchoice(final_val)
            result.extend(init_val(value) + load_reg(idx))
        result.append(vm_code)
        return bytes(result)

    def _build_jit_data(self, target_iv):
        data = self._build_iv_jit(target_iv)
        n = pack('IIII', len(data) + 16, 0, 16, 0)
        return n + data

    def _count_co(self, co):
        size = 1
        for i in co.co_consts:
            if type(i) == type(co) and (not is_assert_armored_lambda(i)):
                size += self._count_co(i)
        return size

    def handle(self, script):
        target_iv = self._rand_iv()
        script.jit_data = self._build_jit_data(target_iv)
        return target_iv

# =============================================================================
# Lambda Armor Patcher - Patches RFT lambda code objects
# =============================================================================
class LambdaArmorPatcher(BaseCodePatcher):

    def __init__(self, ctx, shared_state):
        self.ctx = ctx
        self.impt = shared_state

    def _patch_co_object(self, co):
        code = bytearray(co.co_code)
        iv = len(code)
        co_consts = self.ctx.python_version[1]
        enter_index = iv + 6 if co_consts < 10 else iv + 6 >> 1
        lambda_co = write_varint_instruction(code, 0, dis.opmap['JUMP_FORWARD'], enter_index)
        lambda_consts = bytearray(lambda_co + 40)
        lambda_consts[:8] = [OP_NOP] * 8
        lambda_consts[:lambda_co] = co.co_code[:lambda_co]
        offset = 8
        label = dis.opmap['PUSH_NULL'] if co_consts > 10 else OP_NOP
        lambda_consts[offset:offset + 2] = (label, randint(0, 255))
        offset += 2
        lambda_code = len(co.co_consts)
        offset = write_varint_instruction(lambda_consts, offset, OP_LOAD_CONST, lambda_code)
        offset = write_varint_instruction(lambda_consts, offset, OP_LOAD_CONST, lambda_code + 1)
        lambda_consts[offset:offset + 6] = (dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], randint(0, 255))
        offset += 6
        if co_consts > 10:
            opcode = dis.opmap['JUMP_BACKWARD']
            enter_index = offset + 8 >> 1
            offset = write_padded_varint_instruction(lambda_consts, offset, opcode, enter_index)
        else:
            offset = write_varint_instruction(lambda_consts, offset, dis.opmap['JUMP_ABSOLUTE'], 0)
        code += lambda_consts[:offset]
        new_lambda = bytes(code)
        new_except = offset - lambda_co
        lambda_size = 8 - lambda_co
        iv_data = bytes(lambda_consts[8:20])
        self.impt['generate_co_code'](self.impt['self'], self.ctx, co, new_lambda, len(code), lambda_co | new_except << 16, iv_data)
        self.impt['fix_co_object'](co, b'co_code', new_lambda)
        header_size = list(co.co_consts)
        header_size.append(generate_unique_name('lambda'))
        except_table = pack('QBBBBII', 0, 8, lambda_size, 0, lambda_co, iv, 0)
        header_size.append(except_table)
        footer_size = [1 << self.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << self.impt['CO_MARSHAL_FIX_CO_JIT_OFF'], 0, 0, 0]
        footer_size.extend(encode_type_value(2, lambda_code))
        footer_size.extend(encode_type_value(0, lambda_code + 1))
        footer_size.insert(0, len(footer_size))
        header_size.append(bytes(footer_size))
        self.impt['fix_co_object'](co, b'co_consts', tuple(header_size))
        footer_pos = co.co_flags | self.impt['CO_FLAG_PYTRANSFORM3']
        self.impt['fix_co_object'](co, b'co_flags', footer_pos)

    def handle_mco(self, module_co, mco):

        def footer_pos2(co):
            if mco(co):
                self._patch_co_object(co)
            for i in co.co_consts:
                if type(i) == type(co):
                    footer_pos2(i)
        footer_pos2(module_co)

# =============================================================================
# Non-RFT Lambda Armor Patcher - Simplified lambda patcher
# =============================================================================
class NonRFTLambdaArmorPatcher(LambdaArmorPatcher):

    def handle(self, script):

        def _is_non_armored_lambda(co):
            return co.co_name == '<lambda>' and (not is_assert_armored_lambda(co))
        self.handle_mco(script.mco, _is_non_armored_lambda)

# =============================================================================
# Module Lambda Armor Patcher - Patches module-level code objects
# =============================================================================
class ModuleLambdaArmorPatcher(BaseCodePatcher):

    def __init__(self, ctx, shared_state):
        self.ctx = ctx
        self.impt = shared_state

    def _patch_co_object(self, co):
        code = bytearray(co.co_code)
        iv = len(code)
        module_code = len(co.co_consts)
        co_consts = self.ctx.python_version[1]
        self.impt['fix_co_object'](co, b'co_code', code)
        header_size = list(co.co_consts)
        header_size.append(generate_unique_name('lambda'))
        except_table = pack('QBBBBII', 0, 8, 0, 0, headsize, iv, 0)
        header_size[module_code + 1] = except_table
        footer_size = [1 << self.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << self.impt['CO_MARSHAL_FIX_CO_JIT_OFF'], 0, 0, 0]
        footer_size.extend(encode_type_value(2, module_code))
        footer_size.extend(encode_type_value(0, module_code + 1))
        footer_size.insert(0, len(footer_size))
        header_size.append(bytes(footer_size))
        self.impt['fix_co_object'](co, b'co_consts', tuple(header_size))
        footer_pos = co.co_flags | self.impt['CO_FLAG_PYTRANSFORM3']
        self.impt['fix_co_object'](co, b'co_flags', footer_pos)

    def handle(self, script):
        self._patch_co_object(script.mco)

# =============================================================================
# Local Variable Renamer (mix.localnames) - Renames local/cell/free vars
# =============================================================================
class LocalVariableRenamer(object):
    PREFIX = '_var_var_'

    def __init__(self, ctx, shared_state):
        self.ctx = ctx
        self.imptbl = shared_state

    def _co_narg(self, co):
        nlocals = co.co_argcount + co.co_kwonlyargcount
        nlocals += 1 if co.co_flags & 4 else 0
        nlocals += 1 if co.co_flags & 8 else 0
        return nlocals

    def _name_pool(self, name):
        if name.startswith('__'):
            return name
        if name not in self._pool:
            self._pool.append(name)
        return self.PREFIX + str(self._pool.index(name))

    def _get_name_names(self, co):
        return [bytecode.argval for bytecode in dis.get_instructions(co) if bytecode.opname in ('LOAD_NAME', 'STROE_NAME')]

    def _get_import_names(self, co):
        return [bytecode.argval for bytecode in dis.get_instructions(co) if bytecode.opname in ('IMPORT_NAME', 'IMPORT_FROM')]

    def _get_attr_symbols(self, co):
        return [bytecode.argval for bytecode in dis.get_instructions(co) if bytecode.opname in ('LOAD_ATTR', 'STORE_ATTR')]

    def _handle_module_co(self, mco):
        varnames = {}
        includes = set(self._get_name_names(mco))
        excludes = set()
        for item in mco.co_names:
            if item in includes and item not in excludes:
                varnames.setdefault(item, self._name_pool(item))
        name_pool = [varnames.get(item, item) for item in mco.co_names]
        self.imptbl['fix_co_object'](mco, 'co_names', tuple(name_pool))

    def _handle_co(self, co, is_module):
        nlocals = self._co_narg(co)
        old_name = {}
        for item in co.co_cellvars:
            if item not in co.co_varnames[:nlocals]:
                old_name.setdefault(item, self._name_pool(item))
        for item in co.co_varnames[nlocals:]:
            old_name.setdefault(item, self._name_pool(item))
        new_name = [old_name.get(item, item) for item in co.co_cellvars]
        cell_map = [is_module.get(item, item) for item in co.co_freevars]
        free_map = list(co.co_varnames[:nlocals])
        free_map.extend([old_name.get(item, item) for item in co.co_varnames[nlocals:]])
        name_set = self.imptbl['fix_co_object']
        (cell_vars, co_consts) = self.ctx.python_version[:2]
        if cell_vars == 3 and co_consts < 11:
            name_set(co, b'co_cellvars', tuple(new_name))
            name_set(co, b'co_freevars', tuple(cell_map))
            name_set(co, b'co_varnames', tuple(free_map))
        else:
            free_vars = name_set(co, b'co_freevars', None)
            local_vars = []
            (all_names, co_names, name_idx) = (16, 64, 128)
            for (name, renamed) in zip(*free_vars):
                try:
                    if renamed & co_names:
                        local_vars.append(new_name[co.co_cellvars.index(name)])
                    elif renamed & name_idx:
                        local_vars.append(cell_map[co.co_freevars.index(name)])
                    else:
                        local_vars.append(free_map[co.co_varnames.index(name)])
                except ValueError:
                    local_vars.append(name)
            name_set(co, b'co_varnames', tuple(local_vars))
        is_module = dict(zip(co.co_cellvars, new_name))
        for item in [item for item in co.co_consts if isinstance(item, type(co))]:
            self._handle_co(item, is_module)

    def handle(self, script):
        mco = script.mco
        self._pool = []
        for co in mco.co_consts:
            if isinstance(co, type(mco)):
                self._handle_co(co, {})

# =============================================================================
# VMC Code Patcher - Replaces VMC placeholders with VM bytecode
# =============================================================================
class VMCCodePatcher(Component):
    LOGNAME = 'cli.vmc'

    def __init__(self, ctx, shared_state):
        super().__init__(ctx)
        self.impt = shared_state

    def handle(self, script):
        if not getattr(script, 'vmcblocks', None):
            self.logger.info('no vmc blocks found')
            return
        self.logger.debug('patch vmc')
        name_set = self.impt['fix_co_object']
        vmc_blocks = script.vmcblocks
        mco = script.mco
        block = type(mco)
        jump_target = (None, None, None, None)
        block_items = VMCodeEmitter.ECC_CONSTS
        block_consts = '__pyarmor_ecc_code_block_'
        vmc_index = mco.co_consts.index(block_items)
        self.logger.info('find vmc index: %s', vmc_index)
        script.vmcindex = vmc_index
        item_data = VMCCompiler()

        def compiler(co):
            compiled = list(co.co_consts)
            size = 0
            for item in co.co_consts:
                if isinstance(item, block):
                    compiler(item)
                elif isinstance(item, str) and item.startswith(block_consts):
                    compiled[size] = item_data.build_vmcode(co, vmc_blocks[item])
                elif item is block_items:
                    compiled[size] = jump_target
                size += 1
            name_set(co, b'co_consts', tuple(compiled))
        compiler(mco)
import ast
import re
from fnmatch import fnmatchcase
vmc_name = (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)

# Resolve a relative ImportFrom AST node into a full dotted module name
def resolve_relative_import(mod_name, node):
    if not node.level:
        return node.module
    if mod_name.count('.') < node.level:
        lineno = getattr(node, 'lineno', -1)
        raise RuntimeError('"%s" line %d relative import "%s" overflow' % (mod_name, lineno, node.module))
    vmc_str = mod_name.split('.')[:-node.level]
    if node.module:
        vmc_str.append(node.module)
    return '.'.join(vmc_str)

# Decompose an AST attribute chain (e.g., a.b.c()) into component nodes
def decompose_attr_chain(attr_chain):
    dotted_name = []
    node = attr_chain
    while isinstance(node, ast.Attribute) or isinstance(node, ast.Call) or isinstance(node, ast.Subscript):
        if isinstance(node, ast.Attribute):
            dotted_name.insert(0, node)
        node = node.func if isinstance(node, ast.Call) else node.value
    if attr_chain is not node:
        dotted_name.insert(0, node)
    return dotted_name

# Convert a decomposed attribute chain into a dotted string
def attr_chain_to_dotted_name(dotted_name):
    return '.'.join([item.attr if isinstance(item, ast.Attribute) else item.id if isinstance(item, ast.Name) else attr_chain_to_dotted_name([item.func]) if isinstance(item, ast.Call) else attr_chain_to_dotted_name([item.value]) if isinstance(item, ast.Subscript) else '<%s>' % type(item.value).__name__ if isinstance(item, ast.Constant) else '<%s>' % type(item).__name__ for item in dotted_name])

# Generator yielding all sub-nodes in an attribute/call/subscript chain
def yield_attr_subnodes(attr_chain):
    node = attr_chain
    while isinstance(node, ast.Attribute) or isinstance(node, ast.Call) or isinstance(node, ast.Subscript):
        if isinstance(node, ast.Call):
            for item in node.args + node.keywords:
                yield item
        elif isinstance(node, ast.Subscript):
            yield node.slice
        node = node.func if isinstance(node, ast.Call) else node.value
        yield node
    if attr_chain is not node:
        yield node

# Decompose an attribute chain, breaking on Name nodes
def decompose_dotted_chain(attr_chain):
    dotted_name = []
    node = attr_chain
    while isinstance(node, ast.Attribute) or isinstance(node, ast.Call) or isinstance(node, ast.Subscript):
        dotted_name.insert(0, node)
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                node = node.func.value
            elif isinstance(node.func, (ast.Subscript, ast.Call)):
                node = node.func
            else:
                break
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                node = node.value.value
            elif isinstance(node.value, (ast.Subscript, ast.Call)):
                node = node.value
            else:
                break
    else:
        if attr_chain is not node:
            dotted_name.insert(0, node)
    return dotted_name

# Match a name against glob-like pattern (*prefix, suffix*, /regex/, fnmatchcase)
def match_name_pattern(name, pattern):
    """"""
    if pattern.startswith('*'):
        return name.endswith(pattern[1:])
    elif pattern.endswith('*'):
        return name.startswith(pattern[:-1])
    elif pattern.startswith('/'):
        return bool(re.match(pattern[1:-1], name))
    elif pattern.find(' ') > 0:
        return name in pattern.split()
    else:
        return fnmatchcase(name, pattern)

# Check if a name passes include/exclude filter rules
def is_name_included(value, includes, excludes):
    return (not includes or any([match_name_pattern(item, value) for item in includes])) and (not any([match_name_pattern(item, value) for item in excludes]))

# =============================================================================
# AST Tree Traveler - AST traversal utility with parent tracking
# =============================================================================
class ASTTreeTraveler(object):
    """"""

    def __init__(self, tree):
        self._tree = tree
        self._stack = []

    @property
    def stack(self):
        return [item for item in self._stack if isinstance(item[0], name)]

    @property
    def domain(self):
        return '.'.join([item[0].name for item in self.stack])

    @property
    def top(self, n=0):
        return self._stack[-n - 1]

    def travel(self, ignored=None, noattrs=('ctx',)):

        def entries(node):
            for (field, ignored) in ast.iter_fields(node):
                if field in noattrs:
                    continue
                if ignored and isinstance(ignored, ignored):
                    continue
                if isinstance(ignored, ast.AST):
                    self._stack.append((node, field))
                    yield ignored
                    for item in entries(ignored):
                        yield item
                    self._stack.pop()
                elif isinstance(ignored, list):
                    idx = 0
                    for result in ignored:
                        if isinstance(result, ast.AST) and (not (ignored and isinstance(result, ignored))):
                            self._stack.append((node, field, idx))
                            yield result
                            for item in entries(result):
                                yield item
                            self._stack.pop()
                        idx += 1
        for item in entries(self._tree):
            yield item

# =============================================================================
# Name Filter - Include/exclude filter for names/patterns
# =============================================================================
class NameFilter(object):

    def __init__(self, includes, excludes, namepool=None):
        self._includes = includes.splitlines() if includes else []
        self._excludes = excludes.splitlines() if excludes else []
        if namepool:
            self._refactor_rules(namepool)

    def check(self, name):
        return is_name_included(name, self._includes, self._excludes)

    def _refactor_rules(self, rules):

        def negated(rule):
            for pattern in rule[:]:
                if pattern.startswith('/'):
                    continue
                refactored = ' '.join([rules(item) if item.isidentifier() and rules(item, test=True) else item for item in pattern.split(' ')])
                if refactored != pattern:
                    rule.append(refactored)
        negated(self._includes)
        negated(self._excludes)

# =============================================================================
# Extended Name Filter - NameFilter with visitor reference
# =============================================================================
class ExtendedNameFilter(NameFilter):

    def __init__(self, includes, excludes, visitor=None):
        super().__init__(includes, excludes)
        self._visitor = visitor

# Match an AST node against a complex pattern string
def match_node_pattern(node, mod_name, pattern):
    colon_pos = pattern.find(':')
    prefix = '' if colon_pos == -1 else pattern[:colon_pos]
    expr = pattern[colon_pos + 1:]
    if mod_name.startswith(prefix) or (prefix[:1] == '@' and node.lineno == int(prefix[1:])):
        node_name = get_node_name(node)
        if node_name is None:
            return False
        if expr[0] == '=':
            return expr[1:] == node_name
        elif expr[0] == '+':
            return node_name.startswith(expr)
        elif expr[0] == '-':
            return node_name.endswith(expr[1:])
        elif expr[0] == '*':
            return False
        elif expr[0] == '/':
            return node_name.find(expr[1:]) > -1
        elif expr[0] == '?':
            return re.search(expr[:1], node_name) is not None
        else:
            return node_name in expr.split()
import ast

# =============================================================================
# AttrDict - Dict subclass with attribute access support
# =============================================================================
class AttrDict(dict):

    def __getattr__(self, field):
        if field in self._FIELDS:
            return self[field]
        elif field[:3] == 'is_' and field[3:] in self:
            return self[field[3:]]
        raise AttributeError(field)

    def __setattr__(self, field, value):
        if field in self._FIELDS:
            self[field] = value
        else:
            super().__setattr__(field, value)

    def __eq__(self, flag):
        return self.name == flag.name and self.cls == flag.cls

# =============================================================================
# Type Field - Simple type descriptor for module analysis
# =============================================================================
class TypeField(AttrDict):
    _FIELDS = ('name', 'cls')

    def __init__(self, name, cls='', **type_name):
        super().__init__(name=name, cls=cls, **type_name)

# =============================================================================
# Module Type Info - Rich type descriptor for modules/classes
# =============================================================================
class ModuleTypeInfo(AttrDict):
    _FIELDS = ('name', 'cls', 'fields', 'imports')

    def __init__(self, name, cls='class', **kwargs):
        super().__init__(name=name, cls=cls, fields=[], imports={}, **kwargs)
        self.bases = []

    def append(self, info):
        if info and info not in self.fields:
            self.fields.append(info)

    def find(self, name, inner=False):
        for item in self.fields:
            if name == item.name:
                return item
        if inner:
            return
        for item in self.imports:
            if item == name:
                return self.imports[item]
            elif item.endswith('.*'):
                for flag in self.imports[item]:
                    if name == flag.name:
                        return flag

    def imp_node(self, node, qualname=''):
        if isinstance(node, ast.Import):
            for item in node.names:
                sub_info = item.asname if item.asname else item.name
                sub_info = sub_info.split('.')[0]
                name = item.name.split('.')[0]
                self.imports[sub_info] = TypeField(name, 'import')
        elif isinstance(node, ast.ImportFrom):
            pkg_name = resolve_relative_import(qualname, node)
            for item in node.names:
                sub_info = item.asname if item.asname else item.name
                name = pkg_name + '.' + item.name
                if sub_info == '*':
                    self.imports[pkg_name + '.*'] = []
                else:
                    self.imports[sub_info] = TypeField(name, 'import')

    def add_node(self, node, cls=None):
        name = node.id if isinstance(node, ast.Name) else node.name if isinstance(node, field_name) else None
        if not name:
            lineno = getattr(node, 'lineno', -1)
            raise RuntimeError('type "%s" line %d has an invalid node "%s"' % (self.name, type(node).__name__, lineno))
        info = self.find(name, inner=True)
        if info:
            if info.cls == '<?>' and cls and (cls != '<?>'):
                info.cls = cls
        else:
            cls = cls if cls is not None else 'class' if isinstance(node, ast.ClassDef) else 'function' if isinstance(node, field_name) else '<?>'
            self.append(TypeField(name, cls))

    def extend(self, type_cls):
        for item in type_cls:
            if not isinstance(item, TypeField):
                raise RuntimeError('type "%s" extends invalid field "%s"' % item)
            self.append(item)

    def star_names(self):
        field = [item.name for item in self.fields]
        for item in self.imports:
            if item.endswith('.*'):
                field.extend([item.name for item in self.imports[item]])
            else:
                field.append(item)
        return [item for item in field if not item.startswith('_')]

    def __str__(self):
        from json import dumps
        return dumps(self, indent=2)

# =============================================================================
# Module Analyzer - Analyzes module AST for types and dependencies
# =============================================================================
class ModuleAnalyzer(object):

    def __init__(self, ctx, name=None, node=None, co=None):
        self.ctx = ctx
        self._name = name
        self._node = node
        self._co = co

    def reset(self, name=None, node=None, co=None):
        self._name = name
        self._node = node
        self._co = co

    def log(self, full_name, node, key):
        lineno = getattr(node, 'lineno', -1)
        logger.debug('%s:%s: %s', full_name, lineno, key)

    @property
    def using_modules(self):
        return self._get_using_modules(self._name, self._node)

    def rebuild(self):
        self._get_module_types(self._name, self._node)

    def _constant_type(self, value):
        return '<%s>' % type(value).__name__

    def _get_field_type(self, pkg_name, type_info):
        if type_info.cls == 'import':
            pkg = type_info.name
        elif type_info.cls in ('class', 'module'):
            pkg = pkg_name + '.' + type_info.name
        elif type_info.cls in ('function',):
            pkg = self.ctx.variable_types.get(pkg_name + '.' + type_info.name)
        else:
            pkg = type_info.cls
        return pkg

    def guess_type(self, mod_name2, imports, node):
        import_names = getattr(node, 'type_comment', None)
        if not import_names:
            bases = getattr(node, 'annotation', getattr(node, 'returns', None))
            if bases:
                import_names = bases.id if isinstance(bases, ast.Name) else getattr(bases, 'value', getattr(bases, 's', None))
        if import_names:
            idx = self.ctx.module_types.get(mod_name2)
            if idx:
                type_info = idx.find(import_names)
                if type_info:
                    return self._get_field_type(mod_name2, type_info)
            return '<%s>' % import_names
        node = getattr(node, 'value', None)
        if not (node and isinstance(node, ast.AST)):
            return '<?>'
        if isinstance(node, ast.Constant):
            return self._constant_type(node.value)
        for item in ('Num', 'Str', 'Bytes', 'NameConstant'):
            if isinstance(node, getattr(ast, item, type(None))):
                return self._constant_type(node.n if hasattr(node, 'n') else node.s if hasattr(node, 's') else node.value)
        idx = self.ctx.module_types.get(mod_name2)
        if not idx:
            return '<?>'

        def base_name(import_node):
            if import_node in self.ctx.module_types:
                return True
            name = import_node.split('.')[-1]
            return name and name.isidentifier() and name[0].isupper() and any([item.islower() or item.isdigit() for item in name]) and (not all([item.isupper() or item.isdigit() or item == '_' for item in name]))
        if isinstance(node, ast.Name):
            type_info = idx.find(node.id)
            if type_info:
                return self._get_field_type(idx.name, type_info)
            mod_name = '.'.join(imports + [node.id])
            return self.ctx.variable_types.get(mod_name, '<?>')
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                type_info = idx.find(node.func.id)
                if type_info:
                    if type_info.cls == 'class':
                        return idx.name + '.' + type_info.name
                    elif type_info.cls == 'import':
                        if base_name(type_info.name):
                            return type_info.name
                        else:
                            return self.ctx.variable_types.get(type_info.name, '(%s)' % type_info.name)
                    elif type_info.cls == 'function':
                        body_names = idx.name + '.' + type_info.name
                        return self.ctx.variable_types.get(body_names, '(%s)' % body_names)
        return '<?>'

    def _get_module_types(self, mod_name2, tree):
        var_types = self.ctx.variable_types
        modules = self.ctx.module_types
        mod_info = self.ctx.base_types[mod_name2] = []
        imports = []

        def class_info(node):
            if isinstance(node, field_name):
                mod_name = '.'.join(imports)
                if mod_name in modules:
                    modules[mod_name].add_node(node)
                imports.append(node.name)
                if isinstance(node, ast.ClassDef):
                    mod_name = '.'.join(imports)
                    if mod_name in modules:
                        self.log(mod_name2, node, 'duplicated type "%s"' % mod_name)
                    func_info = modules[mod_name] = ModuleTypeInfo(mod_name)
                    func_node = [item.id for item in node.bases if isinstance(item, ast.Name)]
                    if func_node:
                        mod_info.append((func_info, func_node))
            for ignored in ast.iter_child_nodes(node):
                class_info(ignored)
            if isinstance(node, field_name):
                imports.pop()

        def ret_type(mod_name, node, arg_names):
            arg_names = arg_names if arg_names else '<?>'
            if mod_name in modules:
                modules[mod_name].add_node(node)
                type_info = modules[mod_name].find(node.id)
                if type_info.cls in ('<?>', ''):
                    type_info.cls = arg_names
            var_types[mod_name + '.' + node.id] = arg_names

        def entries(node):
            if isinstance(node, ast.Assign):
                mod_name = '.'.join(imports)
                for node2 in node.targets:
                    if isinstance(node2, ast.Name):
                        local_names = self.guess_type(mod_name2, imports, node)
                        ret_type(mod_name, node2, local_names)
                    elif isinstance(node2, ast.Tuple):
                        for global_names in node2.elts:
                            if isinstance(global_names, ast.Name):
                                ret_type(mod_name, global_names, '<?>')
                            elif isinstance(global_names, ast.Attribute):
                                pass
                    elif isinstance(node2, ast.Attribute) and isinstance(node2.ctx, ast.Store):
                        nonlocal_names = decompose_attr_chain(node2)
                        chain = nonlocal_names.pop(0)
                        if isinstance(chain, ast.Name) and len(nonlocal_names) == 1:
                            imported_names = '.'.join(imports + [chain.id])
                            attr_names = var_types.get(imported_names)
                            if attr_names and attr_names in modules:
                                local_names = self.guess_type(mod_name2, imports, node)
                                type_info = TypeField(nonlocal_names[0].attr, cls=local_names)
                                modules[attr_names].extend([type_info])
                return
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name):
                    mod_name = '.'.join(imports)
                    bases = node.annotation
                    if isinstance(bases, ast.Name):
                        local_names = bases.id
                    elif isinstance(bases, ast.Attribute):
                        local_names = attr_chain_to_dotted_name(decompose_attr_chain(bases))
                    elif isinstance(bases, ast.Subscript):
                        local_names = getattr(bases.value, 'id', '?')
                    else:
                        local_names = '?'
                    if local_names not in modules:
                        local_names = '<%s>' % local_names
                    ret_type(mod_name, node.target, local_names)
                return
            elif isinstance(node, ast.Import):
                mod_name = '.'.join(imports)
                if mod_name in modules:
                    modules[mod_name].imp_node(node)
                return
            elif isinstance(node, ast.ImportFrom):
                mod_name = '.'.join(imports)
                if mod_name in modules:
                    modules[mod_name].imp_node(node, mod_name2)
                return
            elif isinstance(node, field_name):
                parent_info = '.'.join(imports)
                imports.append(node.name)
                if hasattr(node, 'args'):
                    mod_name = '.'.join(imports)
                    import_names = self.guess_type(mod_name2, imports, node)
                    var_types[mod_name] = import_names
                    using_mods = parent_info in modules and parent_info != mod_name2 and ('staticmethod' not in node.decorator_list)
                    result = node.args
                    dep_mod = getattr(result, 'posonlyargs', []) + result.args + result.kwonlyargs
                    if result.args and using_mods:
                        reg = result.args[0]
                        var_types[mod_name + '.' + reg.arg] = parent_info
                        dep_mod.remove(reg)
                    for reg in dep_mod:
                        assign_node = reg.arg
                        import_names = self.guess_type(mod_name2, imports, reg)
                        var_types[mod_name + '.' + assign_node] = import_names
            for ignored in ast.iter_child_nodes(node):
                entries(ignored)
            if isinstance(node, field_name):
                imports.pop()
        modules[mod_name2] = ModuleTypeInfo(mod_name2, cls='module')
        imports = [mod_name2]
        class_info(tree)
        imports = [mod_name2]
        entries(tree)

    def _get_using_modules(self, import_node, tree):
        dep_name = set()

        def entries(node):
            if isinstance(node, ast.Import):
                dep_name.update([item.name for item in node.names])
            elif isinstance(node, ast.ImportFrom):
                dep_name.add(resolve_relative_import(import_node, node))
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        entries(tree)
        return dep_name

    def _search_class_attrs(self, func_name):
        dep_info = set()

        def entries(node):
            if isinstance(node, ast.Assign):
                for node2 in node.targets:
                    if isinstance(node2, ast.Attribute):
                        var_name = []
                        while isinstance(node2, ast.Attribute):
                            var_name.insert(0, node2.attr)
                            node2 = node2.value
                        if isinstance(node2, ast.Name):
                            if node2.id == attr_name:
                                dep_info.add(var_name[0])
            elif isinstance(node, field_name):
                dep_info.add(node)
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        attr_name = func_name.args.args[0].arg if func_name.args.args else '@'
        for item in func_name.body:
            entries(item)
        return dep_info

    def _get_hidden_imports(self, tree):
        var_type = []
        type_str = (ast.Constant, getattr(ast, 'Str', ast.Constant))

        def entries(node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and (node.func.id in ('__import__', '__dict__')) and node.func.args and isinstance(node.func.args[0], type_str):
                pass
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and (node.func.id in ('getattr', 'setattr')) and (len(node.args) > 1) and isinstance(node.args[0], ast.Name) and isinstance(node.args[1], type_str):
                pass
            for ignored in ast.iter_child_nodes(node):
                entries(ignored)
        entries(tree)
        return var_type

    def _get_body_names(self, node):
        nonlocal_names = set()

        def entries(node):
            if isinstance(node, ast.Assign):
                for node2 in node.targets:
                    if isinstance(node2, ast.Name):
                        nonlocal_names.add(node2)
            elif isinstance(node, field_name):
                nonlocal_names.add(node)
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        for item in node.body:
            entries(item)
        return nonlocal_names

    def _get_module_names(self, tree):
        type_node = {}
        imports = []

        def entries(node):
            if isinstance(node, field_name):
                imports.append(node.name)
            elif isinstance(node, ast.Name):
                mod_name = '.'.join(imports)
                type_node.setdefault(mod_name, set())
                type_node[mod_name].add(node.id)
                return
            for ignored in ast.iter_child_nodes(node):
                entries(ignored)
            if isinstance(node, field_name):
                imports.pop()
        entries(tree)
        return type_node

    def _get_module_attrs(self, tree):
        ann_value = set()

        def entries(node):
            if isinstance(node, ast.Assign):
                for node2 in node.targets:
                    if isinstance(node2, ast.Name):
                        ann_value.add(node2.id)
            elif isinstance(node, field_name):
                ann_value.add(node.name)
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)

        def call_name(node):
            if isinstance(node, ast.Global):
                ann_value.update(node.names)
            else:
                for ignored in ast.iter_child_nodes(node):
                    call_name(ignored)
        entries(tree)
        call_name(tree)
        return ann_value

    def _get_import_names(self, tree):
        hidden_imports = {}

        def entries(node):
            if isinstance(node, ast.ImportFrom):
                name = '.' * node.level + node.module if node.module else ''
                hidden_imports.setdefault(name, set())
                hidden_imports[name].update([item.name for item in node.names])
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        entries(tree)
        return hidden_imports

    def _get_import_modules(self, tree):
        hidden_mod = {}

        def entries(node):
            if isinstance(node, ast.Import):
                for (name, sub_info) in [(item.name, item.asname) for item in node.names]:
                    hidden_mod[sub_info if sub_info else name] = name
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        entries(tree)
        return hidden_mod

    def _get_import_attrs(self, tree):
        ann_value = {}
        hidden_name = ast.Attribute
        mod_attrs = ast.Name

        def entries(node):
            if isinstance(node, hidden_name) and isinstance(node.value, mod_attrs):
                name = node.value.id
                if name in self.import_modules:
                    ann_value.setdefault(name, set())
                    ann_value[name].add(node.attr)
            else:
                for ignored in ast.iter_child_nodes(node):
                    entries(ignored)
        entries(tree)
        return ann_value

    def _get_mapped_names(self, tree):
        var_names = {'': set(self._get_module_attrs(tree))}
        imports = []

        def entries(node):
            if isinstance(node, field_name):
                if imports:
                    mod_name = '.'.join(imports)
                    var_names.setdefault(mod_name, set())
                    var_names[mod_name].add(node.name)
                imports.append(node.name)
            for ignored in ast.iter_child_nodes(node):
                entries(ignored)
            if isinstance(node, field_name):
                imports.pop()
        entries(tree)
        return var_names

# =============================================================================
# Package Relations Builder - Builds inter-module type/dependency graph
# =============================================================================
class PackageRelationsBuilder(object):

    def __init__(self, ctx):
        self.ctx = ctx

    def _import_star_names(self, script, rel_name):
        footer_size = self.ctx.module_types.get(rel_name)
        if footer_size:
            field = footer_size.get('exports', footer_size.star_names())
            star_names = []
            var_types = self.ctx.variable_types
            for item in field:
                type_info2 = footer_size.find(item)
                if type_info2.cls == 'class':
                    star_names.append(rel_name + '.' + item)
                elif type_info2.cls == 'import':
                    star_names.append(type_info2.name)
                else:
                    star_names.append(var_types.get(rel_name + '.' + item, '<?>'))
            return zip(field, star_names)
        try:
            pkg = __import__(rel_name, {}, {}, ['__all__'], 0)
            field = getattr(pkg, '__all__', [item for item in dir(pkg) if item[:1] != '_'])
            star_names = [type(getattr(pkg, item)).__name__ for item in field]
            return zip(field, star_names)
        except ModuleNotFoundError as entry:
            logger.error('import "%s" failed: %s', rel_name, str(entry))
            logger.error('please add extra path to PYTHONPATH to fix it')
            raise RuntimeError('could not handle "from %s import *" in the module "%s"' % (rel_name, script.fullname))

    def _get_export_names(self, pkg_info):
        for node in ast.walk(pkg_info.mtree):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and (node.targets[0].id == '__all__'):
                if isinstance(node.value, ast.Constant):
                    init_info = node.value
                elif isinstance(node.value, (ast.List, ast.Tuple)):
                    init_info = [getattr(item, 's', getattr(item, 'value', None)) for item in node.value.elts]
                else:
                    init_info = None
                if not (isinstance(init_info, (list, tuple)) and all([isinstance(item, str) for item in init_info])):
                    logger.error('invalid "__all__" in the module "%s": %s', pkg_info.fullname, ast.dump(node.value))
                    raise RuntimeError('"%s.__all__" is not a string list' % pkg_info.fullname)
                return init_info

    def _format_export_names(self, script, export_names):
        result = []
        if export_names:
            idx = self.ctx.module_types[script.pkgname]
            for item in export_names:
                type_info2 = idx.find(item)
                if not type_info2:
                    logger.error('module "%s" exports "%s" in the "__all__", but not defined it', script.fullname, item)
                    raise RuntimeError('invalid module "%s"' % script.fullname)
                if type_info2.cls == 'import':
                    result.append(type_info2.name)
                result.append('%s.%s' % (script.pkgname, item))
        return result

    def _normalize_export_names(self):
        modules = self.ctx.module_types
        export_name = self.ctx.rft_export_names
        star_mods = [item for item in export_name if item in modules]
        for name in star_mods:
            star_mod = modules[name]
            init_info = ['.'.join([name, item]) for item in star_mod.star_names()]
            export_name.update([item for item in init_info if item not in star_mods])

    def _format_module_types(self):
        modules = self.ctx.module_types
        var_types = self.ctx.variable_types
        star_info = [item.split('.')[0] for item in modules]
        star_imports = {}
        for star_item in star_info:
            star_imports[star_item] = set([item.split('.')[1] for item in modules if item.startswith(star_item + '.')])
        key = '.__init__'
        parent_pkg = [item for item in modules if item.endswith(key)]
        for item in parent_pkg:
            modules[item.replace(key, '')] = modules.pop(item)
            parent_info = [block_list for block_list in var_types if var_types[block_list].startswith(item)]
            for block_list in parent_info:
                merged_types = block_list.replace(key, '', 1)
                var_types[merged_types] = var_types.pop(block_list)
        for star_item in star_info:
            modules.setdefault(star_item, ModuleTypeInfo(star_item, cls='module'))
            modules[star_item].extend([TypeField(item, cls='module') for item in star_imports[star_item]])

    def _format_base_types(self, idx, merged_info, pkg_name):
        modules = self.ctx.module_types
        for (mod_info, rel_info) in merged_info:
            for name in rel_info:
                type_info2 = idx.find(name)
                if type_info2:
                    if type_info2.cls == 'import':
                        item = modules.get(type_info2.name, None)
                        if item:
                            mod_info.bases.append(item)
                    elif type_info2.cls == 'class':
                        pkg2 = pkg_name + '.' + type_info2.name
                        item = modules.get(pkg2, None)
                        if item:
                            mod_info.bases.append(item)

    def process(self, clean=True):
        cfg = self.ctx.cfg['builder']
        full_name = self.ctx.cmd_options
        type_info = full_name.get('enable_rft', cfg.getboolean('enable_rft'))
        mod_list = cfg.get('encoding')
        base_types = type_info and cfg.getboolean('rft_auto_export')
        base_name = {}
        self.ctx.base_types = {}

        def base_info():
            for script in self.ctx.resources:
                for pkg_info in script:
                    if not pkg_info.is_script():
                        continue
                    yield pkg_info
        for pkg_info in base_info():
            if not pkg_info.mtree:
                pkg_info.reparse(encoding=mod_list)
            field = self._get_export_names(pkg_info)
            if field:
                base_name[pkg_info.fullname] = field
        for pkg_info in base_info():
            mod_name = pkg_info.fullname
            footer_size = ModuleAnalyzer(self.ctx, mod_name, pkg_info.mtree)
            footer_size.rebuild()
            self.ctx.module_relations[pkg_info.pkgname] = footer_size.using_modules
            init_info = base_name.get(mod_name)
            if init_info:
                self.ctx.module_types[mod_name]['exports'] = init_info
        self._format_module_types()

        def cls_info(pkg_info, type_info2):
            if type_info2.cls == '':
                logger.warning('type unknown "%s.%s"', pkg_info.fullname, type_info2.name)
        for pkg_info in base_info():
            mod_name = pkg_info.fullname
            idx = self.ctx.module_types.get(pkg_info.pkgname)
            merged_info = self.ctx.base_types.get(mod_name)
            if merged_info:
                self._format_base_types(idx, merged_info, pkg_info.pkgname)
            for (name, type_info2) in idx.imports.items():
                if name.endswith('.*'):
                    mro_list = name[:-2]
                    for (item, mro_name) in self._import_star_names(pkg_info, mro_list):
                        type_info2.append(TypeField(item, cls=mro_name))
            [cls_info(pkg_info, item) for item in idx.fields]
        self.ctx.base_types = None
        if base_types:
            export_name = self.ctx.rft_export_names
            for pkg_info in base_info():
                export_names = base_name.get(pkg_info.fullname)
                export_name.update(self._format_export_names(pkg_info, export_names))
            self._normalize_export_names()
        if clean:
            [pkg_info.clean() for pkg_info in base_info()]
from collections import namedtuple
from marshal import dumps as marshal_dumps
VM_NOP = 0
VM_COMPARE_JUMP = 127
VM_LOAD_CONST = 1
VM_STORE_NAME = 2
VM_LOAD_NAME = 3
VM_LOAD_ATTR = 6
VM_STORE_ATTR = 8
VM_DELETE_ATTR = 12
VM_SUBSCR = 14
VM_STORE_SUBSCR = 16
VM_LOAD_FAST = 18
VM_STORE_FAST = 20
VM_DELETE_FAST = 30
VM_LOAD_GLOBAL = 32
VM_STORE_GLOBAL = 33
VM_DELETE_GLOBAL = 34
VM_LOAD_DEREF = 38
VM_STORE_DEREF = 40
VM_DELETE_DEREF = 42
VM_CALL_FUNCTION = 43
VM_CALL_FUNCTION_KW = 45
VM_CALL_FUNCTION_EX = 46
VM_UNARY_POSITIVE = 48
VM_UNARY_NEGATIVE = 49
VM_UNARY_NOT = 51
VM_UNARY_INVERT = 60
VM_BINARY_ADD = 62
VM_BINARY_SUBTRACT = 64
VM_BINARY_MULTIPLY = 66
VM_BINARY_DIVIDE = 70
VM_BINARY_FLOOR_DIVIDE = 72
VM_BINARY_MODULO = 100
VM_BINARY_POWER = 101
VM_BINARY_LSHIFT = 103
VM_BINARY_RSHIFT = 105
VM_BINARY_AND = 224
VM_BINARY_XOR = 128
VM_BINARY_OR = 130
VM_COMPARE_LT = 132
VM_COMPARE_LE = 134
VM_COMPARE_EQ = 136
VM_COMPARE_NE = 138
VM_COMPARE_GT = 140
VM_COMPARE_GE = 141
VM_COMPARE_IN = 150
VM_COMPARE_NOT_IN = 151
VM_COMPARE_IS = 152
VM_COMPARE_IS_NOT = 160
VM_GET_ITER = 161
VM_FOR_ITER = 165
VM_JUMP_ABSOLUTE = 169
VM_JUMP_FORWARD = 170
VM_POP_JUMP_IF_TRUE = 171
VM_POP_JUMP_IF_FALSE = 172
VM_JUMP_IF_TRUE_OR_POP = 173
VM_JUMP_IF_FALSE_OR_POP = 174
VM_BUILD_TUPLE = 175
VM_BUILD_LIST = 176
VM_BUILD_SET = 177
VM_BUILD_MAP = 178
VM_BUILD_SLICE = 179
VM_UNPACK_SEQUENCE = 180
VM_UNPACK_EX = 181
VM_LIST_APPEND = 182
VM_SET_ADD = 183
VM_MAP_ADD = 241
VM_NONE_ARG = bytes([VM_NOP])
VM_BYTE_LOAD_CONST = bytes([VM_BINARY_AND])
VM_BYTE_BLOCK_END = bytes([VM_COMPARE_IN])
VM_BYTE_EXPR_PREFIX = bytes([VM_COMPARE_NOT_IN])
VM_BYTE_LOAD_CONST = bytes([VM_BINARY_MODULO])
VM_BYTE_STORE_NAME = bytes([VM_LOAD_DEREF])
VM_BYTE_LOAD_NAME = bytes([VM_STORE_GLOBAL])
VM_BYTE_LOAD_ATTR = bytes([VM_DELETE_GLOBAL])
VM_BYTE_STORE_ATTR = bytes([VM_UNARY_POSITIVE])
VM_BYTE_SUBSCR = bytes([VM_UNARY_NOT])
VM_BYTE_STORE_SUBSCR = bytes([VM_CALL_FUNCTION_KW])
VM_BYTE_CALL_FUNCTION = bytes([VM_DELETE_DEREF])
VM_BYTE_UNARY_OP = bytes([VM_BINARY_XOR])
VM_BYTE_BINARY_OP = bytes([VM_STORE_NAME])
VM_BYTE_COMPARE_OP = bytes([VM_COMPARE_IS_NOT])
VM_BYTE_JUMP = bytes([VM_LOAD_NAME])
VM_BYTE_BUILD_TUPLE = bytes([VM_COMPARE_GT])
VM_BYTE_UNPACK = bytes([VM_BUILD_MAP])
VM_BYTE_GET_ITER = 0
rel_using = 1
rel_used_by = 2
rel_imports = 3
rel_base_types = 4
rel_sub_types = 5
rel_attrs = 6
rel_data = 7
rel_entry = 8
rel_key = 9
rel_val = 10
dep_graph = 11
dep_key = 7
dep_val = 8
dep_mods = 9
dep_mod = 10
dep_info = 11
mod_types = 12
mod_type = 13
type_key = 14
type_val = 15
all_types = 16
type_entry = 17
entry_key = 18
entry_val = 19
pkg_types = 20
pkg_type = 21
pkg_key = 22
pkg_val = 23
root_types = 24
root_key = 25
root_val = 26
relations = 27
rel_name2 = 28
rel_data2 = 29
data_key = 30
data_val = 31
rel_types = 32
rel_type = 33
rel_type_key = 34
rel_type_val = 35
pkg_rels = 36
pkg_rel = 37
pkg_rel_key = 38
pkg_rel_val = 75
final_data = 76
VmcStackItem = namedtuple('VmcStackItem', 'node, f_names, f_consts, f_localvars, f_freevars')
VmcBlockItem = namedtuple('VmcBlockItem', 'items, m_consts')
VmcExprItem = namedtuple('VmcExprItem', 'item, m_consts')

# =============================================================================
# VMC Compiler - Compiles Python AST to custom VM bytecode
# =============================================================================
class VMCCompiler(ast.NodeVisitor):
    """"""

    def __init__(self):
        self.co = None
        self.f_consts = None

    def build_vmcode(self, co, comp_target):
        self.co = co
        self.f_consts = comp_target.m_consts
        if isinstance(comp_target, VmcExprItem):
            assert isinstance(comp_target.item, ast.AST)
            return b''.join([VM_BYTE_EXPR_PREFIX, self.visit(comp_target.item)])
        assert isinstance(comp_target, VmcBlockItem)
        key = comp_target.items
        return b''.join([self.visit(item) for item in key]) + VM_BYTE_BLOCK_END

    def get_cell(self, name):
        """"""
        co = self.co
        offset = co.co_nlocals
        if name in co.co_cellvars:
            return offset + co.co_cellvars.index(name)
        if name in co.co_freevars:
            offset += len(co.co_cellvars)
            return offset + co.co_freevars.index(name)

    def get_local(self, name):
        try:
            return self.co.co_varnames.index(name)
        except ValueError:
            pass

    def get_name_index(self, name):
        size = self.get_cell(name)
        if size is not None:
            return (2, size)
        size = self.get_local(name)
        if size is not None:
            return (0, size)
        assert name in self.f_consts
        return (1, self.f_consts.index(name))

    def _load_name_ins(self, name):
        """"""
        (i, size) = self.get_name_index(name)
        comp_iter = [VM_LOAD_FAST, VM_SUBSCR, VM_STORE_FAST]
        return self._make_ins(comp_iter[i], size)

    def _store_name_ins(self, name):
        """"""
        (i, size) = self.get_name_index(name)
        comp_iter = [VM_COMPARE_LT, VM_BINARY_OR, VM_COMPARE_EQ]
        return self._make_ins(comp_iter[i], size)

    def _delete_name_ins(self, name):
        """"""
        (i, size) = self.get_name_index(name)
        comp_iter = [VM_POP_JUMP_IF_FALSE, VM_JUMP_FORWARD, VM_BUILD_LIST]
        return self._make_ins(comp_iter[i], size)

    def get_returns(self, comp_ifs):
        """"""
        size = len(comp_ifs)
        bytecode = pack('<BH', VM_MAP_ADD, size)
        comp_body = b''.join([pack('<H', self.get_local(item)) for item in comp_ifs])
        return b''.join([bytecode, comp_body])

    def _make_ins(self, opcode, size):
        assert size <= 4294967295, 'too big operand (%s)' % size
        return pack('BB', opcode, size) if size < 256 else pack('<BBH', opcode + 1, 0, size) if size < 65535 else pack('<BBI', opcode + 1, 1, size)

    def _make_jmp_ins(self, size):
        assert abs(size) <= 2147483647, 'too big jump offset (%s)' % size
        return pack('BB', VM_COMPARE_IS, size) if size < 256 else pack('<BH', VM_COMPARE_IS + 1, size) if size < 65535 else pack('<BI', VM_COMPARE_IS + 2, size)

    def _make_loop_ins(self, opcode, loop_start, loop_end):
        size = max(loop_start, loop_end)
        assert size <= 2147483647, 'too big loop size (%s)' % size
        return pack('BBB', opcode, loop_start, loop_end) if size < 256 else pack('<BHH', opcode + 1, loop_start, loop_end) if size < 65535 else pack('<BII', opcode + 2, loop_start, loop_end)

    def _make_store_target(self, attr_node):
        """"""
        if isinstance(attr_node, ast.Tuple):
            size = len(attr_node.elts)
            return self._make_ins(VM_COMPARE_NE, size) + b''.join([self.visit(item) for item in attr_node.elts])
        else:
            return self.visit(attr_node)

    def _make_arg(self, reg):
        if reg is None:
            return VM_NONE_ARG
        size = self.f_consts.index(reg)
        return self._make_ins(VM_DELETE_ATTR, size)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            return self._load_name_ins(node.id)
        elif isinstance(node.ctx, ast.Store):
            return self._store_name_ins(node.id)
        elif isinstance(node.ctx, ast.Del):
            return self._delete_name_ins(node.id)

    def visit_Constant(self, node):
        size = self.f_consts.index(node.value)
        return self._make_ins(VM_DELETE_ATTR, size)

    def visit_Call(self, node):
        scope_data = len(node.args)
        f_string = len(node.keywords)
        f_values = len([item for item in node.args if isinstance(item, ast.Starred)])
        f_value = len([cmp_reg for cmp_reg in node.keywords if cmp_reg.arg is None])
        func_name = self.visit(node.func)
        if scope_data == 0 and f_string == 0:
            return pack('BB', VM_BINARY_POWER, 0) + func_name
        if f_values == 0 and f_value == 0:
            if f_string == 0:
                bytecode = self._make_ins(VM_BINARY_POWER, scope_data)
                f_conv = b''.join([self.visit(item) for item in node.args])
                return b''.join([bytecode, f_conv, func_name])
            bytecode = self._make_ins(VM_BINARY_LSHIFT, scope_data)
            f_conv = b''.join([self.visit(item) for item in node.args])
            f_expr = b''.join([self._make_arg(item.arg) + self.visit(item.value) for item in node.keywords])
            return b''.join([bytecode, f_conv, f_expr, VM_NONE_ARG, func_name])
        if scope_data == 1 and f_values == 1:
            block_data = self.visit(node.args[0].value)
            if f_string == 1 and f_value == 1:
                f_format = self.visit(node.keywords[0].value)
                return b''.join([VM_BYTE_LOAD_CONST, block_data, f_format, func_name])
            elif f_string == 0:
                f_format = VM_NONE_ARG
                return b''.join([VM_BYTE_LOAD_CONST, block_data, f_format, func_name])
        if f_string == 1 and f_value == 1 and (scope_data == 0):
            block_data = VM_NONE_ARG
            f_format = self.visit(node.keywords[0].value)
            return b''.join([VM_BYTE_LOAD_CONST, block_data, f_format, func_name])
        bytecode = self._make_ins(VM_BINARY_RSHIFT, f_string)
        f_conv = b''.join([self.visit(item) for item in node.args])
        f_expr = b''.join([self._make_arg(item.arg) + self.visit(item.value) for item in node.keywords])
        return b''.join([bytecode, f_conv, VM_NONE_ARG, f_expr, func_name])

    def visit_BoolOp(self, node):
        opcode = VM_LOAD_ATTR if isinstance(node.op, ast.Or) else VM_STORE_ATTR
        body = b''.join([self.visit(item) for item in node.values])
        return b''.join([self._make_ins(opcode, len(body) + 1), body, VM_NONE_ARG])

    def visit_UnaryOp(self, node):
        ann_tgt = {'Invert': with_ctx, 'UAdd': aug_op, 'USub': assign_val, 'Not': bin_right}
        label = type(node.op).__name__
        bytecode = [pack('BB', VM_LOAD_CONST, ann_tgt[label])]
        bytecode.append(self.visit(node.operand))
        return b''.join(bytecode)

    def visit_BinOp(self, node):
        ann_tgt = {'Add': bin_ops, 'Sub': named_val, 'Mult': assign_tgt, 'Div': dict_keys, 'Mod': unary_ops, 'FloorDiv': sub_nodes, 'MatMult': set_elts, 'Pow': aug_val, 'LShift': with_body, 'RShift': named_tgt, 'BitOr': aug_tgt, 'BitXor': dict_vals, 'BitAnd': bin_left}
        label = type(node.op).__name__
        bytecode = [pack('BB', VM_STORE_NAME, ann_tgt[label])]
        bytecode.append(self.visit(node.left))
        bytecode.append(self.visit(node.right))
        return b''.join(bytecode)

    def visit_Compare(self, node):
        ann_tgt = {'Eq': bytes([left_ops]), 'NotEq': bytes([right_ops]), 'Lt': bytes([VM_BYTE_GET_ITER]), 'LtE': bytes([cmp_ops]), 'Gt': bytes([ops_list]), 'GtE': bytes([op_entry]), 'Is': bytes([kw_args]), 'IsNot': bytes([kw_key]), 'In': bytes([op_node]), 'NotIn': bytes([star_args])}
        ann_val = [self.visit(node.left)]
        for (match_var, match_pattern) in zip(node.ops, node.comparators):
            ann_val.append(ann_tgt[type(match_var).__name__])
            ann_val.append(self.visit(match_pattern))
        ann_val.append(VM_BYTE_LOAD_CONST)
        body = b''.join(ann_val)
        return self._make_ins(VM_LOAD_NAME, len(body)) + body

    def visit_Starred(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Load)):
            return VM_BYTE_STORE_NAME + self.visit(node.value)
        raise NotImplementedError(ast.unparse(node))

    def visit_Attribute(self, node):
        idx = self.f_consts.index(node.attr)
        if isinstance(node.ctx, ast.Del):
            return self._make_ins(VM_JUMP_IF_FALSE_OR_POP, idx)
        elif isinstance(node.ctx, ast.Store):
            return b''.join([self._make_ins(VM_COMPARE_LE, idx), self.visit(node.value)])
        else:
            return b''.join([self._make_ins(VM_DELETE_FAST, idx), self.visit(node.value)])

    def visit_Slice(self, node):
        bytecode = [VM_BYTE_LOAD_NAME]
        for field in ('lower', 'upper', 'step'):
            block_list = getattr(node, field, None)
            bytecode.append(VM_NONE_ARG if block_list is None else self.visit(block_list))
        return b''.join(bytecode)

    def visit_Subscript(self, node):
        return b''.join([VM_BYTE_LOAD_ATTR if isinstance(node.ctx, ast.Load) else VM_BYTE_BUILD_TUPLE if isinstance(node.ctx, ast.Store) else VM_BYTE_UNPACK, self.visit(node.slice), self.visit(node.value)])

    def visit_IfExp(self, node):
        slice_lower = self.visit(node.test)
        body = self.visit(node.body)
        slice_upper = self.visit(node.orelse)
        slice_step = self._make_jmp_ins(len(slice_upper))
        offset = len(body) + len(slice_step)
        bytecode = self._make_ins(VM_BINARY_DIVIDE, offset)
        return b''.join([bytecode, slice_lower, body, slice_step, slice_upper])

    def visit_Dict(self, node):
        sub_value = [self.visit(item) if item else VM_NONE_ARG for item in node.keys]
        call_func = [self.visit(item) for item in node.values]
        body = b''.join([cmp_reg + block_list for (cmp_reg, block_list) in zip(sub_value, call_func)])
        return b''.join([VM_BYTE_STORE_ATTR, body, VM_NONE_ARG, VM_NONE_ARG] if any([item is None for item in node.keys]) else [self._make_ins(VM_CALL_FUNCTION_EX, len(node.keys)), body])

    def visit_Set(self, node):
        body = b''.join([self.visit(item) for item in node.elts])
        return b''.join([VM_BYTE_SUBSCR, body, VM_NONE_ARG] if any([isinstance(item, ast.Starred) for item in node.elts]) else [self._make_ins(VM_UNARY_NEGATIVE, len(node.elts)), body])

    def visit_List(self, node):
        body = b''.join([self.visit(item) for item in node.elts])
        return b''.join([VM_BYTE_STORE_SUBSCR, body, VM_NONE_ARG] if any([isinstance(item, ast.Starred) for item in node.elts]) else [self._make_ins(VM_CALL_FUNCTION, len(node.elts)), body])

    def visit_Tuple(self, node):
        body = b''.join([self.visit(item) for item in node.elts])
        return b''.join([VM_BYTE_CALL_FUNCTION, body, VM_NONE_ARG] if any([isinstance(item, ast.Starred) for item in node.elts]) else [self._make_ins(VM_STORE_DEREF, len(node.elts)), body])

    def visit_comprehension(self, comprehension):
        assert not comprehension.is_async
        comp_type = comprehension.ifs
        if comp_type:
            body = b''.join([self.visit(item) for item in comp_type])
            slice_lower = b''.join([self._make_ins(VM_STORE_ATTR, len(body) + 1), body, VM_NONE_ARG]) if len(comp_type) > 1 else body
        else:
            slice_lower = VM_BYTE_LOAD_CONST
        return b''.join([self.visit(comprehension.iter), self._make_store_target(comprehension.target), slice_lower])

    def _build_xxxxcomp(self, node, comp_node):
        comp_result = b''.join([self.visit_comprehension(item) for item in node.generators])
        if any([item.ifs for item in node.generators]):
            body = b''.join([comp_result, VM_NONE_ARG, self.visit(node.elt)])
            return b''.join([self._make_ins(comp_node, len(body)), body])
        return b''.join([self._make_ins(comp_node, 0), comp_result, VM_NONE_ARG, self.visit(node.elt)])

    def visit_ListComp(self, node):
        return self._build_xxxxcomp(node, VM_UNARY_INVERT)

    def visit_SetComp(self, node):
        return self._build_xxxxcomp(node, VM_BINARY_SUBTRACT)

    def visit_DictComp(self, node):
        comp_result = b''.join([self.visit_comprehension(item) for item in node.generators])
        if any([item.ifs for item in node.generators]):
            body = b''.join([comp_result, VM_NONE_ARG, self.visit(node.key), self.visit(node.value)])
            return b''.join([self._make_ins(VM_BINARY_ADD, len(body)), body])
        return b''.join([self._make_ins(VM_BINARY_ADD, 0), comp_result, VM_NONE_ARG, self.visit(node.key), self.visit(node.value)])

    def visit_GeneratorExp(self, node):
        return self._build_xxxxcomp(node, VM_BINARY_MULTIPLY)

    def visit_JoinedStr(self, node):
        bytecode = [self._make_ins(VM_BINARY_FLOOR_DIVIDE, len(node.values))]
        bytecode.extend([b''.join([self.visit(item), b'\x00']) if isinstance(item, ast.Constant) else self.visit(item) for item in node.values])
        return b''.join(bytecode)

    def visit_FormattedValue(self, node):
        gen_expr = node.conversion
        joined_parts = node.format_spec
        return b''.join([self.visit(node.value), b'\xff' if gen_expr == -1 else pack('B', gen_expr), self.visit(joined_parts) if joined_parts else VM_NONE_ARG])

    def visit_TemplateStr(self, node):
        return self.visit_JoinedStr(node)

    def visit_Interpolation(self, node):
        return self.visit_FormattedValue(node)

    def visit_Assign(self, node):
        value = self.visit(node.value)
        interp_node = b''.join([self._make_store_target(item) for item in node.targets])
        return b''.join([VM_BYTE_UNARY_OP, value, interp_node, VM_NONE_ARG])

    def visit_AugAssign(self, node):
        ann_tgt = {'Add': bytes([if_body]), 'Sub': bytes([handler]), 'Mult': bytes([for_body]), 'Div': bytes([except_type]), 'Mod': bytes([try_body]), 'FloorDiv': bytes([for_target]), 'MatMult': bytes([list_elts]), 'Pow': bytes([while_body]), 'LShift': bytes([for_iter]), 'RShift': bytes([handlers]), 'BitOr': bytes([while_test]), 'BitXor': bytes([except_name]), 'BitAnd': bytes([if_else])}
        template_str = self.visit(node.value)
        node.target.ctx = ast.Load()
        type_alias = self.visit(node.target)
        node.target.ctx = ast.Store()
        attr_node = self.visit(node.target)
        label = type(node.op).__name__
        return b''.join([VM_BYTE_UNARY_OP, VM_BYTE_BINARY_OP, ann_tgt[label], type_alias, template_str, attr_node, VM_NONE_ARG])

    def visit_AnnAssign(self, node):
        if node.value is None:
            return b''
        value = self.visit(node.value)
        attr_node = self.visit(node.target)
        return b''.join([VM_BYTE_UNARY_OP, value, attr_node, VM_NONE_ARG])

    def visit_NamedExpr(self, node):
        value = self.visit(node.value)
        attr_node = self.visit(node.target)
        return b''.join([VM_BYTE_UNARY_OP, value, attr_node, VM_NONE_ARG])

    def visit_Expr(self, node):
        return self.visit(node.value)

    def visit_If(self, node):
        slice_lower = self.visit(node.test)
        body = b''.join([self.visit(item) for item in node.body])
        if node.orelse:
            slice_upper = b''.join([self.visit(item) for item in node.orelse])
            slice_step = self._make_jmp_ins(len(slice_upper))
        else:
            (slice_step, slice_upper) = (b'', b'')
        assert_test = self._make_jmp_ins(len(body) + len(slice_step))
        return b''.join([VM_BYTE_COMPARE_OP, slice_lower, assert_test, body, slice_step, slice_upper])

    def visit_For(self, node):
        """"""
        raise_exc = self._make_store_target(node.target)
        delete_tgt = self.visit(node.iter)
        body = b''.join([self.visit(item) for item in node.body])
        slice_upper = b''.join([self.visit(item) for item in node.orelse]) if node.orelse else b''
        jump_bytes = bytes([VM_JUMP_ABSOLUTE, 1])
        global_names = len(raise_exc) + len(body) + len(jump_bytes)
        nonlocal_names = len(slice_upper)
        return b''.join([self._make_loop_ins(VM_GET_ITER, global_names, nonlocal_names), delete_tgt, raise_exc, body, jump_bytes, slice_upper])

    def visit_While(self, node):
        """"""
        slice_lower = self.visit(node.test)
        body = b''.join([self.visit(item) for item in node.body])
        jump_bytes = bytes([VM_JUMP_ABSOLUTE, 1])
        slice_upper = b''.join([self.visit(item) for item in node.orelse]) if node.orelse else b''
        global_names = len(slice_lower) + len(body) + len(jump_bytes)
        nonlocal_names = len(slice_upper)
        return b''.join([self._make_loop_ins(VM_FOR_ITER, global_names, nonlocal_names), slice_lower, body, jump_bytes, slice_upper])

    def visit_Break(self, node):
        return pack('BB', VM_JUMP_ABSOLUTE, 255)

    def visit_Continue(self, node):
        return pack('BB', VM_JUMP_ABSOLUTE, 1)

    def visit_Pass(self, node):
        return b''

    def visit_Delete(self, node):
        return b''.join([self.visit(item) for item in node.targets])

    def visit_Raise(self, node):
        raise NotImplementedError(ast.unparse(node))

    def visit_Try(self, node):
        raise NotImplementedError(ast.unparse(node))

    def visit_With(self, node):
        raise NotImplementedError(ast.unparse(node))

    def visit_Return(self, node):
        raise NotImplementedError(ast.unparse(node))

    def visit_TypeAlias(self, node):
        return b''

    def visit_Assert(self, node):
        return b''

# =============================================================================
# Global Name Collector - Collects global/nonlocal/import names from AST
# =============================================================================
class GlobalNameCollector(ast.NodeVisitor):
    """"""

    def __init__(self):
        self.names = set()
        self.ext_globals = set()
        self.non_locals = set()

    def _clear(self):
        self.names.clear()
        self.ext_globals.clear()
        self.non_locals.clear()

    def get_globals(self, node):
        """"""
        self._clear()
        self.visit(node)
        return self.names

    def get_names(self, node):
        """"""
        self._clear()
        result = node.args
        for name in result.posonlyargs + result.args + result.kwonlyargs:
            self.names.add(name.arg)
        if result.vararg:
            self.names.add(result.vararg.arg)
        if result.kwarg:
            self.names.add(result.kwarg.arg)
        for name in node.body:
            self.visit(name)
        return self.names

    def visit_ClassDef(self, node):
        self.names.add(node.name)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node):
        self.names.add(node.name)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node):
        for name in node.names:
            self.names.add(name.asname if name.asname else name.name)

    def visit_ImportFrom(self, node):
        for name in node.names:
            self.names.add(name.asname if name.asname else name.name)

    def visit_Global(self, node):
        self.names.difference_update(node.names)
        self.ext_globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.names.difference_update(node.names)
        self.non_locals.update(node.names)

# =============================================================================
# VM Code Emitter - Emits VM bytecode instructions from Python AST
# =============================================================================
class VMCodeEmitter(ast.NodeTransformer):
    ECC_VAR = '_pyarmor_ecc_var'
    ECC_CONSTS = ()
    (F_INIT_INDEX, F_VMM_INDEX) = (1, 2)
    F_BUILTINS = []
    F_NOT_NODES = (ast.ClassDef, ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith, ast.Return, ast.Yield, ast.YieldFrom, ast.Try, ast.With, ast.Raise, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)

    def __init__(self):
        self.counter = 0
        self.stack = []
        self.f_globals = []
        self.f_builtins = []
        self.f_blocks = {}
        self.not_node_types = self.F_NOT_NODES + tuple([getattr(ast, item) for item in ('Match', 'TryStar') if hasattr(ast, item)])

    @property
    def f_consts(self):
        """"""
        if self.stack:
            return self.stack[-1].f_consts

    @property
    def f_names(self):
        """"""
        if self.stack:
            return self.stack[-1].f_names

    @property
    def f_localvars(self):
        """"""
        if self.stack:
            return self.stack[-1].f_localvars

    @property
    def f_freevars(self):
        """"""
        if self.stack:
            return self.stack[-1].f_freevars

    def push_const(self, value):
        if self.stack:
            scope_stack = self.stack[-1].f_consts
            if value not in scope_stack:
                scope_stack.append(value)

    def init_module(self, node):
        if not self.F_BUILTINS:
            import builtins
            self.F_BUILTINS = dir(builtins)
        self.f_builtins.extend(self.F_BUILTINS)
        self.f_globals.extend(GlobalNameCollector().get_globals(node))

    def init_func(self, node):
        """"""
        self.f_names[:] = GlobalNameCollector().get_names(node)

    def enter_scope(self, node):
        self.stack.append(VmcStackItem(node, f_names=[], f_consts=[], f_localvars=set(), f_freevars=set()))

    def exit_scope(self):
        self.stack.pop()

    def is_localvar(self, name):
        if self.stack:
            return name in self.stack[-1].f_names

    def is_freevar(self, name):
        """"""
        for result in reversed(self.stack[:-1]):
            if name in result.f_names:
                return True

    def is_global(self, item):
        return not (self.is_localvar(item) or self.is_freevar(item))

    def is_builtin(self, item):
        return item not in self.f_globals and item in self.f_builtins

    def _get_module_start(self, node):
        n = False if ast.get_docstring(node) else 0
        for scope_data in iter(node.body):
            if n is False:
                n = 1
            elif isinstance(scope_data, ast.ImportFrom) and scope_data.module == '__future__':
                n += 1
            else:
                break
        return n

    def has_difficult_node(self, node):
        """"""
        for item in ast.walk(node):
            if isinstance(item, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return getattr(item.generators[0], 'is_async', 0)
            if isinstance(item, self.not_node_types):
                return True

    def map_block(self, block_node, stmt=True):
        """"""
        self.counter += 1
        stmt = '__pyarmor_ecc_code_block_%d__' % self.counter
        for scope_data in block_node:
            for item in ast.walk(scope_data):
                if isinstance(item, ast.Constant):
                    self.push_const(item.value)
                elif isinstance(item, ast.Attribute):
                    self.push_const(item.attr)
                elif isinstance(item, ast.Name):
                    if self.is_freevar(item.id):
                        self.f_freevars.add(item.id)
                    elif self.is_global(item.id):
                        self.push_const(item.id)
                    elif isinstance(item.ctx, ast.Store):
                        self.f_localvars.add(item.id)
                elif isinstance(item, ast.keyword):
                    if item.arg:
                        self.push_const(item.arg)
        self.f_blocks[stmt] = VmcBlockItem(block_node, self.f_consts) if stmt else VmcExprItem(block_node[0], self.f_consts)
        expr_node = ast.Call(func=ast.Subscript(value=ast.Constant(value=self.ECC_CONSTS), slice=ast.Constant(value=self.F_VMM_INDEX), ctx=ast.Load()), args=[ast.Tuple(elts=[ast.Name(id=self.ECC_VAR, ctx=ast.Load()), ast.Constant(value=stmt)], ctx=ast.Load())], keywords=[])
        return ast.Expr(value=expr_node) if stmt else expr_node

    def fix_header(self, node, n):
        """"""
        arg_list = tuple(self.f_consts) if self.f_consts else None
        body_node = [ast.Assign(targets=[ast.Name(id=self.ECC_VAR, ctx=ast.Store())], value=ast.Call(func=ast.Subscript(value=ast.Constant(value=self.ECC_CONSTS), slice=ast.Constant(value=self.F_INIT_INDEX), ctx=ast.Load()), args=[ast.Constant(value=arg_list)], keywords=[]))]
        if self.f_freevars or self.f_localvars:
            test_node = ast.Tuple(elts=[ast.Name(id=item, ctx=ast.Load()) for item in self.f_freevars], ctx=ast.Load()) if self.f_freevars else ast.List(elts=[], ctx=ast.Load())
            iter_node = ast.Tuple(elts=[ast.Name(id=item, ctx=ast.Store()) for item in self.f_localvars], ctx=ast.Store()) if self.f_localvars else ast.Name(id=self.ECC_VAR, ctx=ast.Store())
            body_node.append(ast.If(test=ast.UnaryOp(op=ast.Not(), operand=ast.Name(id=self.ECC_VAR, ctx=ast.Load())), body=[ast.Assign(targets=[iter_node], value=test_node)], orelse=[]))
        node.body[n:n] = body_node

    def visit_ClassDef(self, node):
        self.enter_scope(node)
        handler_node = (ast.FunctionDef, ast.ClassDef)
        node.body = [self.visit(scope_data) if isinstance(scope_data, handler_node) else scope_data for scope_data in iter(node.body)]
        self.exit_scope()
        return node

    def _handle_body(self, body_node, start=0):
        assert isinstance(body_node, list)
        ctx_node = iter(body_node)
        body = [next(ctx_node) for i in range(start)]
        block_node = []
        for scope_data in ctx_node:
            if self.has_difficult_node(scope_data):
                if block_node:
                    body.append(self.map_block(block_node))
                    block_node = []
                body.append(self.visit(scope_data))
            else:
                block_node.append(scope_data)
        if block_node:
            body.append(self.map_block(block_node))
        return body

    def _handle_expr(self, node):
        return None if node is None else node if self.has_difficult_node(node) else self.map_block([node], stmt=False)

    def visit_Module(self, node):
        self.init_module(node)
        self.enter_scope(node)
        n = self._get_module_start(node)
        node.body = self._handle_body(node.body, n)
        self.fix_header(node, n)
        self.exit_scope()
        return node

    def visit_FunctionDef(self, node):
        self.enter_scope(node)
        self.init_func(node)
        n = 1 if ast.get_docstring(node) else 0
        node.body = self._handle_body(node.body, n)
        self.fix_header(node, n)
        self.exit_scope()
        return node

    def visit_Constant(self, node):
        """"""
        value = node.value
        if isinstance(value, tuple) and len(value) == 0:
            return ast.Call(func=ast.Name(id='tuple', ctx=ast.Load()), args=[ast.List(elts=[], ctx=ast.Load())], keywords=[])
        return node

    def visit_If(self, node):
        node.test = self._handle_expr(node.test)
        node.body = self._handle_body(node.body)
        node.orelse = self._handle_body(node.orelse)
        return node

    def visit_Return(self, node):
        node.value = self._handle_expr(node.value)
        return node

    def visit_Try(self, node):
        node.body = self._handle_body(node.body)
        for func_node in node.handlers:
            func_node.body = self._handle_body(func_node.body)
        node.orelse = self._handle_body(node.orelse)
        node.finalbody = self._handle_body(node.finalbody)
        return node

    def visit_TryStar(self, node):
        return self.visit_Try(node)

    def visit_With(self, node):
        node.body = self._handle_body(node.body)
        return node

    def visit_match_case(self, node):
        node.body = self._handle_body(node.body)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_AsyncFor(self, node):
        return self.visit_For(node)

    def visit_AsyncWith(self, node):
        return self.visit_With(node)
header_data = Template('$shebang# Pyarmor VMC $rev, requires: pyarmor_mini >= 3.0\nfrom $pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, $body, 2)')

# Serialize an obfuscated script object to bytes
def serialize_script(tree, **options):
    compiler = VMCodeEmitter()
    compiler.visit(tree)
    ast.fix_missing_locations(tree)
    return compiler.f_blocks

# Deserialize script header from bytes (magic + version check)
def deserialize_script_header(data, miver=1, head=32, cindex=0):
    iv = len(data)
    padded_size = head
    module_data = 0
    n2 = pack('<7sBBB6xIIII', b'PYARVMC', miver, *sys.version_info[:2], padded_size, iv, cindex, module_data)
    return n2

# Full deserialize of an obfuscated script from bytes
def deserialize_script(co, miver=1, head=32, cindex=0):
    jit_data = marshal_dumps(co)
    n2 = deserialize_script_header(jit_data, miver, head, cindex)
    return n2 + jit_data

# Get BCC (Built-in C Compiler) compilation options
def get_bcc_options():
    try:
        from pyarmor.mini.pyarmor_mini import __pyarmor__ as builder
        return builder
    except ModuleNotFoundError:
        raise RuntimeError('please install pyarmor.mini package')

# Create a BCC wrapper function for the obfuscated code
def make_bcc_wrapper(co, vmc_blocks):
    inner_func = get_bcc_options()

    def inner_wrapper(*arg_list):
        return inner_func(arg_list, b'', -1)
    block = type(co)
    jump_target = (None, None, None, None)
    items = VMCodeEmitter.ECC_CONSTS
    consts = '__pyarmor_ecc_code_block_'
    item_data = VMCCompiler().build_vmcode

    def compiler2(co):
        compiled = list(co.co_consts)
        size = 0
        for item in co.co_consts:
            if isinstance(item, block):
                compiler2(item)
            elif isinstance(item, str) and item.startswith(consts):
                compiled[size] = item_data(co, vmc_blocks[item])
            elif item is items:
                compiled[size] = jump_target
            size += 1
        inner_wrapper(co, co.co_consts, tuple(compiled))
    compiler2(co)

# Build VMC (Virtual Machine Code) compiled blocks from script
def vmc_build(platform, hook_name, output_dir, **options):
    wrapper_code = os.path.join(output_dir, platform)
    vmc_blocks = serialize_script(hook_name)
    if options.get('debug'):
        with open(wrapper_code.replace('.py', '.rft.py'), 'w') as suffix:
            suffix.write(ast.unparse(hook_name))
    enter_func = options.get('optimize', -1)
    exit_func = '<frozen %s>' % platform
    co = compile(hook_name, exit_func, 'exec', optimize=enter_func)
    enter_code = co.co_consts.index(VMCodeEmitter.ECC_CONSTS)
    make_bcc_wrapper(co, vmc_blocks)
    exit_code = options.get('rev', 1)
    body = deserialize_script(co, miver=exit_code, cindex=enter_code)
    os.makedirs(os.path.dirname(wrapper_code), exist_ok=True)
    with open(wrapper_code, 'w') as suffix:
        suffix.write(header_data.substitute(shebang=options.get('shebang', ''), pyarmor_mini=options.get('mini_import_from', 'pyarmor_mini'), rev=exit_code, body=repr(body)))
import ast as i
import dis as j
import logging as k
import logging.config
import os as n
import marshal as size
import struct as offset
import sys as length
from string import Template as data
result = data('$shebang# Pyarmor MINI $rev, requires: pyarmor_mini >= 1.0\nfrom $pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, $body)')
header = {'builtins': (b'\xb7S,?~\xfa\xbe\xa2\x97\xd0\xd5\xd9g\x04\xdcl', b'\x96\xaf\xd2\xfa\xcc\x97\xe3\x01\xceYQ\xbf\xb9\xc3\x98', b'\xd1\xb4\t\x0e\xb7Y\x83\xec\xa7\x04\xec\x95\x8cj\xfc'), 'keyiv': None}
version = logging.getLogger('cli.mini')

# [Mini] Generate random bytes for padding
def mini_generate_random_bytes(n=16):
    from random import randrange as magic
    return [magic(1, 255) for flags in range(n)]

# [Mini] Deserialize script header
def mini_deserialize_header(mini_data, miver=1, head=80, cindex=0):
    value = [len(mini_code_obj) for mini_code_obj in header['builtins']]
    encoded = len(mini_data)
    decoded = head + sum(value)
    chunk = 0
    chunks = header['keyiv']
    buffer = offset.pack('<7sBBBBBBBBBIIII48s', b'PYARMIN', miver, *length.version_info[:2], head, head + value[0], head + value[0] + value[1], *value, decoded, encoded, cindex, chunk, chunks)
    return buffer

# [Mini] Deserialize full script
def mini_deserialize_script(mini_code_obj2, miver=1, head=80, cindex=0):
    block = size.dumps(mini_code_obj2)
    buffer = mini_deserialize_header(block, miver, head, cindex)
    version.debug('header size is %d', len(buffer))
    return buffer + b''.join(header['builtins']) + block

# [Mini] Create BCC wrapper
def mini_make_bcc_wrapper(mini_code_obj2, mini_key_data):
    key = type(mini_code_obj2)
    iv = j.opmap['LOAD_CONST']
    cipher = j.opmap['BUILD_LIST']
    plain = j.opmap['NOP']

    def _mini_bcc_inner(mini_code_obj2):
        encrypted = bytearray(mini_code_obj2.co_code)
        padded = j.get_instructions(mini_code_obj2)
        for pad_len in padded:
            if pad_len.opcode == iv and pad_len.argval == mini_key_data:
                for pad_len in padded:
                    if pad_len.opcode == cipher and pad_len.arg == 1:
                        seed = pad_len.offset
                        encrypted[seed:seed + 2] = (plain, 0)
                        break
        [_mini_bcc_inner(mini_code_obj) for mini_code_obj in mini_code_obj2.co_consts if isinstance(mini_code_obj, key)]
    _mini_bcc_inner(mini_code_obj2)

# [Mini] Get BCC options
def mini_get_bcc_options():
    try:
        from pyarmor.mini.pyarmor_mini import __pyarmor__ as mode
        return mode
    except ModuleNotFoundError:
        raise RuntimeError('please install pyarmor.mini package')

# [Mini] Call BCC compiled function
def mini_bcc_call(mini_code_obj2, mini_bcc_func):
    mode = mini_get_bcc_options()
    return mode((mini_code_obj2, mini_code_obj2.co_consts, mini_bcc_func), b'', -1)

# [Mini] Encrypt data with key
def mini_encrypt_data(mini_plaintext, ptlen=16):
    mode = mini_get_bcc_options()
    buffer = mini_deserialize_header('')
    mini_data = mini_plaintext.encode('utf-8') if isinstance(mini_plaintext, str) else mini_plaintext
    script_obj = len(mini_data) & ptlen - 1
    script_obj = ptlen - script_obj if script_obj else 0
    mtree = bytes(mini_generate_random_bytes(script_obj))
    return mode(bytes([script_obj]) + mini_data + mtree, buffer, -2)

# [Mini] Obfuscate a script (lightweight path)
def mini_obfuscate_script(mini_code_obj2):
    import builtins as entry
    path = j.opmap['LOAD_GLOBAL']
    key = type(mini_code_obj2)
    output_dir = dir(entry)
    options = []

    def _mini_obfuscate_inner(mini_code_obj2):
        for pad_len in j.get_instructions(mini_code_obj2):
            if pad_len.opcode == path:
                if pad_len.argval in output_dir:
                    options.append(pad_len.argval)
        [_mini_obfuscate_inner(mini_code_obj) for mini_code_obj in mini_code_obj2.co_consts if isinstance(mini_code_obj, key)]
    _mini_obfuscate_inner(mini_code_obj2)
    return set(options)

# [Mini] Serialize obfuscated script to bytes
def mini_serialize_script(mini_script, **mini_options):
    mini_code_obj2 = compile(mini_script, '<str>', 'exec')
    flag = mini_options.get('mini_rft_builtin', 1)
    item = mini_options.get('mini_rft_setattr', 0)
    name = mini_options.get('mini_rft_getattr', 0)
    func = mini_options.get('mini_rft_import', 1)
    code = mini_options.get('mini_rft_str', 0)
    co_consts = list(mini_obfuscate_script(mini_code_obj2)) if flag else []
    version.debug('got bulitins: %s', co_consts)
    co_names = tuple([mini_encrypt_data(mini_code_obj) for mini_code_obj in co_consts])
    co_names += header['builtins']
    co_code = i.List(elts=[i.Constant(value=co_names)], ctx=i.Load())
    if not mini_options.get('advanced', None):
        co_code = i.Subscript(value=co_code, slice=i.Constant(value=0), ctx=i.Load())

    def _mini_serialize_inner(mini_code_obj):
        return mini_code_obj.id in co_consts and isinstance(mini_code_obj.ctx, i.Load)

    class MiniTreeTransformer(i.NodeTransformer):

        def visit_Name(self, node):
            if _mini_serialize_inner(node):
                version.debug('line %d: reform builtin "%s"', node.lineno, node.id)
                source = co_consts.index(node.id)
                encoding = i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=node.ctx)
                i.copy_location(encoding, node)
                return encoding
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str):
                if not code:
                    return node
                version.debug('line %d: protect str "%s"', node.lineno, node.value)
                source = len(co_consts)
                tree = mini_encrypt_data(node.value)
                encoding = i.Call(func=i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=i.Load()), args=[i.Constant(value=tree)], keywords=[])
                i.copy_location(encoding, node)
                return encoding
            elif isinstance(node.value, (int, float)):
                pass
            return node

        def visit_Attribute(self, node):
            if isinstance(node.ctx, i.Store) or not name:
                return node
            version.debug('line %d: attr "%s"', node.lineno, node.attr)
            source = len(co_consts) + 1
            compiled = mini_encrypt_data(node.attr)
            compiled2 = [node.value, i.Constant(value=compiled)]
            encoding = i.Call(func=i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=i.Load()), args=[i.Tuple(elts=compiled2, ctx=i.Load())], keywords=[])
            i.copy_location(encoding, node)
            return encoding

        def visit_Assign(self, node):
            if not item:
                return node
            if isinstance(node.targets[0], i.Attribute):
                source = len(co_consts) + 1
                bcc_data = node.targets[0]
                compiled = mini_encrypt_data(bcc_data.attr)
                compiled2 = [bcc_data.value, i.Constant(value=compiled), node.value]
                encoding = i.Call(func=i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=i.Load()), args=[i.Tuple(elts=compiled2, ctx=i.Load())], keywords=[])
                i.copy_location(encoding, node)
                return encoding
            return node

        def visit_Import(self, node):
            if not func:
                return node
            bcc_func = ', '.join([mini_code_obj.name for mini_code_obj in node.names])
            version.debug('line %d: import "%s"', node.lineno, bcc_func)

            def obfuscated(bcc_result):
                mini_data = b'\x01' + bcc_result.encode('utf-8') + b'\x00\x00'
                return mini_encrypt_data(mini_data)
            source = len(co_consts) + 2
            serialized = [i.Call(func=i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=i.Load()), args=[i.Constant(value=obfuscated(mini_code_obj.name))], keywords=[]) for mini_code_obj in node.names]
            deserialized = i.Store()
            co = [mini_code_obj.asname if mini_code_obj.asname else mini_code_obj.name for mini_code_obj in node.names]
            pkg_name = [i.Name(id=mini_code_obj, ctx=deserialized) for mini_code_obj in co]
            mod_name = len(pkg_name) > 1
            if mod_name:
                pkg_name = [i.Tuple(elts=pkg_name, ctx=deserialized)]
                serialized = i.Tuple(elts=serialized, ctx=i.Load())
            encoding = i.Assign(targets=pkg_name, value=serialized if mod_name else serialized[0])
            i.copy_location(encoding, node)
            return encoding

        def visit_ImportFrom(self, node):
            if not func:
                return node
            version.debug('line %d: import from "%s"', node.lineno, node.module)
            source = len(co_consts) + 2
            filename = len(node.names)
            bcc_func = [mini_code_obj.name.encode('utf-8') for mini_code_obj in node.names]
            fullname = [bytes([len(mini_code_obj)]) for mini_code_obj in bcc_func]
            mod_list = node.module if node.module else ''
            mini_data = offset.pack('<BHH', 2, filename, node.level) + b''.join([mod_info + script_data for (mod_info, script_data) in zip(fullname, bcc_func)]) + mod_list.encode('utf-8') + bytes([0, 0])
            deserialized = i.Store()
            co = [mini_code_obj.asname if mini_code_obj.asname else mini_code_obj.name for mini_code_obj in node.names]
            pkg_name = [i.Name(id=mini_code_obj, ctx=deserialized) for mini_code_obj in co]
            encoding = i.Assign(targets=[i.Tuple(elts=pkg_name, ctx=deserialized)], value=i.Call(func=i.Subscript(value=co_code, slice=i.Constant(value=source), ctx=i.Load()), args=[i.Constant(value=mini_encrypt_data(mini_data))], keywords=[]))
            i.copy_location(encoding, node)
            return encoding
    MiniTreeTransformer().visit(mini_script)
    i.fix_missing_locations(mini_script)
    return co_names

# Mini build mode - lightweight obfuscation without full pipeline
def mini_build(filename, mtree, output, **mini_options):
    if header['keyiv'] is None:
        header['keyiv'] = bytes(mini_generate_random_bytes(48))
    output_path = n.path.join(output, filename)
    co_names = mini_serialize_script(mtree, **mini_options)
    if mini_options.get('debug'):
        with open(output_path + '.rft', 'w') as outfile:
            outfile.write(i.unparse(mtree))
    optimize_level = mini_options.get('optimize', -1)
    compile_filename = '<frozen %s>' % filename
    mini_code_obj2 = compile(mtree, compile_filename, 'exec', optimize=optimize_level)
    if co_names not in mini_code_obj2.co_consts:
        version.info('append builtins to co_consts')
        all_consts = mini_code_obj2.co_consts + (co_names,)
        if mini_bcc_call(mini_code_obj2, all_consts) is None:
            version.error('patch co_consts failed')
            return
    cindex = mini_code_obj2.co_consts.index(co_names)
    version.debug('find cindex: %d', cindex)
    mini_make_bcc_wrapper(mini_code_obj2, co_names)
    miver = mini_options.get('rev', 1)
    deserialized = mini_deserialize_script(mini_code_obj2, miver=miver, cindex=cindex)
    version.info('save obfuscated script %s', output_path)
    n.makedirs(n.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as outfile:
        outfile.write(result.substitute(shebang=mini_options.get('shebang', ''), pyarmor_mini=mini_options.get('mini_import_from', 'pyarmor_mini'), rev=miver, body=repr(deserialized)))