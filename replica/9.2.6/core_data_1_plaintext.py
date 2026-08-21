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
pyarmor_core_1 = {}

def pyarmor_core_2(n=16):
    return [randrange(1, 255) for pyarmor_core_3 in range(n)]

def pyarmor_core_4(refsize=32768):
    from ctypes import PyDLL, cast, c_void_p, string_at
    from hashlib import md5
    pyarmor_core_5 = PyDLL(None)
    pyarmor_core_6 = []
    for pyarmor_core_7 in ('PyParser_New', 'PyToken_OneChar', 'Py_IncRef', 'Py_Main', 'Py_RunMain', 'Py_Finalize', 'Py_FinalizeEx'):
        if hasattr(pyarmor_core_5, pyarmor_core_7):
            pyarmor_core_6.append(cast(getattr(pyarmor_core_5, pyarmor_core_7), c_void_p).value)
    pyarmor_core_6.sort()
    pyarmor_core_8 = cast(pyarmor_core_5.PyEval_EvalFrame, c_void_p).value
    pyarmor_core_9 = min(pyarmor_core_8 - refsize, pyarmor_core_6[0])
    pyarmor_core_10 = max(pyarmor_core_8 + refsize, pyarmor_core_6[-1])
    return ' '.join(['PyEval_EvalFrame', str(pyarmor_core_8 - pyarmor_core_9), str(pyarmor_core_10 - pyarmor_core_8), md5(string_at(pyarmor_core_9, pyarmor_core_10)).hexdigest()])

def pyarmor_core_12(pyarmor_core_11):
    (pyarmor_core_13, pyarmor_core_14, pyarmor_core_15) = unpack('III', pyarmor_core_11[40:52])
    if pyarmor_core_14:
        pyarmor_core_16 = 64 + pyarmor_core_13
        (pyarmor_core_17, pyarmor_core_18) = unpack('<BI', pyarmor_core_11[pyarmor_core_16:pyarmor_core_16 + 5])
        if pyarmor_core_17 == 0:
            pyarmor_core_18 &= 16777215
            pyarmor_core_19 = bytearray(pyarmor_core_11)
            pyarmor_core_19[pyarmor_core_16] = 1
            pyarmor_core_3 = 64 + pyarmor_core_15 + pyarmor_core_18
            pyarmor_core_20 = 64 + pyarmor_core_13 + 4 + pyarmor_core_18
            while pyarmor_core_18:
                pyarmor_core_18 -= 1
                pyarmor_core_3 -= 1
                pyarmor_core_20 -= 1
                pyarmor_core_19[pyarmor_core_3] ^= pyarmor_core_19[pyarmor_core_20]
            return bytes(pyarmor_core_19)
    return pyarmor_core_11

class pyarmor_core_21(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def _pack_message_lang(pyarmor_core_22, pyarmor_core_24, lang=''):
        pyarmor_core_25 = '' if lang == '' else '.' + lang
        pyarmor_core_26 = pyarmor_core_24['runtime.message' + pyarmor_core_25]
        pyarmor_core_27 = 3
        pyarmor_core_28 = [pack('BB5s', 7, pyarmor_core_27, lang.encode())]

        def pyarmor_core_31(pyarmor_core_27, pyarmor_core_29, pyarmor_core_30):
            pyarmor_core_32 = pyarmor_core_30.encode() + b'\x00'
            pyarmor_core_33 = len(pyarmor_core_32) + 2
            if pyarmor_core_33 > 255:
                raise CliError('too long message "%s"' % pyarmor_core_30)
            return pack('BB', pyarmor_core_33, pyarmor_core_27 | pyarmor_core_29 << 2) + pyarmor_core_32
        pyarmor_core_34 = ('init', 'import', 'load', 'run')
        pyarmor_core_27 = 1
        for pyarmor_core_3 in range(len(pyarmor_core_34)):
            pyarmor_core_35 = pyarmor_core_34[pyarmor_core_3] + '_error_format'
            pyarmor_core_30 = pyarmor_core_26.get(pyarmor_core_35, None)
            if pyarmor_core_30:
                pyarmor_core_28.append(pyarmor_core_31(pyarmor_core_27, pyarmor_core_3, pyarmor_core_30))
        pyarmor_core_36 = ('system', 'system', 'system', 'pyarmor', 'protect')
        pyarmor_core_27 = 2
        for pyarmor_core_3 in range(len(pyarmor_core_36)):
            pyarmor_core_35 = pyarmor_core_36[pyarmor_core_3] + '_error'
            pyarmor_core_30 = pyarmor_core_26.get(pyarmor_core_35, None)
            if pyarmor_core_30:
                pyarmor_core_28.append(pyarmor_core_31(pyarmor_core_27, pyarmor_core_3, pyarmor_core_30))
                pyarmor_core_28.append(pyarmor_core_31(pyarmor_core_27, pyarmor_core_3, pyarmor_core_30))
        pyarmor_core_27 = 0
        for pyarmor_core_35 in pyarmor_core_26:
            if pyarmor_core_35.startswith('error_'):
                pyarmor_core_29 = pyarmor_core_35[6:]
                if not pyarmor_core_29.isdecimal():
                    raise CliError('invalid option "%s"' % pyarmor_core_35)
                pyarmor_core_30 = pyarmor_core_26.get(pyarmor_core_35)
                pyarmor_core_28.append(pyarmor_core_31(pyarmor_core_27, int(pyarmor_core_29), pyarmor_core_30))
        return b''.join(pyarmor_core_28)

    def _pack_messages(pyarmor_core_22):
        pyarmor_core_24 = pyarmor_core_22.ctx.runtime_messages
        if not pyarmor_core_24 or not pyarmor_core_24.has_section('runtime.message'):
            return b'\x00'
        pyarmor_core_37 = pyarmor_core_24['runtime.message'].get('languages', '').split()
        pyarmor_core_37.append('')
        return b''.join([pyarmor_core_22._pack_message_lang(pyarmor_core_24, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_37])

    def _pack_interp_line(pyarmor_core_22, pyarmor_core_39):
        try:
            if pyarmor_core_39 == 'check-debugger':
                pyarmor_core_40 = 'D'
            elif pyarmor_core_39 == 'check-interp':
                pyarmor_core_40 = 'S'
                pyarmor_core_41 = pyarmor_core_4()
            elif pyarmor_core_39 == 'py:bootstrap':
                pyarmor_core_40 = 'B'
            else:
                (pyarmor_core_40, pyarmor_core_41) = pyarmor_core_39.split(':', 2)
            pyarmor_core_40 = pyarmor_core_40.encode()
            if pyarmor_core_40 == b'S':
                (pyarmor_core_7, pyarmor_core_9, pyarmor_core_10, pyarmor_core_42) = pyarmor_core_41.split()
                pyarmor_core_43 = pack('ii', int(pyarmor_core_9), int(pyarmor_core_10))
                pyarmor_core_44 = bytes.fromhex(pyarmor_core_42)
                return pyarmor_core_40 + pyarmor_core_7.encode() + b'\x00' + pyarmor_core_43 + pyarmor_core_44
            elif pyarmor_core_40 == b'D':
                return pyarmor_core_40
            elif pyarmor_core_40 == b'B':
                from marshal import dumps
                pyarmor_core_45 = pyarmor_core_22.ctx.runtime_hook('pyarmor_runtime')
                if pyarmor_core_45 is None:
                    raise CliError('no bootstrap script found')
                pyarmor_core_46 = compile(pyarmor_core_45, '<pyarmor_runtime>', 'exec')
                for pyarmor_core_38 in pyarmor_core_46.co_consts:
                    if type(pyarmor_core_38) == type(pyarmor_core_46) and pyarmor_core_38.co_name == 'bootstrap':
                        return pyarmor_core_40 + dumps(pyarmor_core_38)
                raise CliError('invalid bootstrap script')
        except (IndexError, ValueError) as pyarmor_core_47:
            logger.error('%s', str(pyarmor_core_47))
            raise CliError('invalid interp key "%s"' % pyarmor_core_39)

    def _pack_machine_line(pyarmor_core_22, pyarmor_core_39):
        pyarmor_core_48 = (('*MID:', re.compile('^[a-z][0-9a-fA-F]{32}$')), ('*IFMAC:', re.compile('^([0-9a-zA-Z]+/)?([0-9a-fA-F]{1,2}:){1,5}[0-9a-fA-F]{1,2}$')), ('*IFMAC:', re.compile('^<(([0-9a-fA-F]{1,2}:){2,6},?)+>$')), ('*IFIPV4:', re.compile('^([0-9]{1,3}\\.){3}[0-9]{1,3}$')), ('*DOMAIN:', re.compile('^\\{[a-zA-Z0-9.]+\\}$')), ('*HARDDISK:', re.compile('[a-zA-Z0-9_]{6,30}')))
        pyarmor_core_49 = []
        pyarmor_core_50 = pyarmor_core_39.split()
        pyarmor_core_33 = 0
        for pyarmor_core_38 in pyarmor_core_50:
            for (pyarmor_core_51, pyarmor_core_52) in pyarmor_core_48:
                if pyarmor_core_38.startswith(pyarmor_core_51):
                    pyarmor_core_49.append([pyarmor_core_51, pyarmor_core_38[len(pyarmor_core_51):].strip('{}')])
                    pyarmor_core_33 += 1
                    break
                elif pyarmor_core_52.search(pyarmor_core_38):
                    pyarmor_core_49.append([pyarmor_core_51, pyarmor_core_38.strip('{}')])
                    pyarmor_core_33 += 1
                    break
        if len(pyarmor_core_50) > pyarmor_core_33:
            raise CliError('invalid device info "%s"' % pyarmor_core_39)
        if pyarmor_core_33 > 1:
            pyarmor_core_53 = ('*MID:', '*HARDDISK:', '*IFMAC:', '*IFIPV4:', '*DOMAIN:')

            def pyarmor_core_55(pyarmor_core_54):
                return pyarmor_core_53.index(pyarmor_core_54[0])
            pyarmor_core_49.sort(key=pyarmor_core_55)
        return ''.join(sum(pyarmor_core_49, [])).encode('utf-8')

    def _pack_runtime_key(pyarmor_core_22, outer=None):
        pyarmor_core_23 = pyarmor_core_22.ctx
        pyarmor_core_56 = 0
        pyarmor_core_57 = b''
        pyarmor_core_58 = 2 if outer else 1 if pyarmor_core_22.ctx.runtime_outer else 0
        pyarmor_core_59 = pyarmor_core_22.ctx.outer_keyname if pyarmor_core_58 else ''
        pyarmor_core_60 = 0
        if pyarmor_core_59:
            pyarmor_core_60 = len(pyarmor_core_59)
            pyarmor_core_57 += pyarmor_core_59.encode('utf-8')
        pyarmor_core_57 += b'\x00'
        pyarmor_core_56 += 2
        pyarmor_core_61 = pyarmor_core_23.runtime_on_error
        if pyarmor_core_61:
            pyarmor_core_58 |= int(pyarmor_core_61) << pyarmor_core_56
        pyarmor_core_56 += 2
        pyarmor_core_62 = pyarmor_core_23.runtime_period
        if pyarmor_core_62 == -1:
            raise CliError('invalid period format "%s"' % pyarmor_core_62)
        elif pyarmor_core_62:
            if pyarmor_core_62 > pow(2, 20):
                raise CliError('period "%s" is overflow' % pyarmor_core_62)
            pyarmor_core_58 |= pyarmor_core_62 << pyarmor_core_56
        pyarmor_core_56 += 20
        pyarmor_core_63 = pyarmor_core_1['get_license_features'](pyarmor_core_1['self'], pyarmor_core_23)
        pyarmor_core_58 |= (0 if pyarmor_core_63 else 1) << pyarmor_core_56
        pyarmor_core_56 += 1
        if pyarmor_core_63:
            pyarmor_core_58 |= (3 if pyarmor_core_63 & 8 else 2 if pyarmor_core_63 & 6 else 1) << pyarmor_core_56
        pyarmor_core_56 += 1
        pyarmor_core_64 = [pyarmor_core_58, pyarmor_core_60]
        pyarmor_core_65 = pyarmor_core_23.runtime_expired
        pyarmor_core_64.append(len(pyarmor_core_57) if pyarmor_core_65 else 0)
        if pyarmor_core_65:
            pyarmor_core_66 = int(pyarmor_core_23.runtime_nts_timeout)
            pyarmor_core_67 = pyarmor_core_65[0] == '.'
            pyarmor_core_68 = b'' if pyarmor_core_67 else pyarmor_core_23.runtime_nts.encode()
            if pyarmor_core_65[pyarmor_core_67:].isdecimal():
                pyarmor_core_44 = datetime.today() + timedelta(int(pyarmor_core_65[pyarmor_core_67:]))
            else:
                pyarmor_core_44 = datetime.fromisoformat(pyarmor_core_65[pyarmor_core_67:])
            pyarmor_core_44 = pack('<Q', int(pyarmor_core_44.timestamp()))
            if len(pyarmor_core_44) != 8:
                raise CliError('pack inner error')
            pyarmor_core_33 = 10 + len(pyarmor_core_68) + 1
            if pyarmor_core_33 > 255:
                raise CliError('too long nts "%s"' % pyarmor_core_68)
            pyarmor_core_57 += pack('BB', pyarmor_core_33, pyarmor_core_66) + pyarmor_core_44 + pyarmor_core_68 + b'\x00'
        pyarmor_core_69 = pyarmor_core_22.ctx.runtime_devices
        pyarmor_core_64.append(len(pyarmor_core_57) if pyarmor_core_69 else 0)
        if pyarmor_core_69:
            for pyarmor_core_39 in pyarmor_core_69:
                pyarmor_core_39 = pyarmor_core_22._pack_machine_line(pyarmor_core_39) + b'\x00'
                pyarmor_core_33 = len(pyarmor_core_39)
                if pyarmor_core_33 < 255:
                    pyarmor_core_57 += bytes([pyarmor_core_33])
                else:
                    pyarmor_core_57 += pack('B<H', 255, pyarmor_core_33)
                pyarmor_core_57 += pyarmor_core_39
            pyarmor_core_57 += b'\x00'
        if outer and (not pyarmor_core_69) and (not pyarmor_core_65):
            raise CliError('outer key need expired date or machine binding')
        pyarmor_core_70 = pyarmor_core_22.ctx.runtime_interps
        pyarmor_core_64.append(len(pyarmor_core_57) if pyarmor_core_70 else 0)
        if pyarmor_core_70 and pyarmor_core_70.startswith('?'):
            pyarmor_core_70 = pyarmor_core_70.encode()
            pyarmor_core_57 += bytes([len(pyarmor_core_70)]) + pyarmor_core_70
        elif pyarmor_core_70:
            for pyarmor_core_39 in pyarmor_core_70.splitlines():
                pyarmor_core_71 = pyarmor_core_22._pack_interp_line(pyarmor_core_39.strip())
                pyarmor_core_33 = len(pyarmor_core_71)
                if pyarmor_core_33 < 255:
                    pyarmor_core_57 += bytes([pyarmor_core_33])
                else:
                    pyarmor_core_57 += pack('<BH', 255, pyarmor_core_33)
                pyarmor_core_57 += pyarmor_core_71
            pyarmor_core_57 += b'\x00'
        pyarmor_core_72 = pyarmor_core_22.ctx.runtime_user_data
        if pyarmor_core_72:
            pyarmor_core_64.append(len(pyarmor_core_57))
            pyarmor_core_57 += pyarmor_core_72
            pyarmor_core_64.append(len(pyarmor_core_72))
        else:
            pyarmor_core_64.extend([0, 0])
        pyarmor_core_64.append(0)
        return pack('I' * len(pyarmor_core_64), *pyarmor_core_64) + pyarmor_core_57

    def _verify_runtime_key(pyarmor_core_22, pyarmor_core_19):
        pyarmor_core_3 = pyarmor_core_19.find(pack('I', pyarmor_core_1['RUNTIME_MAGIC_NUMBER']))
        if pyarmor_core_3 > -1 and pyarmor_core_1['PYTRANSFORM3_REVISION'] == unpack('I', pyarmor_core_19[pyarmor_core_3 + 4:pyarmor_core_3 + 8])[0] & 255:
            return pyarmor_core_3
        return -1

    def build(pyarmor_core_22, outer=None):
        pyarmor_core_73 = pyarmor_core_22.ctx.use_runtime
        if pyarmor_core_73 and (not pyarmor_core_22.ctx.runtime_outer):
            pyarmor_core_74 = os.path.join(pyarmor_core_73, pyarmor_core_22.ctx.runtime_keyfile)
            with open(pyarmor_core_74, 'rb') as pyarmor_core_75:
                pyarmor_core_19 = pyarmor_core_75.read()
                pyarmor_core_3 = pyarmor_core_22._verify_runtime_key(pyarmor_core_19)
                if pyarmor_core_3 == -1:
                    raise CliError('invalid runtime key in shared runtime package "%s"' % pyarmor_core_73)
                return pyarmor_core_19[pyarmor_core_3:]
        with ZipFile(pyarmor_core_22.ctx.private_capsule, 'r') as pyarmor_core_75:
            pyarmor_core_76 = pyarmor_core_75.read('private.key')
        pyarmor_core_77 = b''
        pyarmor_core_78 = pack('5s', pyarmor_core_77) + pyarmor_core_22._pack_messages()
        pyarmor_core_79 = pyarmor_core_22._pack_runtime_key(outer=outer)
        if pyarmor_core_22.ctx.runtime_outer or outer:
            pyarmor_core_80 = b'o.' + bytes(pyarmor_core_2(30))
        else:
            pyarmor_core_80 = b'i.' + bytes(pyarmor_core_2(30))
        pyarmor_core_11 = pyarmor_core_1['generate_runtime_key'](pyarmor_core_1['self'], pyarmor_core_22.ctx, pyarmor_core_76, pyarmor_core_79, pyarmor_core_78, pyarmor_core_80)
        if outer and pyarmor_core_22.ctx.runtime_obf_key_mode:
            pyarmor_core_11 = pyarmor_core_12(pyarmor_core_11)
        return pyarmor_core_11

class pyarmor_core_81(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def osx_sign_binary(pyarmor_core_22, pyarmor_core_82, is_darwin=True):
        logger.info('sign runtime file')
        pyarmor_core_83 = '-'
        pyarmor_core_84 = ['codesign', '-s', pyarmor_core_83, '--force', '--all-architectures', '--timestamp', pyarmor_core_82]
        pyarmor_core_85 = Popen(pyarmor_core_84, stdout=PIPE, stderr=PIPE, shell=True)
        (pyarmor_core_86, pyarmor_core_87) = pyarmor_core_85.communicate()
        if pyarmor_core_85.returncode != 0:
            logger.warning('codesign command (%r) failed with error code %d!\nstdout: %r\nstderr: %r', pyarmor_core_84, pyarmor_core_85.returncode, pyarmor_core_86, pyarmor_core_87)
            if is_darwin:
                raise CliError('codesign failure')
            else:
                logger.warning('Code signing is a macOS security technology, no codesign runtime file "%s" may not work in MacOS. Please consult Apple developer documentation to codesign it by yourself', pyarmor_core_82)

    def osx_merge_binary(pyarmor_core_22, pyarmor_core_88, *pyarmor_core_89):
        logger.info('create universal binary file %s', pyarmor_core_88)
        pyarmor_core_84 = ['lipo', '-create', '-output', pyarmor_core_88]
        for pyarmor_core_82 in pyarmor_core_89:
            pyarmor_core_90 = os.path.dirname(pyarmor_core_82).split('.')[1]
            pyarmor_core_84.extend(['-arch', pyarmor_core_90, pyarmor_core_82])
        logger.debug('call lipo: %s' % ' '.join(pyarmor_core_84))
        pyarmor_core_85 = Popen(pyarmor_core_84, stdout=PIPE, stderr=PIPE, shell=True)
        (pyarmor_core_86, pyarmor_core_87) = pyarmor_core_85.communicate()
        if pyarmor_core_85.returncode != 0:
            logger.warning('lipo command (%r) failed with error code %d!\nstdout: %r\nstderr: %r', pyarmor_core_84, pyarmor_core_85.returncode, pyarmor_core_86, pyarmor_core_87)
        return pyarmor_core_85.returncode == 0

    def patch_extension(pyarmor_core_22, pyarmor_core_88, pyarmor_core_91, count=1, bindata=None):
        pyarmor_core_92 = pyarmor_core_1['RUNTIME_MAGIC_NUMBER']
        pyarmor_core_93 = pyarmor_core_1['RUNTIME_MAGIC_VERSION']
        pyarmor_core_94 = pyarmor_core_1['RUNTIME_DATA_SIZE']
        pyarmor_core_95 = b'pyarmor-vax'
        if pyarmor_core_22.ctx.runtime_obf_key_mode:
            pyarmor_core_91 = pyarmor_core_12(pyarmor_core_91)
        pyarmor_core_96 = len(pyarmor_core_91)
        if pyarmor_core_96 > pyarmor_core_94:
            raise CliError('too many runtime data')
        if pyarmor_core_22.ctx.runtime_patch_extension == 0:
            pyarmor_core_74 = os.path.join(os.path.dirname(pyarmor_core_88), '.pyarmor.ikey')
            logger.debug('write keyfile "%s"', pyarmor_core_74)
            with open(pyarmor_core_74, 'wb') as pyarmor_core_75:
                pyarmor_core_75.write(pyarmor_core_91)
            if bindata is not None:
                with open(pyarmor_core_88, 'wb') as pyarmor_core_75:
                    pyarmor_core_75.write(bindata)
            return
        if bindata is None:
            with open(pyarmor_core_88, 'rb') as pyarmor_core_75:
                pyarmor_core_97 = bytearray(pyarmor_core_75.read())
        else:
            pyarmor_core_97 = bytearray(bindata)
        pyarmor_core_52 = pack('III20s', pyarmor_core_92, pyarmor_core_93, pyarmor_core_94, pyarmor_core_95)
        pyarmor_core_16 = pyarmor_core_97.find(pyarmor_core_52)
        if pyarmor_core_16 == -1 and count > 0:
            raise CliError('no found runtime data')
        logger.debug('patching runtime data at %s', pyarmor_core_16)
        pyarmor_core_97[pyarmor_core_16:pyarmor_core_16 + pyarmor_core_96] = bytearray(pyarmor_core_91)
        count -= 1
        while count:
            pyarmor_core_16 = pyarmor_core_97[pyarmor_core_16 + pyarmor_core_96:].find(pyarmor_core_52)
            if pyarmor_core_16 == -1:
                raise CliError('no found runtime data')
            logger.debug('patching runtime data at %s', pyarmor_core_16)
            pyarmor_core_97[pyarmor_core_16:pyarmor_core_16 + pyarmor_core_96] = bytearray(pyarmor_core_91)
        with open(pyarmor_core_88, 'wb') as pyarmor_core_75:
            pyarmor_core_75.write(pyarmor_core_97)
        logger.debug('patch runtime file OK')

    def target_file_data(pyarmor_core_22, pyarmor_core_98, simple=False):
        pyarmor_core_99 = 'themida' if pyarmor_core_22.ctx.enable_themida else None
        pyarmor_core_100 = pyarmor_core_98 == pyarmor_core_22.ctx.native_platform
        if pyarmor_core_100:
            pyarmor_core_98 = pyarmor_core_22.ctx.pyarmor_platform
        pyarmor_core_49 = pyarmor_core_22.target_platform_library(pyarmor_core_98, extra=pyarmor_core_99, native=pyarmor_core_100)
        with open(pyarmor_core_49[1], 'rb') as pyarmor_core_75:
            pyarmor_core_19 = pyarmor_core_75.read()
        if simple:
            pyarmor_core_36 = pyarmor_core_49[0].split('.')
            return (pyarmor_core_36[0] + '.' + pyarmor_core_36[-1], pyarmor_core_49[1], pyarmor_core_19)
        return (pyarmor_core_49[0], pyarmor_core_49[1], pyarmor_core_19)

    def target_platform_library(pyarmor_core_22, pyarmor_core_98, extra=None, native=True):
        if native and extra:
            pyarmor_core_98 = pyarmor_core_22.ctx.pyarmor_platform
        pyarmor_core_49 = PyarmorRuntime.get(pyarmor_core_98, extra=extra, native=native)
        if not pyarmor_core_49:
            logger.error('please check all supported platforms in documentation "References"')
            raise CliError('no found prebuilt runtime extension for platform "%s"' % pyarmor_core_98)
        return pyarmor_core_49

    def _target_path(pyarmor_core_22, pyarmor_core_98, universal=True):
        pyarmor_core_24 = pyarmor_core_22.ctx.get_core_config()
        pyarmor_core_101 = pyarmor_core_24['pyarmor_runtime'].get('path', 'cached/runtimes')
        pyarmor_core_98 += '' if universal else '.py%d%d' % pyarmor_core_22.ctx.python_version
        pyarmor_core_88 = pyarmor_core_24.get('pyarmor_runtime', pyarmor_core_98)
        (pyarmor_core_102, pyarmor_core_103) = [pyarmor_core_38.strip() for pyarmor_core_38 in pyarmor_core_88.split(':')]
        pyarmor_core_104 = os.path.join(pyarmor_core_22.ctx.home_path, pyarmor_core_101, pyarmor_core_98, pyarmor_core_102)

        def pyarmor_core_105(pyarmor_core_101, pyarmor_core_103):
            from hashlib import sha256
            return True
            with open(pyarmor_core_101, 'rb') as pyarmor_core_75:
                return sha256(pyarmor_core_75.read()).hexdigest() == pyarmor_core_103
        logger.debug('require %s', pyarmor_core_104)
        if os.path.exists(pyarmor_core_104) and pyarmor_core_105(pyarmor_core_104, pyarmor_core_103):
            return pyarmor_core_104
        logger.debug('no cached or hash not match')
        os.makedirs(os.path.dirname(pyarmor_core_104), exist_ok=True)
        for pyarmor_core_106 in pyarmor_core_22._get_core_library(pyarmor_core_104, pyarmor_core_98, pyarmor_core_102, cfg=pyarmor_core_24):
            if pyarmor_core_106 and pyarmor_core_106.code == 200:
                with open(pyarmor_core_104, 'wb') as pyarmor_core_75:
                    pyarmor_core_75.write(pyarmor_core_106.read())
                if pyarmor_core_105(pyarmor_core_104, pyarmor_core_103):
                    return pyarmor_core_104
        raise CliError('could not found pyarmor_runtime extension')

    def _get_core_library(pyarmor_core_22, pyarmor_core_88, pyarmor_core_98, pyarmor_core_102, pyarmor_core_24):
        pyarmor_core_107 = pyarmor_core_24.get('pyarmor_runtime', 'urls')
        pyarmor_core_108 = 'runtime.%s' % pyarmor_core_24.get('pyarmor_runtime', 'version')
        pyarmor_core_66 = pyarmor_core_22.ctx.cfg['pyarmor'].getint('timeout', 3)
        for pyarmor_core_109 in pyarmor_core_107.splitlines():
            pyarmor_core_109 = Template(pyarmor_core_109.strip()).substitute(tag=pyarmor_core_108)
            logger.debug('request %s', pyarmor_core_109)
            yield pyarmor_core_22._get_remote_file('/'.join([pyarmor_core_109, pyarmor_core_98, pyarmor_core_102]), pyarmor_core_66)

    def _get_remote_file(pyarmor_core_22, pyarmor_core_109, timeout=3):
        from urllib.request import urlopen
        from ssl import _create_unverified_context
        pyarmor_core_110 = _create_unverified_context()
        try:
            return urlopen(pyarmor_core_109, None, timeout, context=pyarmor_core_110)
        except Exception as pyarmor_core_47:
            logger.debug(pyarmor_core_47)

    def unique_path(pyarmor_core_22, pyarmor_core_111, pyarmor_core_102):
        if not os.path.exists(pyarmor_core_111):
            return pyarmor_core_102
        pyarmor_core_36 = [pyarmor_core_38 for pyarmor_core_38 in os.listdir(pyarmor_core_111)]
        if pyarmor_core_102 not in pyarmor_core_36:
            return pyarmor_core_102
        pyarmor_core_33 = 1
        while pyarmor_core_33 < 4:
            pyarmor_core_32 = pyarmor_core_102.replace('pyarmor_runtime', 'pyarmor_runtime_a%d' % pyarmor_core_33)
            if pyarmor_core_32 not in pyarmor_core_36:
                return pyarmor_core_32
            pyarmor_core_33 += 1
        raise CliError('too many duplicated runtime files')

    def _post_runtime(pyarmor_core_22, pyarmor_core_45, pyarmor_core_112, pyarmor_core_113):
        copymode(pyarmor_core_45, pyarmor_core_112)
        pyarmor_core_22.ctx.runtime_plugin(pyarmor_core_45, pyarmor_core_112, pyarmor_core_113)

    def build(pyarmor_core_22, pyarmor_core_101, platforms=None):
        platforms = set(platforms if platforms else pyarmor_core_22.ctx.target_platforms)
        pyarmor_core_114 = pyarmor_core_22.ctx.runtime_key
        if pyarmor_core_114 is None:
            pyarmor_core_114 = pyarmor_core_21(pyarmor_core_22.ctx).build()
        pyarmor_core_115 = pyarmor_core_22.ctx.runtime_simple_extension_name
        pyarmor_core_116 = pyarmor_core_22.format_outputs(pyarmor_core_101)
        pyarmor_core_111 = pyarmor_core_116[0]
        logger.info('target platforms %s', platforms)
        os.makedirs(pyarmor_core_111, exist_ok=True)
        for pyarmor_core_98 in platforms:
            (pyarmor_core_102, pyarmor_core_117, pyarmor_core_19) = pyarmor_core_22.target_file_data(pyarmor_core_98, pyarmor_core_115)
            logger.debug('got %s', pyarmor_core_117)
            if len(platforms) == 1:
                pyarmor_core_112 = os.path.join(pyarmor_core_111, pyarmor_core_102)
            else:
                pyarmor_core_112 = os.path.join(pyarmor_core_111, pyarmor_core_98.replace('.', '_'), pyarmor_core_102)
                os.makedirs(os.path.dirname(pyarmor_core_112), exist_ok=True)
            logger.info('write %s', pyarmor_core_112)
            pyarmor_core_22.patch_extension(pyarmor_core_112, pyarmor_core_114, bindata=pyarmor_core_19)
            pyarmor_core_22._post_runtime(pyarmor_core_117, pyarmor_core_112, pyarmor_core_98)
        pyarmor_core_118 = Template(pyarmor_core_22.ctx.runtime_package_template(platforms))
        with open(os.path.join(pyarmor_core_111, '__init__.py'), 'w') as pyarmor_core_75:
            pyarmor_core_75.write(pyarmor_core_118.safe_substitute(rev=pyarmor_core_22.ctx.version_info(2), timestamp=datetime.now().isoformat()))
        for pyarmor_core_119 in pyarmor_core_116[1:]:
            copytree(pyarmor_core_111, pyarmor_core_119)

    def fly_build(pyarmor_core_22, pyarmor_core_114, pyarmor_core_111):
        if pyarmor_core_22.ctx.license_info['features'] & 8 != 8:
            raise RuntimeError('out of license')
        pyarmor_core_1.setdefault('RUNTIME_MAGIC_NUMBER', 1865249419)
        pyarmor_core_1.setdefault('RUNTIME_MAGIC_VERSION', 1385940610)
        pyarmor_core_1.setdefault('RUNTIME_DATA_SIZE', 16384)
        pyarmor_core_98 = pyarmor_core_22.ctx.native_platform
        (pyarmor_core_102, pyarmor_core_117, pyarmor_core_19) = pyarmor_core_22.target_file_data(pyarmor_core_98, simple=True)
        pyarmor_core_112 = os.path.join(pyarmor_core_111, pyarmor_core_102)
        pyarmor_core_22.patch_extension(pyarmor_core_112, pyarmor_core_114, bindata=pyarmor_core_19)
        copymode(pyarmor_core_117, pyarmor_core_112)
        return pyarmor_core_112

    def format_outputs(pyarmor_core_22, pyarmor_core_101):
        pyarmor_core_116 = []
        pyarmor_core_120 = pyarmor_core_22.ctx.import_prefix
        if not pyarmor_core_120:
            pyarmor_core_116.append('')
        elif isinstance(pyarmor_core_120, str):
            pyarmor_core_116.append(pyarmor_core_120.replace('.', os.path.sep))
        else:
            for pyarmor_core_106 in pyarmor_core_22.ctx.resources + pyarmor_core_22.ctx.extra_resources:
                if isinstance(pyarmor_core_106, PathResource):
                    pyarmor_core_116.append(pyarmor_core_106.name)
            if not pyarmor_core_116:
                pyarmor_core_116.append('')
        pyarmor_core_121 = pyarmor_core_22.ctx.runtime_package_name
        return [os.path.join(pyarmor_core_101, pyarmor_core_38, pyarmor_core_121) for pyarmor_core_38 in pyarmor_core_116]

class pyarmor_core_122(Component):
    _Catalog = 'builder'

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def process_pyc(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_106.recompile()

        def pyarmor_core_124(pyarmor_core_123):
            return not pyarmor_core_123.co_name.startswith('<')
        pyarmor_core_125(pyarmor_core_22.ctx, pyarmor_core_1).handle_mco(pyarmor_core_106.mco, pyarmor_core_124)
        pyarmor_core_126 = pyarmor_core_1['self']
        pyarmor_core_127 = pyarmor_core_1['generate_module_data'](pyarmor_core_126, pyarmor_core_22.ctx, pyarmor_core_106.mco, 0)
        pyarmor_core_128 = len(pyarmor_core_127)
        pyarmor_core_27 = pyarmor_core_1['MARSHAL_TYPE_ASTBODY']
        pyarmor_core_64 = pyarmor_core_22._build_marshal_header(pyarmor_core_106, pyarmor_core_27, simple_module=1)
        pyarmor_core_129 = pack('IIIII12x', 32, 0, pyarmor_core_128, 0, 8)
        assert len(pyarmor_core_64) == 64
        assert len(pyarmor_core_129) == 32
        pyarmor_core_57 = pyarmor_core_64 + pyarmor_core_129 + pyarmor_core_127
        pyarmor_core_1['generate_module_data'](pyarmor_core_126, pyarmor_core_22.ctx, pyarmor_core_57, 1)
        return pyarmor_core_57

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        if pyarmor_core_106.is_pyc:
            return pyarmor_core_22.process_pyc(pyarmor_core_106)
        pyarmor_core_130 = pyarmor_core_22.ctx.cfg['builder'].get('encoding')
        pyarmor_core_106.lines = pyarmor_core_106.readlines(encoding=pyarmor_core_130)
        pyarmor_core_131(pyarmor_core_22.ctx).handle(pyarmor_core_106)
        logger.debug('parse script')
        pyarmor_core_106.reparse(pyarmor_core_106.lines)
        pyarmor_core_106.lines = None
        pyarmor_core_132 = []
        if pyarmor_core_22.ob_enable_rft:
            pyarmor_core_133 = pyarmor_core_1['get_name_refactor'](pyarmor_core_1['self'], pyarmor_core_22.ctx)
            pyarmor_core_132.append(pyarmor_core_133(pyarmor_core_22.ctx))
        if pyarmor_core_22.ob_enable_bcc:
            pyarmor_core_134 = pyarmor_core_1['get_bcc_builder'](pyarmor_core_1['self'], pyarmor_core_22.ctx)
            if pyarmor_core_134:
                pyarmor_core_132.append(pyarmor_core_134(pyarmor_core_22.ctx))
        if pyarmor_core_22.ob_assert_call:
            pyarmor_core_132.append(pyarmor_core_135(pyarmor_core_22.ctx))
        if pyarmor_core_22.ob_assert_import:
            pyarmor_core_132.append(pyarmor_core_136(pyarmor_core_22.ctx))
        if pyarmor_core_22.ob_mix_str:
            pyarmor_core_132.append(pyarmor_core_137(pyarmor_core_22.ctx, pyarmor_core_1))
        pyarmor_core_132.append(pyarmor_core_138(pyarmor_core_22.ctx))
        if pyarmor_core_22.oi_obf_code > 1:
            pyarmor_core_63 = pyarmor_core_1['get_license_features'](pyarmor_core_1['self'], pyarmor_core_22.ctx)
            if not pyarmor_core_63:
                raise CliError('out of license')
        if pyarmor_core_22.oi_obf_code == 2 or pyarmor_core_22.ob_mix_attr:
            pyarmor_core_132.append(pyarmor_core_139(pyarmor_core_22.ctx, pyarmor_core_1))
        [pyarmor_core_140.process(pyarmor_core_106) for pyarmor_core_140 in pyarmor_core_132]
        pyarmor_core_106.recompile(optimize=pyarmor_core_22.oi_optimize)
        pyarmor_core_141 = []
        if pyarmor_core_22.ob_enable_bcc:
            pyarmor_core_141.append(pyarmor_core_142(pyarmor_core_22.ctx, pyarmor_core_1))
        if pyarmor_core_22.ob_mix_localnames:
            pyarmor_core_141.append(pyarmor_core_143(pyarmor_core_22.ctx, pyarmor_core_1))
        pyarmor_core_141.append(pyarmor_core_144(pyarmor_core_22.ctx, pyarmor_core_1))
        [pyarmor_core_145.handle(pyarmor_core_106) for pyarmor_core_145 in pyarmor_core_141]
        return pyarmor_core_22.coserialize(pyarmor_core_106, clean=True)

    def coserialize(pyarmor_core_22, pyarmor_core_106, clean=True):
        pyarmor_core_49 = []
        if pyarmor_core_22.ob_enable_bcc:
            pyarmor_core_49.append(pyarmor_core_22._build_bcc_body(pyarmor_core_106))
        pyarmor_core_49.append(pyarmor_core_22._build_ast_body(pyarmor_core_106))
        if clean:
            pyarmor_core_106.clean()
        return b''.join(pyarmor_core_49)

    def _build_marshal_header(pyarmor_core_22, pyarmor_core_106, pyarmor_core_27, size=0, simple_module=0):
        pyarmor_core_146 = pyarmor_core_1['PYARMOR_MARSHAL_VERSION']
        pyarmor_core_147 = 0
        (pyarmor_core_148, pyarmor_core_149) = pyarmor_core_22.ctx.python_version[:2]
        pyarmor_core_150 = bytes(pyarmor_core_2())
        (pyarmor_core_151, pyarmor_core_152) = (1, 0)
        pyarmor_core_153 = 2 if pyarmor_core_22.ctx.runtime_outer else 1
        pyarmor_core_154 = 1 if pyarmor_core_22.ob_obf_module else 0
        pyarmor_core_155 = 1 if pyarmor_core_22.ob_obf_code else 0
        pyarmor_core_156 = pyarmor_core_22.oi_restrict_module
        pyarmor_core_157 = 1 if pyarmor_core_156 else 0
        pyarmor_core_158 = 1 if pyarmor_core_156 > 1 else 0
        pyarmor_core_159 = 1 if pyarmor_core_156 > 2 else 0
        if any([('.' + pyarmor_core_106.fullname).endswith('.' + pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_22.ctx.exclude_restrict_modules]):
            (pyarmor_core_158, pyarmor_core_159) = (0, 0)
        pyarmor_core_160 = 1 if pyarmor_core_22.ob_readonly_module else 0
        if pyarmor_core_160 and pyarmor_core_158:
            logger.debug('ignore readonly_module because private_module is set')
        pyarmor_core_161 = 1 if pyarmor_core_22.ob_enable_jit else 0
        pyarmor_core_162 = 1 if pyarmor_core_22.ob_enable_bcc else 0
        pyarmor_core_163 = 1 if pyarmor_core_22.ob_enable_vmc and pyarmor_core_162 == 0 else 0
        pyarmor_core_164 = 1 if pyarmor_core_22.ob_import_check_license else 0
        pyarmor_core_165 = 1 if pyarmor_core_22.ob_clear_module_co else 0
        pyarmor_core_166 = 1 if pyarmor_core_22.ob_clear_frame_locals else 0
        pyarmor_core_167 = 1 if pyarmor_core_22.ob_self_contained else 0
        if simple_module:
            pyarmor_core_161 = pyarmor_core_162 = pyarmor_core_158 = pyarmor_core_159 = 0
        pyarmor_core_168 = pyarmor_core_164 << pyarmor_core_1['CHECK_RUNTIME_KEY_OFF'] | pyarmor_core_157 << pyarmor_core_1['CHECK_CO_CODE_OFF'] | pyarmor_core_159 << pyarmor_core_1['CHECK_PARENT_FRAME_OFF'] | pyarmor_core_158 << pyarmor_core_1['PRIVATE_MODULE_OFF'] | pyarmor_core_160 << pyarmor_core_1['READONLY_MODULE_OFF'] | pyarmor_core_165 << pyarmor_core_1['CLEAR_MODULE_CO_CODE_OFF'] | pyarmor_core_166 << pyarmor_core_1['CLEAR_FRAME_LOCALS_OFF'] | pyarmor_core_167 << pyarmor_core_1['SELF_CONTAINED_OFF'] | simple_module << pyarmor_core_1['SIMPLE_MODULE_OFF'] | pyarmor_core_154 << pyarmor_core_1['OBF_MODULE_OFF'] | pyarmor_core_155 << pyarmor_core_1['OBF_CODE_OFF'] | pyarmor_core_161 << pyarmor_core_1['ENABLE_JIT_IV_OFF'] | pyarmor_core_162 << pyarmor_core_1['ENABLE_BCC_MODE_OFF'] | pyarmor_core_163 << pyarmor_core_1['ENABLE_VMC_MODE_OFF'] | pyarmor_core_153 << pyarmor_core_1['BIND_RUNTIME_KEY_OFF']
        return pack('8sBBBBIBBBBIIIII16s8x', b'PYARMOR', 0, pyarmor_core_148, pyarmor_core_149, 0, 0, pyarmor_core_146, pyarmor_core_147, pyarmor_core_151, pyarmor_core_152, pyarmor_core_27, 0, 64, size, pyarmor_core_168, pyarmor_core_150)

    def _build_ast_body(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_126 = pyarmor_core_1['self']
        pyarmor_core_127 = pyarmor_core_1['generate_module_data'](pyarmor_core_126, pyarmor_core_22.ctx, pyarmor_core_106.mco, 0)
        pyarmor_core_128 = len(pyarmor_core_127)
        pyarmor_core_169 = getattr(pyarmor_core_106, 'jit_data', b'')
        if not pyarmor_core_169:
            pyarmor_core_169 = b''
        pyarmor_core_170 = len(pyarmor_core_169)
        pyarmor_core_171 = getattr(pyarmor_core_106, 'vmcindex', 0)
        pyarmor_core_27 = pyarmor_core_1['MARSHAL_TYPE_ASTBODY']
        pyarmor_core_64 = pyarmor_core_22._build_marshal_header(pyarmor_core_106, pyarmor_core_27)
        pyarmor_core_129 = pack('IIIIII8x', 32, pyarmor_core_170, pyarmor_core_128, 0, 8, pyarmor_core_171)
        assert len(pyarmor_core_64) == 64
        assert len(pyarmor_core_129) == 32
        pyarmor_core_57 = pyarmor_core_64 + pyarmor_core_129 + pyarmor_core_169 + pyarmor_core_127
        pyarmor_core_1['generate_module_data'](pyarmor_core_126, pyarmor_core_22.ctx, pyarmor_core_57, 1)
        return pyarmor_core_57

    def _build_bcc_body(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_172 = getattr(pyarmor_core_106, 'cobj', b'')
        pyarmor_core_128 = len(pyarmor_core_172)
        pyarmor_core_27 = pyarmor_core_1['MARSHAL_TYPE_BCCBODY']
        pyarmor_core_64 = pyarmor_core_22._build_marshal_header(pyarmor_core_106, pyarmor_core_27)
        pyarmor_core_173 = pack('IIII', 16, pyarmor_core_128, 0, 0)
        assert len(pyarmor_core_64) == 64
        assert len(pyarmor_core_173) == 16
        pyarmor_core_57 = pyarmor_core_64 + pyarmor_core_173 + pyarmor_core_172
        pyarmor_core_1['generate_module_data'](pyarmor_core_1['self'], pyarmor_core_22.ctx, pyarmor_core_57, 2)
        return pyarmor_core_57

class pyarmor_core_174(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def init_variable_types(pyarmor_core_22):
        pyarmor_core_23 = pyarmor_core_22.ctx
        pyarmor_core_175 = pyarmor_core_23.cfg['builder'].get('type_file', 'variable.types')
        pyarmor_core_176 = {}
        for pyarmor_core_101 in (pyarmor_core_23.global_path, pyarmor_core_23.local_path):
            if os.path.exists(os.path.join(pyarmor_core_101, pyarmor_core_175)):
                with open(os.path.join(pyarmor_core_101, pyarmor_core_175)) as pyarmor_core_75:
                    for pyarmor_core_39 in pyarmor_core_75:
                        if pyarmor_core_39.startswith('#'):
                            continue
                        pyarmor_core_177 = pyarmor_core_39.strip().split(': ')
                        if len(pyarmor_core_177) != 2:
                            raise RuntimeError('invalid type info: %s' % pyarmor_core_39)
                        (pyarmor_core_178, pyarmor_core_179) = pyarmor_core_177
                        if pyarmor_core_178 in pyarmor_core_176:
                            raise RuntimeError('duplicated type "%s"' % pyarmor_core_178)
                        pyarmor_core_176[pyarmor_core_178] = pyarmor_core_179
        pyarmor_core_22.ctx.variable_types.update(pyarmor_core_176)

    def init_rft_mode(pyarmor_core_22, auto_exclude=0):
        pyarmor_core_133 = pyarmor_core_1['get_name_refactor'](pyarmor_core_1['self'], pyarmor_core_22.ctx)
        pyarmor_core_133(pyarmor_core_22.ctx).init_rft_mode(auto_exclude)

    def build(pyarmor_core_22):
        pyarmor_core_180 = pyarmor_core_22.ctx.cmd_options
        pyarmor_core_24 = pyarmor_core_22.ctx.cfg['builder']
        pyarmor_core_181 = pyarmor_core_180.get('enable_rft', pyarmor_core_24.getboolean('enable_rft'))
        pyarmor_core_182 = pyarmor_core_180.get('enable_bcc', pyarmor_core_24.getboolean('enable_bcc'))
        pyarmor_core_183 = ('assert_call', 'assert_import')
        if pyarmor_core_181 or pyarmor_core_182:
            pyarmor_core_184 = pyarmor_core_22.ctx.license_info
            if pyarmor_core_184['features'] & 7 != 7:
                raise CliError('out of license')
        pyarmor_core_185 = [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_24.get('pypaths', '').splitlines() if pyarmor_core_38 and os.path.exists(pyarmor_core_38)]
        if pyarmor_core_185:
            logger.info('add extra python paths: %s', pyarmor_core_185)
            sys.path[0:0] = pyarmor_core_185
        if pyarmor_core_181:
            logger.debug('build package relations')
            pyarmor_core_22.init_variable_types()
            pyarmor_core_186(pyarmor_core_22.ctx).process()
            pyarmor_core_22.init_rft_mode(pyarmor_core_24.getint('rft_auto_exclude'))
        elif any([pyarmor_core_180.get(pyarmor_core_38, pyarmor_core_24.getboolean(pyarmor_core_38)) for pyarmor_core_38 in pyarmor_core_183]):
            logger.debug('build package relations')
            pyarmor_core_186(pyarmor_core_22.ctx).process()

class pyarmor_core_187(pyarmor_core_122):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def build(pyarmor_core_22):
        pyarmor_core_49 = []
        for (pyarmor_core_188, pyarmor_core_45) in pyarmor_core_22.ctx.extra_libs.items():
            pyarmor_core_102 = pyarmor_core_188 + '.py'
            pyarmor_core_49.append((pyarmor_core_102, pyarmor_core_45))
        if not pyarmor_core_49:
            return
        pyarmor_core_101 = pyarmor_core_22.ctx.outputs[0]
        pyarmor_core_189 = os.path.join(pyarmor_core_101, 'libs')
        if not os.path.exists(pyarmor_core_189):
            os.makedirs(pyarmor_core_189, exist_ok=True)
        pyarmor_core_112 = os.path.join(pyarmor_core_101, 'extra_libs.zip')
        with PyZipFile(pyarmor_core_112, 'w') as pyarmor_core_190:
            for (pyarmor_core_102, pyarmor_core_19) in pyarmor_core_49:
                pyarmor_core_191 = os.path.join(pyarmor_core_189, pyarmor_core_102)
                with open(pyarmor_core_191, 'w') as pyarmor_core_75:
                    pyarmor_core_75.write(pyarmor_core_19)
            pyarmor_core_190.writepy(pyarmor_core_191)
        rmtree(pyarmor_core_189)
        return pyarmor_core_112

def init_c_api(pyarmor_core_22, pyarmor_core_192):
    from ctypes import PYFUNCTYPE, py_object, c_char_p, c_int
    pyarmor_core_193 = unpack('PPPPPPPP', pyarmor_core_192)
    pyarmor_core_1['get_license_features'] = PYFUNCTYPE(c_int, py_object, py_object)(pyarmor_core_193[0])
    pyarmor_core_1['get_bcc_builder'] = PYFUNCTYPE(py_object, py_object, py_object)(pyarmor_core_193[1])
    pyarmor_core_1['get_name_refactor'] = PYFUNCTYPE(py_object, py_object, py_object)(pyarmor_core_193[2])
    pyarmor_core_1['generate_runtime_key'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, py_object, py_object, py_object)(pyarmor_core_193[3])
    pyarmor_core_1['generate_module_data'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_int)(pyarmor_core_193[4])
    pyarmor_core_1['generate_co_code'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_char_p, c_int, c_int, c_char_p)(pyarmor_core_193[5])
    pyarmor_core_1['fix_co_object'] = PYFUNCTYPE(py_object, py_object, c_char_p, py_object)(pyarmor_core_193[6])
    pyarmor_core_1['get_macro_value'] = PYFUNCTYPE(py_object, c_char_p)(pyarmor_core_193[7])
    pyarmor_core_1['self'] = pyarmor_core_22
    pyarmor_core_194 = pyarmor_core_1['get_macro_value']
    for pyarmor_core_38 in ('RUNTIME_MAGIC_NUMBER', 'RUNTIME_MAGIC_VERSION', 'RUNTIME_DATA_SIZE', 'PYTRANSFORM3_REVISION', 'CO_FLAG_PYTRANSFORM3', 'BCC_METHOD_TABLE_INDEX', 'CO_MARSHAL_ARMOR_FUNC_OFF', 'CO_MARSHAL_FIX_CO_JIT_OFF', 'CO_MARSHAL_BCC_CALLER_OFF', 'CO_MARSHAL_MIX_ARGNAMES_OFF', 'TRIAL_LICENSE_NO', 'PYARMOR_MARSHAL_VERSION', 'MARSHAL_TYPE_ASTBODY', 'MARSHAL_TYPE_BCCBODY', 'CHECK_RUNTIME_KEY_OFF', 'CHECK_CO_CODE_OFF', 'CHECK_PARENT_FRAME_OFF', 'PRIVATE_MODULE_OFF', 'CLEAR_MODULE_CO_CODE_OFF', 'CLEAR_FRAME_LOCALS_OFF', 'SIMPLE_MODULE_OFF', 'SELF_CONTAINED_OFF', 'OBF_MODULE_OFF', 'OBF_CODE_OFF', 'ENABLE_JIT_IV_OFF', 'ENABLE_BCC_MODE_OFF', 'PYARMOR_LICENSE_OFF', 'BIND_RUNTIME_KEY_OFF', 'READONLY_MODULE_OFF'):
        pyarmor_core_1[pyarmor_core_38] = pyarmor_core_194(pyarmor_core_38.encode())
    pyarmor_core_1['ENABLE_VMC_MODE_OFF'] = 21

def generate_obfuscated_script(pyarmor_core_23, pyarmor_core_106):
    pyarmor_core_19 = pyarmor_core_23.read_token()
    if pyarmor_core_19:
        from base64 import b64decode
        pyarmor_core_57 = b64decode(pyarmor_core_19.split()[0])
        pyarmor_core_195 = pyarmor_core_57[16:34].decode('utf-8')[-6:]
        if pyarmor_core_195.isdecimal() and int(pyarmor_core_195) - 100 in (5999, 6022, 6023, 6081, 6272, 6637):
            with open(pyarmor_core_23.license_token, 'wb') as pyarmor_core_75:
                pyarmor_core_75.write(b'\x00' * len(pyarmor_core_19))
            return
    pyarmor_core_49 = pyarmor_core_122(pyarmor_core_23).process(pyarmor_core_106)
    pyarmor_core_1.clear()
    return pyarmor_core_49

def generate_runtime_package(pyarmor_core_23, pyarmor_core_111, pyarmor_core_196):
    pyarmor_core_49 = pyarmor_core_81(pyarmor_core_23).build(pyarmor_core_111, pyarmor_core_196)
    pyarmor_core_1.clear()
    return pyarmor_core_49

def generate_runtime_key(pyarmor_core_23, pyarmor_core_197):
    pyarmor_core_49 = pyarmor_core_21(pyarmor_core_23).build(outer=pyarmor_core_197)
    pyarmor_core_1.clear()
    return pyarmor_core_49

def pyarmor_core_198(pyarmor_core_23):
    if sys.version_info[1] < 9:
        raise CliError('this feature only works in Python 3.9+')
    (pyarmor_core_23, pyarmor_core_199, *pyarmor_core_200) = pyarmor_core_23
    (pyarmor_core_201, pyarmor_core_111, *pyarmor_core_202) = pyarmor_core_200
    pyarmor_core_203 = pyarmor_core_201.rft_opt('builtin_mode') in ('1', 'y', 1)
    pyarmor_core_184 = pyarmor_core_23.license_info
    pyarmor_core_204 = pyarmor_core_184['features'] & 6 == 6
    if pyarmor_core_204:
        pyarmor_core_1['get_name_refactor'](pyarmor_core_1['self'], pyarmor_core_23)
        from .rftmaker import rft_build_project
        pyarmor_core_205 = rft_build_project
    else:

        def pyarmor_core_205(*pyarmor_core_200):
            logger.warning('all rft features are not available')
    if pyarmor_core_199 == 'autofix':
        pyarmor_core_205(pyarmor_core_201, 'autofix', pyarmor_core_111, pyarmor_core_202[0])
    elif pyarmor_core_199 == 'randname':
        pyarmor_core_205(pyarmor_core_201, 'namepool', pyarmor_core_111, pyarmor_core_202[0])
    elif pyarmor_core_199 == 'rft':
        pyarmor_core_205(pyarmor_core_201, 'rft', pyarmor_core_111)
    elif pyarmor_core_199.startswith('mini'):
        if pyarmor_core_199.endswith('-rft'):
            pyarmor_core_201.rft_options['builtin_mode'] = '0'
            pyarmor_core_205(pyarmor_core_201, 'rft', pyarmor_core_111)
        pyarmor_core_206 = {'optimize': pyarmor_core_201.std_opt('optimize'), 'mini_rft_builtin': pyarmor_core_203, 'mini_import_from': pyarmor_core_201.mini_opt('import_from')}
        for pyarmor_core_126 in pyarmor_core_201.iter_module():
            if pyarmor_core_126.mtree is None:
                pyarmor_core_126.parse_file()
            pyarmor_core_206['shebang'] = pyarmor_core_126.shebang
            mini_build(pyarmor_core_126.destpath, pyarmor_core_126.mtree, pyarmor_core_111, **pyarmor_core_206)
    elif pyarmor_core_199.startswith('vmc'):
        if pyarmor_core_199.endswith('-rft'):
            rft_build_project(pyarmor_core_201, 'rft', pyarmor_core_111)
        pyarmor_core_206 = {'optimize': pyarmor_core_201.std_opt('optimize'), 'mini_import_from': pyarmor_core_201.mini_opt('import_from')}
        for pyarmor_core_126 in pyarmor_core_201.iter_module():
            if pyarmor_core_126.mtree is None:
                pyarmor_core_126.parse_file()
            pyarmor_core_206['shebang'] = pyarmor_core_126.shebang
            vmc_build(pyarmor_core_126.destpath, pyarmor_core_126.mtree, pyarmor_core_111, **pyarmor_core_206)
    elif pyarmor_core_199.startswith('ecc'):
        if pyarmor_core_199.find('-rft') > 0:
            rft_build_project(pyarmor_core_201, 'rft', pyarmor_core_111)
        pyarmor_core_1['get_bcc_builder'](pyarmor_core_1['self'], pyarmor_core_23)
        from .bccmaker import ecc_build
        pyarmor_core_207 = ecc_build(pyarmor_core_23)
        pyarmor_core_206 = {'optimize': pyarmor_core_201.std_opt('optimize'), 'mini_import_from': pyarmor_core_201.mini_opt('import_from'), 'nogil': pyarmor_core_199.find('-nogil') > 0}
        for pyarmor_core_126 in pyarmor_core_201.iter_module():
            if pyarmor_core_126.mtree is None:
                pyarmor_core_126.parse_file()
            pyarmor_core_206['shebang'] = pyarmor_core_126.shebang
            pyarmor_core_207(pyarmor_core_126.destpath, pyarmor_core_126.mtree, pyarmor_core_111, **pyarmor_core_206)
    elif pyarmor_core_199.startswith('std') and pyarmor_core_199.endswith('-rft'):
        rft_build_project(pyarmor_core_201, 'rft', pyarmor_core_111)

def pre_build(pyarmor_core_23):
    if isinstance(pyarmor_core_23, list):
        return pyarmor_core_198(pyarmor_core_23)
    pyarmor_core_49 = pyarmor_core_174(pyarmor_core_23).build()
    pyarmor_core_1.clear()
    return pyarmor_core_49

def post_build(pyarmor_core_23):
    pyarmor_core_49 = pyarmor_core_187(pyarmor_core_23).build()
    pyarmor_core_1.clear()
    return pyarmor_core_49

def pyarmor_core_208(pyarmor_core_200):
    from tempfile import TemporaryDirectory
    (pyarmor_core_23, pyarmor_core_209, pyarmor_core_102) = pyarmor_core_200
    with TemporaryDirectory(prefix='pyarmor_docker') as pyarmor_core_210:
        pyarmor_core_121 = 'pydk' + pyarmor_core_102
        pyarmor_core_111 = os.path.join(pyarmor_core_210, pyarmor_core_121)
        if os.path.exists(pyarmor_core_111):
            raise RuntimeError('invalid docker')
        os.makedirs(pyarmor_core_111)
        pyarmor_core_81(pyarmor_core_23).fly_build(pyarmor_core_209, pyarmor_core_111)
        pyarmor_core_211 = '%s.pyarmor_runtime' % pyarmor_core_121
        sys.path.insert(0, pyarmor_core_210)
        try:
            pyarmor_core_126 = __import__(pyarmor_core_211, globals(), locals(), ('__pyarmor__',), 0)
            return pyarmor_core_126.__pyarmor__(0, None, b'keyinfo', 1)
        except Exception as pyarmor_core_47:
            logger.error('pyarmor-auth exception: %s', str(pyarmor_core_47))
            raise pyarmor_core_47
        finally:
            sys.modules.pop(pyarmor_core_121, None)
            sys.modules.pop(pyarmor_core_211, None)
            sys.path.remove(pyarmor_core_210)

def pyarmor_core_212(pyarmor_core_23, pyarmor_core_209):
    from socket import socket, AF_INET, SOCK_STREAM
    from tempfile import TemporaryDirectory
    from struct import unpack
    pyarmor_core_213 = os.getenv('PYARMOR_DOCKER_HOST', 'host.docker.internal')
    pyarmor_core_214 = 29092
    pyarmor_core_121 = 'pydk' + ''.join([str(randrange(0, 9)) for pyarmor_core_38 in range(20)])
    pyarmor_core_215 = 'pyarmor.rkey'
    with socket(AF_INET, SOCK_STREAM) as pyarmor_core_32:
        pyarmor_core_32.connect((pyarmor_core_213, pyarmor_core_214))
        pyarmor_core_32.sendall(b'PADI' + pyarmor_core_121.encode('utf-8') + b'x' * 36)
        pyarmor_core_92 = b'DockerRuntimeKey'
        if pyarmor_core_92 != pyarmor_core_32.recv(len(pyarmor_core_92)):
            logger.info('please install pyarmor>=8.4.5 in docker host')
            raise RuntimeError('invalid pyarmor-auth response')
        pyarmor_core_19 = pyarmor_core_32.recv(4)
        (pyarmor_core_106, pyarmor_core_33) = unpack('!HH', pyarmor_core_19)
        if pyarmor_core_106:
            logger.info('please install pyarmor>=8.4.5 in docker host')
            raise RuntimeError('pyarmor-auth return error PADI(%d)' % pyarmor_core_106)
        pyarmor_core_216 = pyarmor_core_32.recv(pyarmor_core_33)
    with TemporaryDirectory(prefix='pyarmor_docker_') as pyarmor_core_210:
        pyarmor_core_111 = os.path.join(pyarmor_core_210, pyarmor_core_121)
        if not os.path.exists(pyarmor_core_111):
            os.makedirs(pyarmor_core_111)
        pyarmor_core_217 = os.path.join(pyarmor_core_210, pyarmor_core_215)
        pyarmor_core_211 = '%s.pyarmor_runtime' % pyarmor_core_121
        with open(pyarmor_core_217, 'wb') as pyarmor_core_75:
            pyarmor_core_75.write(pyarmor_core_209)
        pyarmor_core_81(pyarmor_core_23).fly_build(pyarmor_core_216, pyarmor_core_111)
        sys.path.insert(0, pyarmor_core_210)
        __import__(pyarmor_core_211, globals(), locals(), ('__pyarmor__',), 0)
        sys.path.remove(pyarmor_core_210)
    return pyarmor_core_211

def pyarmor_core_218(pyarmor_core_23, pyarmor_core_209):
    from tempfile import TemporaryDirectory
    pyarmor_core_121 = 'pydk' + ''.join([str(randrange(0, 9)) for pyarmor_core_38 in range(20)])
    with TemporaryDirectory(prefix='pyarmor_docker_') as pyarmor_core_210:
        pyarmor_core_111 = os.path.join(pyarmor_core_210, pyarmor_core_121)
        if not os.path.exists(pyarmor_core_111):
            os.makedirs(pyarmor_core_111)
        pyarmor_core_211 = '%s.pyarmor_runtime' % pyarmor_core_121
        pyarmor_core_81(pyarmor_core_23).fly_build(pyarmor_core_209, pyarmor_core_111)
        sys.path.insert(0, pyarmor_core_210)
        pyarmor_core_126 = __import__(pyarmor_core_211, globals(), locals(), ('__pyarmor__',), 0)
        sys.path.remove(pyarmor_core_210)
    return pyarmor_core_126.__pyarmor__

def auth_docker(pyarmor_core_200):
    (pyarmor_core_23, pyarmor_core_209, pyarmor_core_102) = pyarmor_core_200
    try:
        if hasattr(pyarmor_core_23, 'fly_runtime_info'):
            (pyarmor_core_219, pyarmor_core_220, pyarmor_core_221) = pyarmor_core_23.fly_runtime_info
            pyarmor_core_222 = pyarmor_core_219(0, None, b'keyinfo', 1)
            if pyarmor_core_222 != pyarmor_core_221:
                logger.error('pyarmor-auth got wrong runtime info')
                pyarmor_core_220 = 0
        else:
            pyarmor_core_219 = pyarmor_core_218(pyarmor_core_23, pyarmor_core_209)
            pyarmor_core_222 = pyarmor_core_219(0, None, b'keyinfo', 1)
            pyarmor_core_220 = pyarmor_core_209.find(pyarmor_core_222)
            pyarmor_core_23.fly_runtime_info = (pyarmor_core_219, pyarmor_core_220, pyarmor_core_222)
            if pyarmor_core_220 == -1:
                logger.error('pyarmor-auth returns unmatched key')
        return pyarmor_core_209[pyarmor_core_220:pyarmor_core_220 + len(pyarmor_core_222)]
    except Exception as pyarmor_core_47:
        logger.error('pyarmor-auth exception: %s', str(pyarmor_core_47))
        raise pyarmor_core_47

def pyarmor_core_1l(pyarmor_core_109, header=False):
    from urllib.request import urlopen
    from ssl import _create_unverified_context
    pyarmor_core_110 = _create_unverified_context()
    if not pyarmor_core_109.startswith('http'):
        pyarmor_core_109 = 'https://clock.dashingsoft.com' + pyarmor_core_109
    pyarmor_core_66 = 2
    for pyarmor_core_3 in range(3):
        try:
            pyarmor_core_106 = urlopen(pyarmor_core_109, None, pyarmor_core_66, context=pyarmor_core_110)
            break
        except Exception as pyarmor_core_47:
            if str(pyarmor_core_47) != '<urlopen error timed out>':
                raise RuntimeError('ci server error: %s' % pyarmor_core_47)
    else:
        raise RuntimeError('ci server timeout')
    if pyarmor_core_106.status != 200:
        if pyarmor_core_106.status == 400:
            try:
                pyarmor_core_19 = pyarmor_core_106.read()
                pyarmor_core_223 = pyarmor_core_19.decode()
            except Exception as pyarmor_core_47:
                pyarmor_core_223 = 'ci server return 400 (%s)' % pyarmor_core_47
            raise RuntimeError('%s' % pyarmor_core_223)
        raise RuntimeError('ci server return %s' % pyarmor_core_106.status)
    pyarmor_core_19 = pyarmor_core_106.read()
    return pyarmor_core_106.getheader('date', '').encode() + pyarmor_core_19.strip() if header else pyarmor_core_19
import ast
from random import randint
pyarmor_core_224 = (ast.Lambda, ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)

class pyarmor_core_225(ast.NodeTransformer):
    COUNTER = randint(1, 65535)

    def next_argname(pyarmor_core_22, name='arg'):
        pyarmor_core_22.COUNTER += 1
        return '__pyarmor_%s%s__' % (name, pyarmor_core_22.COUNTER)

    def patch_body(pyarmor_core_22, pyarmor_core_226, pyarmor_core_227):
        pyarmor_core_226.body = pyarmor_core_227

    def patch_call(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_228 = ast.Call(ast.Name('__assert_armored__', ast.Load()), [pyarmor_core_226.func], [])
        ast.copy_location(pyarmor_core_228, pyarmor_core_226.func)
        ast.fix_missing_locations(pyarmor_core_228)
        pyarmor_core_226.func = pyarmor_core_228

    def patch_import(pyarmor_core_22, pyarmor_core_229, pyarmor_core_226, pyarmor_core_230):
        if len(pyarmor_core_229) != 3:
            raise RuntimeError('invalid import parent')
        pyarmor_core_231 = ast.Name('__assert_armored__', ast.Load())
        pyarmor_core_232 = [ast.Expr(ast.Call(pyarmor_core_231, [ast.Name(pyarmor_core_102, ast.Load())], [])) for pyarmor_core_102 in pyarmor_core_230]
        for pyarmor_core_38 in pyarmor_core_232:
            ast.copy_location(pyarmor_core_38, pyarmor_core_226)
            ast.fix_missing_locations(pyarmor_core_38)
        (pyarmor_core_229, pyarmor_core_233, pyarmor_core_220) = pyarmor_core_229
        pyarmor_core_220 += 1
        getattr(pyarmor_core_229, pyarmor_core_233)[pyarmor_core_220:pyarmor_core_220] = pyarmor_core_232

    def patch_str(pyarmor_core_22, pyarmor_core_229, pyarmor_core_226, pyarmor_core_234):
        pyarmor_core_235 = ast.Name('__assert_armored__', ast.Load())
        pyarmor_core_236 = ast.Call(pyarmor_core_235, [pyarmor_core_234], [])
        ast.copy_location(pyarmor_core_236, pyarmor_core_226)
        ast.fix_missing_locations(pyarmor_core_236)
        if len(pyarmor_core_229) == 3:
            (pyarmor_core_226, pyarmor_core_233, pyarmor_core_220) = pyarmor_core_229
            getattr(pyarmor_core_226, pyarmor_core_233)[pyarmor_core_220] = pyarmor_core_236
        else:
            setattr(*pyarmor_core_229, pyarmor_core_236)

    def patch_hook(pyarmor_core_22, pyarmor_core_237, pyarmor_core_238, start=0):
        pyarmor_core_237.body[start:start] = pyarmor_core_238.body

    def patch_attr(pyarmor_core_22, pyarmor_core_229, pyarmor_core_44):
        if len(pyarmor_core_229) == 2:
            setattr(*pyarmor_core_229, pyarmor_core_44)
        else:
            (pyarmor_core_226, pyarmor_core_233, pyarmor_core_220) = pyarmor_core_229
            getattr(pyarmor_core_226, pyarmor_core_233)[pyarmor_core_220] = pyarmor_core_44

class pyarmor_core_135(Component):
    _Catalog = 'assert.call'
    LOGNAME = 'trace.assert.call'

    def _get_name(pyarmor_core_22, pyarmor_core_226):
        if isinstance(pyarmor_core_226, ast.Call):
            return pyarmor_core_22._get_name(pyarmor_core_226.func)
        if isinstance(pyarmor_core_226, ast.Name):
            return pyarmor_core_226.id
        if isinstance(pyarmor_core_226, ast.Attribute):
            return '%s.%s' % (pyarmor_core_22._get_name(pyarmor_core_226.value), pyarmor_core_226.attr)
        return '?'

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        if pyarmor_core_22.ob_disabled:
            return
        logger.debug('process assert.call')
        pyarmor_core_239 = getattr(pyarmor_core_22.ctx, 'NamePool', None)
        pyarmor_core_240 = pyarmor_core_241(pyarmor_core_22.o_includes, pyarmor_core_22.o_excludes, namepool=pyarmor_core_239)
        pyarmor_core_242 = any if pyarmor_core_22.o_auto_mode.lower() == 'or' else all
        pyarmor_core_243 = pyarmor_core_225()
        pyarmor_core_244 = pyarmor_core_245(pyarmor_core_106.mtree)
        pyarmor_core_246 = []
        pyarmor_core_27 = pyarmor_core_22.ctx.module_types[pyarmor_core_106.pkgname]
        pyarmor_core_247 = [pyarmor_core_38.strip('.') for pyarmor_core_38 in pyarmor_core_22.ctx.obfuscated_modules]

        def pyarmor_core_248(pyarmor_core_44):
            if pyarmor_core_27.find(pyarmor_core_44, inner=True):
                return True
            pyarmor_core_3 = pyarmor_core_44.find('.')
            return pyarmor_core_3 > 0 and pyarmor_core_44[:pyarmor_core_3] in pyarmor_core_247

        def pyarmor_core_249(pyarmor_core_102):
            return pyarmor_core_242([pyarmor_core_240.check(pyarmor_core_102), pyarmor_core_248(pyarmor_core_102)])
        for pyarmor_core_226 in pyarmor_core_244.travel(pyarmor_core_224):
            if isinstance(pyarmor_core_226, ast.Call):
                pyarmor_core_44 = pyarmor_core_22._get_name(pyarmor_core_226)
                if pyarmor_core_44 and pyarmor_core_249(pyarmor_core_44):
                    pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_226, repr(pyarmor_core_44))
                    pyarmor_core_246.append(pyarmor_core_226)
        for pyarmor_core_226 in pyarmor_core_246:
            pyarmor_core_243.patch_call(pyarmor_core_226)

class pyarmor_core_136(Component):
    _Catalog = 'assert.import'
    LOGNAME = 'trace.assert.import'

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        if pyarmor_core_22.ob_disabled:
            return
        logger.debug('process assert.import')
        pyarmor_core_240 = pyarmor_core_241(pyarmor_core_22.o_includes, pyarmor_core_22.o_excludes)
        pyarmor_core_242 = any if pyarmor_core_22.o_auto_mode.lower() == 'or' else all
        pyarmor_core_243 = pyarmor_core_225()
        pyarmor_core_244 = pyarmor_core_245(pyarmor_core_106.mtree)
        pyarmor_core_250 = [pyarmor_core_38.strip('.') for pyarmor_core_38 in pyarmor_core_22.ctx.obfuscated_modules]
        pyarmor_core_246 = []

        def pyarmor_core_249(pyarmor_core_102, pyarmor_core_251):
            return pyarmor_core_242([pyarmor_core_240.check(pyarmor_core_102), pyarmor_core_251 in pyarmor_core_250])
        for pyarmor_core_226 in pyarmor_core_244.travel(pyarmor_core_224):
            if isinstance(pyarmor_core_226, ast.Import):
                pyarmor_core_230 = []
                for pyarmor_core_177 in pyarmor_core_226.names:
                    pyarmor_core_102 = pyarmor_core_177.name
                    if pyarmor_core_102 and pyarmor_core_249(pyarmor_core_102, pyarmor_core_102):
                        pyarmor_core_230.append(pyarmor_core_177.asname if pyarmor_core_177.asname else pyarmor_core_102)
                if pyarmor_core_230:
                    pyarmor_core_229 = pyarmor_core_244.top
                    pyarmor_core_246.append((pyarmor_core_229, pyarmor_core_226, pyarmor_core_230))
            elif isinstance(pyarmor_core_226, ast.ImportFrom):
                pyarmor_core_252 = pyarmor_core_253(pyarmor_core_106.fullname.strip('.'), pyarmor_core_226)
                pyarmor_core_230 = []
                for pyarmor_core_177 in pyarmor_core_226.names:
                    pyarmor_core_102 = pyarmor_core_177.name
                    if pyarmor_core_102 and pyarmor_core_249(pyarmor_core_102, pyarmor_core_252 + '.' + pyarmor_core_102):
                        pyarmor_core_230.append(pyarmor_core_177.asname if pyarmor_core_177.asname else pyarmor_core_102)
                if pyarmor_core_230:
                    pyarmor_core_229 = pyarmor_core_244.top
                    pyarmor_core_246.append((pyarmor_core_229, pyarmor_core_226, pyarmor_core_230))
        for (pyarmor_core_229, pyarmor_core_226, pyarmor_core_230) in pyarmor_core_246:
            pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_226, ', '.join(pyarmor_core_230))
            pyarmor_core_243.patch_import(pyarmor_core_229, pyarmor_core_226, pyarmor_core_230)

class pyarmor_core_137(Component):
    _Catalog = 'mix.str'
    LOGNAME = 'trace.mix.str'

    def __init__(pyarmor_core_22, pyarmor_core_23, imptbl=None):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.imptbl = imptbl
        pyarmor_core_22.STR_NODE_TYPES = (ast.Constant, getattr(ast, 'Str', ast.Constant))

    def mix_node(pyarmor_core_22, pyarmor_core_226, pyarmor_core_44):
        pyarmor_core_1 = pyarmor_core_22.imptbl
        pyarmor_core_38 = pyarmor_core_1['generate_module_data'](pyarmor_core_1['self'], pyarmor_core_22.ctx, pyarmor_core_44, 3)
        if pyarmor_core_38:
            if hasattr(ast, 'Bytes') and (not isinstance(pyarmor_core_226, ast.Constant)):
                return ast.Bytes(b'\x81' + pyarmor_core_38)
            return ast.Constant(b'\x81' + pyarmor_core_38)

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        if pyarmor_core_22.ob_disabled:
            return
        logger.debug('process mix.str')
        pyarmor_core_240 = pyarmor_core_241(pyarmor_core_22.o_includes, pyarmor_core_22.o_excludes)
        pyarmor_core_243 = pyarmor_core_225()
        pyarmor_core_244 = pyarmor_core_245(pyarmor_core_106.mtree)
        pyarmor_core_254 = pyarmor_core_22.oi_threshold

        def pyarmor_core_255(pyarmor_core_44):
            return isinstance(pyarmor_core_44, str) and len(pyarmor_core_44) > pyarmor_core_254

        def pyarmor_core_256(pyarmor_core_226):
            return isinstance(pyarmor_core_226, ast.Module) and len(pyarmor_core_226.body) > 1 and isinstance(pyarmor_core_226.body[1], ast.ImportFrom) and (pyarmor_core_226.body[1].module == '__future__') and (ast.get_docstring(pyarmor_core_226) is not None) and pyarmor_core_226.body[0]
        pyarmor_core_257 = pyarmor_core_224
        if hasattr(ast, 'MatchValue'):
            pyarmor_core_257 += (ast.MatchValue,)
        pyarmor_core_258 = []
        pyarmor_core_259 = pyarmor_core_256(pyarmor_core_106.mtree)
        if pyarmor_core_259:
            pyarmor_core_258.append(pyarmor_core_259)
            if hasattr(pyarmor_core_259, 'value'):
                pyarmor_core_258.append(pyarmor_core_259.value)
        for pyarmor_core_226 in pyarmor_core_244.travel(pyarmor_core_257):
            if pyarmor_core_226 in pyarmor_core_258:
                logger.debug('ingore docstring')
            elif isinstance(pyarmor_core_226, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                if ast.get_docstring(pyarmor_core_226, clean=False):
                    pyarmor_core_259 = pyarmor_core_226.body[0]
                    pyarmor_core_258.append(pyarmor_core_259)
                    if hasattr(pyarmor_core_259, 'value'):
                        pyarmor_core_258.append(pyarmor_core_259.value)
            elif pyarmor_core_226 and isinstance(pyarmor_core_226, pyarmor_core_22.STR_NODE_TYPES):
                pyarmor_core_44 = getattr(pyarmor_core_226, 'value', getattr(pyarmor_core_226, 's', None))
                if pyarmor_core_255(pyarmor_core_44) and pyarmor_core_240.check(pyarmor_core_44):
                    pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_226, repr(pyarmor_core_44))
                    pyarmor_core_228 = pyarmor_core_22.mix_node(pyarmor_core_226, pyarmor_core_44)
                    if pyarmor_core_228:
                        pyarmor_core_229 = pyarmor_core_244.top
                        pyarmor_core_243.patch_str(pyarmor_core_229, pyarmor_core_226, pyarmor_core_228)

class pyarmor_core_138(Component):
    _Catalog = 'builder'
    LOGNAME = 'trace.co'

    def _body_start(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_9 = 1 if ast.get_docstring(pyarmor_core_226) else 0
        for pyarmor_core_38 in pyarmor_core_226.body[pyarmor_core_9:]:
            if isinstance(pyarmor_core_38, ast.ImportFrom) and pyarmor_core_38.module == '__future__':
                pyarmor_core_9 += 1
                continue
            break
        return pyarmor_core_9

    def _fix_lineno(pyarmor_core_22, pyarmor_core_260, pyarmor_core_226, footer=False):
        pyarmor_core_261 = getattr(pyarmor_core_260, 'lineno', 1)
        if footer and pyarmor_core_261 == 1:
            pyarmor_core_261 = 2
        if isinstance(pyarmor_core_226, ast.Module):
            for pyarmor_core_38 in pyarmor_core_226.body:
                ast.increment_lineno(pyarmor_core_38, pyarmor_core_261 - 1)
                ast.fix_missing_locations(pyarmor_core_38)

    def _reform_node(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_262 = pyarmor_core_225()
        pyarmor_core_9 = pyarmor_core_22._body_start(pyarmor_core_226)
        if not pyarmor_core_226.body[pyarmor_core_9:]:
            return
        if pyarmor_core_22._assert_mode:
            pyarmor_core_227 = pyarmor_core_226.body[:pyarmor_core_9]
            pyarmor_core_263 = '__assert_armored__ = lambda _x_:_x_'
            pyarmor_core_264 = ast.parse(pyarmor_core_263)
            pyarmor_core_22._fix_lineno(pyarmor_core_226, pyarmor_core_264)
            pyarmor_core_227.extend(pyarmor_core_264.body)
            pyarmor_core_227.extend(pyarmor_core_226.body[pyarmor_core_9:])
            pyarmor_core_262.patch_body(pyarmor_core_226, pyarmor_core_227)
            return
        pyarmor_core_227 = pyarmor_core_226.body[:pyarmor_core_9]
        pyarmor_core_265 = pyarmor_core_262.next_argname()
        pyarmor_core_263 = '\n'.join(['__assert_armored__ = lambda _x_:_x_', '(lambda _x_:1976)(%r)' % pyarmor_core_265])
        pyarmor_core_264 = ast.parse(pyarmor_core_263)
        pyarmor_core_22._fix_lineno(pyarmor_core_226, pyarmor_core_264)
        pyarmor_core_227.extend(pyarmor_core_264.body)
        if pyarmor_core_22.oi_wrap_mode:
            pyarmor_core_266 = ast.parse('(lambda _y_:_y_)(%r)' % pyarmor_core_265)
            pyarmor_core_22._fix_lineno(pyarmor_core_226.body[-1], pyarmor_core_266, footer=True)
            pyarmor_core_267 = ast.Try(pyarmor_core_226.body[pyarmor_core_9:], [], [], pyarmor_core_266.body)
            ast.copy_location(pyarmor_core_267, pyarmor_core_226)
            ast.fix_missing_locations(pyarmor_core_267)
            pyarmor_core_227.append(pyarmor_core_267)
        else:
            pyarmor_core_227.extend(pyarmor_core_226.body[pyarmor_core_9:])
        pyarmor_core_262.patch_body(pyarmor_core_226, pyarmor_core_227)

    def _filter(pyarmor_core_22, pyarmor_core_226):

        def pyarmor_core_268(pyarmor_core_226):
            return not pyarmor_core_226.body or (len(pyarmor_core_226.body) == 1 and isinstance(pyarmor_core_226.body[0], ast.Pass))
        pyarmor_core_193 = (ast.ClassDef, ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
        return isinstance(pyarmor_core_226, pyarmor_core_193) and (not getattr(pyarmor_core_226, 'HIDDEN_NODE', 0))

    def _hook_script(pyarmor_core_22, pyarmor_core_106, pyarmor_core_269):
        logger.debug('install runtime hook')
        pyarmor_core_9 = pyarmor_core_22._body_start(pyarmor_core_106.mtree)
        pyarmor_core_238 = ast.parse(pyarmor_core_269, pyarmor_core_106.pkgname, 'exec')
        for pyarmor_core_38 in pyarmor_core_238.body:
            ast.fix_missing_locations(pyarmor_core_38)
        pyarmor_core_225().patch_hook(pyarmor_core_106.mtree, pyarmor_core_238, pyarmor_core_9)

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_22._assert_mode = False
        if not pyarmor_core_22.oi_obf_code:
            pyarmor_core_22._assert_mode = any([pyarmor_core_22.ob_enable_rft, pyarmor_core_22.ob_assert_call, pyarmor_core_22.ob_assert_import, pyarmor_core_22.ob_mix_str])
            if not pyarmor_core_22._assert_mode:
                return
        logger.debug('process co')
        pyarmor_core_106.recompile(optimize=pyarmor_core_22.oi_optimize)
        pyarmor_core_269 = pyarmor_core_22.ctx.runtime_hook(pyarmor_core_106.pkgname)
        if pyarmor_core_269:
            pyarmor_core_22._hook_script(pyarmor_core_106, pyarmor_core_269)
        pyarmor_core_244 = pyarmor_core_245(pyarmor_core_106.mtree)
        pyarmor_core_22._reform_node(pyarmor_core_106.mtree)
        for pyarmor_core_226 in pyarmor_core_244.travel():
            if pyarmor_core_22._filter(pyarmor_core_226) and pyarmor_core_226 not in pyarmor_core_106.exclude_nodes:
                pyarmor_core_22._reform_node(pyarmor_core_226)

class pyarmor_core_139(pyarmor_core_138):
    LOGNAME = 'trace.co.attr'

    def __init__(pyarmor_core_22, pyarmor_core_23, imptbl=None):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.imptbl = imptbl
        pyarmor_core_270 = (ast.MatchValue,) if hasattr(ast, 'MatchValue') else ()
        pyarmor_core_22.ignore_node_types = pyarmor_core_224 + pyarmor_core_270
        pyarmor_core_22.ignore_attrs = ('ctx', 'annotation')
        if pyarmor_core_23.python_version[1] == 12:
            pyarmor_core_22.ignore_attrs += ('bases',)

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        logger.debug('process attribute')
        pyarmor_core_271 = pyarmor_core_22.oi_obf_code > 1
        pyarmor_core_1 = pyarmor_core_22.imptbl

        def pyarmor_core_272(pyarmor_core_44):
            if pyarmor_core_271:
                pyarmor_core_44 = b'\x81' + pyarmor_core_1['generate_module_data'](pyarmor_core_1['self'], pyarmor_core_22.ctx, pyarmor_core_44, 3)
            return ast.Constant(pyarmor_core_44)

        def pyarmor_core_273(pyarmor_core_226):
            return pyarmor_core_226.attr[:2] != '__'
        pyarmor_core_243 = pyarmor_core_225()
        pyarmor_core_244 = pyarmor_core_245(pyarmor_core_106.mtree)
        pyarmor_core_274 = []
        pyarmor_core_275 = []
        for pyarmor_core_226 in pyarmor_core_244.travel(ignored=pyarmor_core_22.ignore_node_types, noattrs=pyarmor_core_22.ignore_attrs):
            if isinstance(pyarmor_core_226, ast.Attribute):
                if isinstance(pyarmor_core_226.ctx, ast.Load) and pyarmor_core_273(pyarmor_core_226):
                    pyarmor_core_274.append((pyarmor_core_226, pyarmor_core_244.top))
            elif isinstance(pyarmor_core_226, ast.Assign) and len(pyarmor_core_226.targets) == 1 and isinstance(pyarmor_core_226.targets[0], ast.Attribute) and pyarmor_core_273(pyarmor_core_226.targets[0]):
                pyarmor_core_275.append((pyarmor_core_226, pyarmor_core_244.top))
        for (pyarmor_core_226, pyarmor_core_229) in reversed(pyarmor_core_274):
            pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_226, pyarmor_core_226.attr)
            pyarmor_core_276 = [pyarmor_core_226.value, pyarmor_core_272(pyarmor_core_226.attr)]
            pyarmor_core_228 = ast.Call(ast.Name(id='__assert_armored__', ctx=ast.Load()), [ast.Tuple(pyarmor_core_276, ctx=ast.Load())], [])
            ast.copy_location(pyarmor_core_228, pyarmor_core_226)
            ast.fix_missing_locations(pyarmor_core_228)
            pyarmor_core_243.patch_attr(pyarmor_core_229, pyarmor_core_228)
        for (pyarmor_core_226, pyarmor_core_229) in pyarmor_core_275:
            pyarmor_core_88 = pyarmor_core_226.targets[0]
            pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_226, '(%s)' % pyarmor_core_88.attr)
            pyarmor_core_276 = [pyarmor_core_88.value, pyarmor_core_272(pyarmor_core_88.attr), pyarmor_core_226.value]
            pyarmor_core_228 = ast.Expr(ast.Call(ast.Name(id='__assert_armored__', ctx=ast.Load()), [ast.Tuple(pyarmor_core_276, ctx=ast.Load())], []))
            ast.copy_location(pyarmor_core_228, pyarmor_core_226)
            ast.fix_missing_locations(pyarmor_core_228)
            pyarmor_core_243.patch_attr(pyarmor_core_229, pyarmor_core_228)

class pyarmor_core_277(Component):
    _Catalog = 'builder'
    LOGNAME = 'cli.vmc'

    def __init__(pyarmor_core_22, pyarmor_core_23, imptbl=None):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.imptbl = imptbl

    @resoptions
    def process(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_278 = pyarmor_core_106.mtree
        pyarmor_core_279 = pyarmor_core_280()
        pyarmor_core_279.visit(pyarmor_core_278)
        ast.fix_missing_locations(pyarmor_core_278)
        pyarmor_core_106.vmcblocks = pyarmor_core_279.f_blocks
import dis
from struct import pack, unpack
from random import randint, choice as randchoice
pyarmor_core_281 = 12
pyarmor_core_282 = dis.opmap['NOP']
pyarmor_core_283 = dis.opmap['POP_TOP']
pyarmor_core_284 = dis.opmap['LOAD_CONST']
pyarmor_core_285 = dis.opmap['STORE_FAST']
pyarmor_core_286 = dis.opmap['RETURN_VALUE']
pyarmor_core_287 = dis.opmap['EXTENDED_ARG']
pyarmor_core_288 = [randint(1, 65535)]

def pyarmor_core_289(pyarmor_core_102):
    pyarmor_core_288[0] = pyarmor_core_288[0] + 1
    return '__pyarmor_%s_%s__' % (pyarmor_core_102, pyarmor_core_288[0])

def pyarmor_core_290(pyarmor_core_123):
    pyarmor_core_291 = (b'd\x00S\x00', b'\x97\x00d\x00S\x00', b'\x95\x00U\x00$\x00')
    pyarmor_core_291 = (b'|\x00S\x00', b'\x97\x00|\x00S\x00', b'\x95\x00U\x00$\x00', b'\x80\x00V\x00#\x00')
    return pyarmor_core_123 and hasattr(pyarmor_core_123, 'co_name') and (pyarmor_core_123.co_name == '<lambda>') and (pyarmor_core_123.co_consts == (None,)) and (pyarmor_core_123.co_code in pyarmor_core_291) and (len(pyarmor_core_123.co_varnames) == 1) and (pyarmor_core_123.co_varnames[0] in ('_x_', '_y_'))

def pyarmor_core_293(pyarmor_core_292):
    return isinstance(pyarmor_core_292, str) and pyarmor_core_292.endswith('<lambda>')

def pyarmor_core_294(pyarmor_core_220, pyarmor_core_44):
    pyarmor_core_295 = [] if pyarmor_core_44 else [0]
    while pyarmor_core_44:
        pyarmor_core_295.insert(0, pyarmor_core_44 & 255)
        pyarmor_core_44 >>= 8
    pyarmor_core_295.insert(0, len(pyarmor_core_295) - 1 << 6 | pyarmor_core_220)
    return pyarmor_core_295

def pyarmor_core_297(pyarmor_core_296):
    return 4 if pyarmor_core_296 > 16777215 else 3 if pyarmor_core_296 > 65535 else 2 if pyarmor_core_296 > 255 else 1

def pyarmor_core_300(pyarmor_core_298, pyarmor_core_16, pyarmor_core_299, pyarmor_core_296):
    if pyarmor_core_296 > 4294967295:
        raise RuntimeError('oparg overflow')
    pyarmor_core_3 = 3 if pyarmor_core_296 > 16777215 else 2 if pyarmor_core_296 > 65535 else 1 if pyarmor_core_296 > 255 else 0
    for pyarmor_core_33 in range(pyarmor_core_3, 0, -1):
        pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_287, pyarmor_core_296 >> pyarmor_core_33 * 8 & 255)
        pyarmor_core_16 += 2
    pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_299, pyarmor_core_296 & 255)
    return pyarmor_core_16 + 2

def pyarmor_core_301(pyarmor_core_298, pyarmor_core_16, pyarmor_core_299, pyarmor_core_296):
    if pyarmor_core_296 > 4294967295:
        raise RuntimeError('oparg overflow')
    pyarmor_core_3 = 3 if pyarmor_core_296 > 16777215 else 2 if pyarmor_core_296 > 65535 else 1 if pyarmor_core_296 > 255 else 0
    pyarmor_core_33 = 3 - pyarmor_core_3
    while pyarmor_core_33:
        pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_282, 0)
        pyarmor_core_16 += 2
        pyarmor_core_33 -= 1
    for pyarmor_core_33 in range(pyarmor_core_3, 0, -1):
        pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_287, pyarmor_core_296 >> pyarmor_core_33 * 8 & 255)
        pyarmor_core_16 += 2
    pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_299, pyarmor_core_296 & 255)
    return pyarmor_core_16 + 2

def pyarmor_core_302(pyarmor_core_123, msg='invalid v8 code'):
    logger.debug('%s caused by %s:%s:%s', msg, pyarmor_core_123.co_filename, pyarmor_core_123.co_firstlineno, pyarmor_core_123.co_name)
    raise RuntimeError(msg)

def pyarmor_core_304(pyarmor_core_123, pyarmor_core_303):
    logger.debug('special co "%s" at %s:%s:%s', pyarmor_core_303, pyarmor_core_123.co_filename, pyarmor_core_123.co_firstlineno, pyarmor_core_123.co_name)

class pyarmor_core_305(object):

    def __init__(pyarmor_core_22):
        pyarmor_core_22.headsize = 0
        pyarmor_core_22.footsize = 0

    def __str__(pyarmor_core_22):
        return '\n'.join(['{0}: {1}'.format(pyarmor_core_38, getattr(pyarmor_core_22, pyarmor_core_38, None)) for pyarmor_core_38 in ('headsize', 'footsize', 'footpos', 'footpos2', 'refins', 'endins2', 'valueins2', 'assertindex', 'argindex', 'enterindex', 'exitindex')])

class pyarmor_core_131(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_306 = pyarmor_core_22.ctx.inline_plugin_marker
        if pyarmor_core_306:
            logger.debug('process inline marker')
            pyarmor_core_106.lines = [pyarmor_core_39.replace(pyarmor_core_306, '') for pyarmor_core_39 in pyarmor_core_106.lines]
            return pyarmor_core_106.lines

class pyarmor_core_307(Component):

    def _match_ins(pyarmor_core_22, pyarmor_core_308, pyarmor_core_309):
        try:
            for pyarmor_core_102 in pyarmor_core_309:
                pyarmor_core_310 = next(pyarmor_core_308)
                if pyarmor_core_310.opname != pyarmor_core_102:
                    return
            return next(pyarmor_core_308)
        except StopIteration:
            pass

    def _next_ins(pyarmor_core_22, pyarmor_core_308, pyarmor_core_303):
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_303 == pyarmor_core_310.opname:
                return pyarmor_core_310

    def _is_armor_ins(pyarmor_core_22, pyarmor_core_38):
        return pyarmor_core_38 and pyarmor_core_38.opname == 'LOAD_CONST' and pyarmor_core_290(pyarmor_core_38.argval)

    def trace(pyarmor_core_22, pyarmor_core_106, pyarmor_core_123):
        pyarmor_core_261 = pyarmor_core_123.co_firstlineno
        pyarmor_core_22.logger.info('%s:%s:%s', pyarmor_core_106.fullname, pyarmor_core_261, pyarmor_core_123.co_name)

class pyarmor_core_142(pyarmor_core_307):
    LOGNAME = 'trace.bcc'

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.impt = pyarmor_core_1
        pyarmor_core_22._bccdata = None

    def _is_patched_ins(pyarmor_core_22, pyarmor_core_310):
        return pyarmor_core_310 and pyarmor_core_310.opname == 'STORE_FAST' and (pyarmor_core_310.argval == '__assert_bcc__')

    def _find_co_data(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_220 = 0
        for (pyarmor_core_261, pyarmor_core_311) in pyarmor_core_22._bccdata:
            if pyarmor_core_261 == pyarmor_core_123.co_firstlineno:
                return (pyarmor_core_220, pyarmor_core_311)
            pyarmor_core_220 += 1
        pyarmor_core_302(pyarmor_core_123, 'no found bcc data')

    def _patch_co_code_py14(pyarmor_core_22, pyarmor_core_123, pyarmor_core_308, pyarmor_core_298):
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'LOAD_CONST')
        while not pyarmor_core_22._is_armor_ins(pyarmor_core_312):
            pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'LOAD_CONST')
            if not pyarmor_core_312:
                return
        if pyarmor_core_312.arg > 2:
            pyarmor_core_302(pyarmor_core_123, 'invalid bcc code')
        pyarmor_core_310 = next(pyarmor_core_308)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        if pyarmor_core_22.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            pyarmor_core_313 = dis.opmap['CALL_FUNCTION_EX']
            pyarmor_core_314 = dis.opmap['PUSH_NULL']
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'CALL')
            pyarmor_core_9 = pyarmor_core_310.offset
            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + 6] = (pyarmor_core_314, 0, pyarmor_core_313, 0, pyarmor_core_286, 0)
        return pyarmor_core_312

    def _patch_co_code_py13(pyarmor_core_22, pyarmor_core_123, pyarmor_core_308, pyarmor_core_298):
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'LOAD_CONST')
        while not pyarmor_core_22._is_armor_ins(pyarmor_core_312):
            pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'LOAD_CONST')
            if not pyarmor_core_312:
                return
        if pyarmor_core_312.arg > 2:
            pyarmor_core_302(pyarmor_core_123, 'invalid bcc code')
        pyarmor_core_310 = next(pyarmor_core_308)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        if pyarmor_core_22.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            pyarmor_core_313 = dis.opmap['CALL_FUNCTION_EX']
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'CALL')
            pyarmor_core_9 = pyarmor_core_310.offset
            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + 4] = (pyarmor_core_313, 0, pyarmor_core_286, 0)
        return pyarmor_core_312

    def _patch_co_code_py11(pyarmor_core_22, pyarmor_core_123, pyarmor_core_308, pyarmor_core_298):
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_312 = pyarmor_core_22._match_ins(pyarmor_core_308, ['PUSH_NULL'])
        if not pyarmor_core_22._is_armor_ins(pyarmor_core_312):
            return
        if pyarmor_core_312.arg > 2:
            pyarmor_core_302(pyarmor_core_123, 'invalid bcc code')
        pyarmor_core_310 = next(pyarmor_core_308)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        if pyarmor_core_22.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            pyarmor_core_313 = dis.opmap['CALL_FUNCTION_EX']
            pyarmor_core_315 = pyarmor_core_22.ctx.python_version[1] == 11
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'PRECALL' if pyarmor_core_315 else 'CALL')
            pyarmor_core_9 = pyarmor_core_310.offset
            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + 4] = (pyarmor_core_313, 0, pyarmor_core_286, 0)
        return pyarmor_core_312

    def _patch_co_code(pyarmor_core_22, pyarmor_core_123, pyarmor_core_308, pyarmor_core_298):
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_312 = next(pyarmor_core_308)
        if not pyarmor_core_22._is_armor_ins(pyarmor_core_312):
            return
        if pyarmor_core_312.arg > 2:
            pyarmor_core_302(pyarmor_core_123, 'invalid bcc code')
        for pyarmor_core_310 in pyarmor_core_308:
            pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
            if pyarmor_core_310.opname == 'MAKE_FUNCTION':
                break
        if pyarmor_core_22.ctx.cfg.getboolean('bcc', 'call_function_ex'):
            pyarmor_core_313 = dis.opmap['CALL_FUNCTION_EX']
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.opname == 'CALL_FUNCTION':
                    pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_313
                    pyarmor_core_298[pyarmor_core_310.offset + 1] = 0
                    break
        return pyarmor_core_312

    def _patch_co_object(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_149 = pyarmor_core_22.ctx.python_version[1]
        pyarmor_core_3 = 2 if pyarmor_core_149 > 10 else 0
        if pyarmor_core_298[pyarmor_core_3] == dis.opmap['LOAD_GLOBAL']:
            pyarmor_core_16 = 10 if pyarmor_core_149 > 11 else 14 if pyarmor_core_149 > 10 else 3 if pyarmor_core_149 > 9 else 6
            pyarmor_core_298[pyarmor_core_3:pyarmor_core_3 + 2] = (dis.opmap['JUMP_FORWARD'], pyarmor_core_16)
        pyarmor_core_316 = pyarmor_core_22._patch_co_code_py14 if pyarmor_core_149 > 13 else pyarmor_core_22._patch_co_code_py13 if pyarmor_core_149 > 12 else pyarmor_core_22._patch_co_code_py11 if pyarmor_core_149 > 10 else pyarmor_core_22._patch_co_code
        pyarmor_core_312 = pyarmor_core_316(pyarmor_core_123, pyarmor_core_308, pyarmor_core_298)
        if not pyarmor_core_312:
            return
        (pyarmor_core_317, pyarmor_core_318) = pyarmor_core_22._find_co_data(pyarmor_core_123)
        pyarmor_core_319 = list(pyarmor_core_123.co_consts)
        pyarmor_core_319[pyarmor_core_312.arg] = pyarmor_core_289('bcc')
        pyarmor_core_319.append(tuple(pyarmor_core_318))
        pyarmor_core_320 = [1 << pyarmor_core_22.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << pyarmor_core_22.impt['CO_MARSHAL_BCC_CALLER_OFF'], 0, 0, 0]
        pyarmor_core_320.extend(pyarmor_core_294(1, 0))
        pyarmor_core_320.extend(pyarmor_core_294(pyarmor_core_312.arg, pyarmor_core_317))
        pyarmor_core_320.insert(0, len(pyarmor_core_320))
        pyarmor_core_319.append(bytes(pyarmor_core_320))
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_consts', tuple(pyarmor_core_319))
        pyarmor_core_321 = pyarmor_core_123.co_flags | pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_flags', pyarmor_core_321)
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_code', pyarmor_core_298)

    def handle(pyarmor_core_22, pyarmor_core_106):
        if not getattr(pyarmor_core_106, 'bccdata', None):
            return
        logger.debug('patch bcc')
        pyarmor_core_22._bccdata = pyarmor_core_106.bccdata

        def pyarmor_core_322(pyarmor_core_123):
            pyarmor_core_22._patch_co_object(pyarmor_core_123)
            for pyarmor_core_38 in pyarmor_core_123.co_consts:
                if type(pyarmor_core_38) == type(pyarmor_core_123) and (not pyarmor_core_290(pyarmor_core_38)):
                    pyarmor_core_322(pyarmor_core_38)
        pyarmor_core_322(pyarmor_core_106.mco)

class pyarmor_core_144(pyarmor_core_307):
    LOGNAME = 'trace.co'
    _Catalog = 'builder'

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.impt = pyarmor_core_1

    def _is_patched_ins(pyarmor_core_22, pyarmor_core_310):
        return pyarmor_core_310 and pyarmor_core_310.opname in ('STORE_FAST', 'STORE_NAME') and (pyarmor_core_310.argval == '__assert_armored__')

    def _patch_co_code_py31X(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        pyarmor_core_323 = False
        pyarmor_core_324 = pyarmor_core_305()
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)

        def pyarmor_core_326(pyarmor_core_33):
            pyarmor_core_298[pyarmor_core_33:pyarmor_core_33 + 2] = (pyarmor_core_282, randint(0, 255))
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_327 = pyarmor_core_310.opcode
        pyarmor_core_328 = pyarmor_core_310.offset - 6
        pyarmor_core_324.assertindex = pyarmor_core_298[3 + pyarmor_core_328]
        if not pyarmor_core_290(pyarmor_core_123.co_consts[pyarmor_core_324.assertindex]):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_329 = pyarmor_core_298[7 + pyarmor_core_328]
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
        if pyarmor_core_310.offset != 24 + pyarmor_core_328:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.enterindex = pyarmor_core_298[9 + pyarmor_core_328]
        pyarmor_core_324.argindex = pyarmor_core_298[15 + pyarmor_core_328]
        pyarmor_core_324.headsize = pyarmor_core_310.offset + 2
        pyarmor_core_330 = dis.opmap['RESUME']
        if pyarmor_core_324.headsize > 255:
            pyarmor_core_298[:18] = (pyarmor_core_284, pyarmor_core_324.enterindex, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, pyarmor_core_284, pyarmor_core_324.assertindex, pyarmor_core_327, pyarmor_core_329)
            pyarmor_core_324.headsize = pyarmor_core_310.offset - pyarmor_core_328 + 2
            assert pyarmor_core_324.headsize >= 18
            for pyarmor_core_3 in range(18, pyarmor_core_324.headsize, 2):
                pyarmor_core_326(pyarmor_core_3)
            pyarmor_core_298[pyarmor_core_310.offset - pyarmor_core_328:pyarmor_core_310.offset] = pyarmor_core_123.co_code[:pyarmor_core_328]
            if pyarmor_core_323:
                pyarmor_core_298[pyarmor_core_310.offset:pyarmor_core_310.offset + 2] = (pyarmor_core_330, 0)
            else:
                pyarmor_core_326(pyarmor_core_310.offset)
            pyarmor_core_328 = 0
        else:
            if pyarmor_core_298[pyarmor_core_328] == pyarmor_core_330:
                pyarmor_core_326(pyarmor_core_328)
            else:
                pyarmor_core_331 = [pyarmor_core_3 for pyarmor_core_3 in range(0, 1 + pyarmor_core_328, 2) if pyarmor_core_298[pyarmor_core_3] == pyarmor_core_330]
                if len(pyarmor_core_331) != 1:
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_298[pyarmor_core_331[0]] = pyarmor_core_282
            pyarmor_core_326(2 + pyarmor_core_328)
            pyarmor_core_298[4 + pyarmor_core_328:24 + pyarmor_core_328] = (pyarmor_core_284, pyarmor_core_324.enterindex, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'] if pyarmor_core_323 else pyarmor_core_282, 0, pyarmor_core_284, pyarmor_core_324.assertindex, pyarmor_core_327, pyarmor_core_329)
            for pyarmor_core_3 in range(24 + pyarmor_core_328, pyarmor_core_310.offset + 2, 2):
                pyarmor_core_326(pyarmor_core_3)
        if no_wrap:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
            pyarmor_core_324.footsize = 0
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_332 = iter(reversed(list(pyarmor_core_308)))
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        if pyarmor_core_310 is None:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        if not pyarmor_core_290(pyarmor_core_312.argval):
            pyarmor_core_302(pyarmor_core_123)
        if pyarmor_core_310.offset - pyarmor_core_312.offset != 2:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_312.arg
        pyarmor_core_333 = pyarmor_core_297(pyarmor_core_324.exitindex)
        pyarmor_core_298[pyarmor_core_312.offset] = pyarmor_core_284
        assert pyarmor_core_298[pyarmor_core_312.offset + 6] == pyarmor_core_284
        pyarmor_core_298[pyarmor_core_312.offset + 6] = pyarmor_core_284
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'PUSH_EXC_INFO')
        if pyarmor_core_310 is None or pyarmor_core_312.offset - pyarmor_core_310.offset != 2 * pyarmor_core_333:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.footpos = pyarmor_core_310.offset
        pyarmor_core_334 = len(pyarmor_core_123.co_code)
        pyarmor_core_335 = dis.opmap['JUMP_FORWARD']
        while pyarmor_core_310 and pyarmor_core_310.offset > pyarmor_core_324.headsize:
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
            if pyarmor_core_310 and pyarmor_core_310.arg == pyarmor_core_312.arg:
                pyarmor_core_9 = pyarmor_core_310.offset - 2 * pyarmor_core_333 + 2
                pyarmor_core_336 = pyarmor_core_310.offset + 18
                assert pyarmor_core_298[pyarmor_core_336 - 2] == pyarmor_core_283
                pyarmor_core_337 = 0
                while pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] != pyarmor_core_286:
                    pyarmor_core_337 += 2
                pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337]
                pyarmor_core_9 += pyarmor_core_337
                pyarmor_core_338 = pyarmor_core_334 - pyarmor_core_9 - 8 >> 1
                pyarmor_core_301(pyarmor_core_298, pyarmor_core_9, pyarmor_core_335, pyarmor_core_338)
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
        pyarmor_core_339 = [pyarmor_core_284, pyarmor_core_324.exitindex & 255, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['PUSH_NULL'], 0, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        pyarmor_core_340 = pyarmor_core_324.exitindex >> 8
        while pyarmor_core_340:
            pyarmor_core_339[0:0] = (dis.opmap['EXTENDED_ARG'], pyarmor_core_340 & 255)
            pyarmor_core_340 >>= 8
        pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos + len(pyarmor_core_339)
        pyarmor_core_324.co_code = bytes(pyarmor_core_298) + bytes(pyarmor_core_339)
        return pyarmor_core_324

    def _patch_co_code_py313(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        pyarmor_core_324 = pyarmor_core_305()
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)

        def pyarmor_core_326(pyarmor_core_33):
            pyarmor_core_298[pyarmor_core_33:pyarmor_core_33 + 2] = (pyarmor_core_282, randint(0, 255))
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_327 = pyarmor_core_310.opcode
        pyarmor_core_328 = pyarmor_core_310.offset - 6
        pyarmor_core_324.assertindex = pyarmor_core_298[3 + pyarmor_core_328]
        if not pyarmor_core_290(pyarmor_core_123.co_consts[pyarmor_core_324.assertindex]):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_329 = pyarmor_core_298[7 + pyarmor_core_328]
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
        if pyarmor_core_310.offset != 24 + pyarmor_core_328:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.enterindex = pyarmor_core_298[9 + pyarmor_core_328]
        pyarmor_core_324.argindex = pyarmor_core_298[15 + pyarmor_core_328]
        pyarmor_core_324.headsize = pyarmor_core_310.offset + 2
        pyarmor_core_330 = dis.opmap['RESUME']
        if pyarmor_core_324.headsize > 255:
            pyarmor_core_298[:16] = (pyarmor_core_284, pyarmor_core_324.enterindex, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, pyarmor_core_284, pyarmor_core_324.assertindex, pyarmor_core_327, pyarmor_core_329)
            pyarmor_core_324.headsize = pyarmor_core_310.offset - pyarmor_core_328 + 2
            for pyarmor_core_3 in range(16, pyarmor_core_324.headsize, 2):
                pyarmor_core_326(pyarmor_core_3)
            pyarmor_core_298[pyarmor_core_310.offset - pyarmor_core_328:pyarmor_core_310.offset] = pyarmor_core_123.co_code[:pyarmor_core_328]
            pyarmor_core_298[pyarmor_core_310.offset:pyarmor_core_310.offset + 2] = (pyarmor_core_330, 0)
            pyarmor_core_328 = 0
        else:
            if pyarmor_core_298[pyarmor_core_328] == pyarmor_core_330:
                pyarmor_core_326(pyarmor_core_328)
            else:
                pyarmor_core_331 = [pyarmor_core_3 for pyarmor_core_3 in range(0, 1 + pyarmor_core_328, 2) if pyarmor_core_298[pyarmor_core_3] == pyarmor_core_330]
                if len(pyarmor_core_331) != 1:
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_298[pyarmor_core_331[0]] = pyarmor_core_282
            pyarmor_core_326(2 + pyarmor_core_328)
            pyarmor_core_298[4 + pyarmor_core_328:22 + pyarmor_core_328] = (pyarmor_core_284, pyarmor_core_324.enterindex, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0, pyarmor_core_284, pyarmor_core_324.assertindex, pyarmor_core_327, pyarmor_core_329)
            for pyarmor_core_3 in range(22 + pyarmor_core_328, pyarmor_core_310.offset + 2, 2):
                pyarmor_core_326(pyarmor_core_3)
        if no_wrap:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
            pyarmor_core_324.footsize = 0
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_332 = iter(reversed(list(pyarmor_core_308)))
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        if pyarmor_core_310 is None:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        if not pyarmor_core_290(pyarmor_core_312.argval):
            pyarmor_core_302(pyarmor_core_123)
        if pyarmor_core_310.offset - pyarmor_core_312.offset != 2:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_312.arg
        pyarmor_core_333 = pyarmor_core_297(pyarmor_core_324.exitindex)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'PUSH_EXC_INFO')
        if pyarmor_core_310 is None or pyarmor_core_312.offset - pyarmor_core_310.offset != 2 * pyarmor_core_333:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.footpos = pyarmor_core_310.offset
        pyarmor_core_334 = len(pyarmor_core_123.co_code)
        pyarmor_core_335 = dis.opmap['JUMP_FORWARD']
        pyarmor_core_341 = dis.opmap['COPY']
        pyarmor_core_342 = dis.opmap['LOAD_CLOSURE']
        pyarmor_core_343 = dis.opmap['LOAD_FAST']
        while pyarmor_core_310 and pyarmor_core_310.offset > pyarmor_core_324.headsize:
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
            if pyarmor_core_310 and pyarmor_core_310.arg == pyarmor_core_312.arg:
                pyarmor_core_9 = pyarmor_core_310.offset - 2 * pyarmor_core_333 + 2
                pyarmor_core_336 = pyarmor_core_310.offset + 18
                pyarmor_core_337 = 0
                pyarmor_core_344 = pyarmor_core_298[pyarmor_core_336]
                while pyarmor_core_344 == pyarmor_core_287:
                    pyarmor_core_337 += 2
                    pyarmor_core_344 = pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337]
                if pyarmor_core_344 == dis.opmap['RETURN_CONST']:
                    pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337 + 2] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337 + 2]
                    pyarmor_core_298[pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_284
                    pyarmor_core_9 += pyarmor_core_337 + 2
                elif pyarmor_core_344 in (pyarmor_core_342, pyarmor_core_284):
                    pyarmor_core_345 = (pyarmor_core_342, pyarmor_core_343, pyarmor_core_284)
                    while pyarmor_core_344 in pyarmor_core_345:
                        pyarmor_core_337 += 4 if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337 + 2] == pyarmor_core_341 else 2
                        while pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == pyarmor_core_287:
                            pyarmor_core_337 += 2
                        if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] != dis.opmap['STORE_NAME']:
                            pyarmor_core_302(pyarmor_core_123)
                        pyarmor_core_337 += 2
                        if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == dis.opmap['RETURN_VALUE']:
                            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337]
                            break
                        else:
                            while pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == pyarmor_core_287:
                                pyarmor_core_337 += 2
                            if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] in pyarmor_core_345:
                                continue
                            if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] != dis.opmap['RETURN_CONST']:
                                pyarmor_core_302(pyarmor_core_123)
                            pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] = pyarmor_core_284
                            pyarmor_core_337 += 2
                            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337]
                            break
                    pyarmor_core_9 += pyarmor_core_337
                elif pyarmor_core_344 not in (dis.opmap['RETURN_VALUE'],):
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_338 = pyarmor_core_334 - pyarmor_core_9 - 8 >> 1
                pyarmor_core_301(pyarmor_core_298, pyarmor_core_9, pyarmor_core_335, pyarmor_core_338)
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
        pyarmor_core_339 = [pyarmor_core_284, pyarmor_core_324.exitindex & 255, dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        pyarmor_core_340 = pyarmor_core_324.exitindex >> 8
        while pyarmor_core_340:
            pyarmor_core_339[0:0] = (dis.opmap['EXTENDED_ARG'], pyarmor_core_340 & 255)
            pyarmor_core_340 >>= 8
        pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos + len(pyarmor_core_339)
        pyarmor_core_324.co_code = bytes(pyarmor_core_298) + bytes(pyarmor_core_339)
        return pyarmor_core_324

    def _patch_co_code_py312(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        pyarmor_core_324 = pyarmor_core_305()
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)

        def pyarmor_core_326(pyarmor_core_33):
            pyarmor_core_298[pyarmor_core_33:pyarmor_core_33 + 2] = (pyarmor_core_282, randint(0, 255))
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_328 = pyarmor_core_310.offset - 6
        pyarmor_core_324.assertindex = pyarmor_core_298[3 + pyarmor_core_328]
        if not pyarmor_core_290(pyarmor_core_123.co_consts[pyarmor_core_324.assertindex]):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
        if pyarmor_core_310.offset != 24 + pyarmor_core_328:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.enterindex = pyarmor_core_298[11 + pyarmor_core_328]
        pyarmor_core_324.argindex = pyarmor_core_298[15 + pyarmor_core_328]
        pyarmor_core_324.headsize = pyarmor_core_310.offset + 2
        pyarmor_core_330 = dis.opmap['RESUME']
        if pyarmor_core_324.headsize > 255:
            pyarmor_core_298[:12] = (dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.enterindex, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0)
            pyarmor_core_324.headsize = pyarmor_core_310.offset - pyarmor_core_328 + 2
            for pyarmor_core_3 in range(12, pyarmor_core_324.headsize, 2):
                pyarmor_core_326(pyarmor_core_3)
            pyarmor_core_298[pyarmor_core_310.offset - pyarmor_core_328:pyarmor_core_310.offset] = pyarmor_core_123.co_code[:pyarmor_core_328]
            pyarmor_core_298[pyarmor_core_310.offset:pyarmor_core_310.offset + 2] = (pyarmor_core_330, 0)
            pyarmor_core_328 = 0
        else:
            if pyarmor_core_298[pyarmor_core_328] == pyarmor_core_330:
                pyarmor_core_326(pyarmor_core_328)
            else:
                pyarmor_core_331 = [pyarmor_core_3 for pyarmor_core_3 in range(0, 1 + pyarmor_core_328, 2) if pyarmor_core_298[pyarmor_core_3] == pyarmor_core_330]
                if len(pyarmor_core_331) != 1:
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_298[pyarmor_core_331[0]] = pyarmor_core_282
            pyarmor_core_326(2 + pyarmor_core_328)
            pyarmor_core_298[4 + pyarmor_core_328:18 + pyarmor_core_328] = (dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.enterindex, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0)
            for pyarmor_core_3 in range(18 + pyarmor_core_328, pyarmor_core_310.offset + 2, 2):
                pyarmor_core_326(pyarmor_core_3)
        if no_wrap:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
            pyarmor_core_324.footsize = 0
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_332 = iter(reversed(list(pyarmor_core_308)))
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        if pyarmor_core_310 is None:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        if not pyarmor_core_290(pyarmor_core_312.argval):
            pyarmor_core_302(pyarmor_core_123)
        if pyarmor_core_310.offset - pyarmor_core_312.offset != 2:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_312.arg
        pyarmor_core_333 = pyarmor_core_297(pyarmor_core_324.exitindex)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'PUSH_EXC_INFO')
        if pyarmor_core_310 is None or pyarmor_core_312.offset - pyarmor_core_310.offset != 2 + 2 * pyarmor_core_333:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.footpos = pyarmor_core_310.offset
        pyarmor_core_334 = len(pyarmor_core_123.co_code)
        pyarmor_core_335 = dis.opmap['JUMP_FORWARD']
        pyarmor_core_341 = dis.opmap['COPY']
        pyarmor_core_342 = dis.opmap['LOAD_CLOSURE']
        while pyarmor_core_310 and pyarmor_core_310.offset > pyarmor_core_324.headsize:
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
            if pyarmor_core_310 and pyarmor_core_310.arg == pyarmor_core_312.arg:
                pyarmor_core_9 = pyarmor_core_310.offset - 2 * pyarmor_core_333
                pyarmor_core_336 = pyarmor_core_310.offset + 16
                pyarmor_core_337 = 0
                pyarmor_core_344 = pyarmor_core_298[pyarmor_core_336]
                while pyarmor_core_344 == pyarmor_core_287:
                    pyarmor_core_337 += 2
                    pyarmor_core_344 = pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337]
                if pyarmor_core_344 == dis.opmap['RETURN_CONST']:
                    pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337 + 2] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337 + 2]
                    pyarmor_core_298[pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_284
                    pyarmor_core_9 += pyarmor_core_337 + 2
                elif pyarmor_core_344 in (pyarmor_core_342, pyarmor_core_284):
                    pyarmor_core_345 = (pyarmor_core_342, pyarmor_core_284)
                    while pyarmor_core_344 in pyarmor_core_345:
                        pyarmor_core_337 += 4 if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337 + 2] == pyarmor_core_341 else 2
                        while pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == pyarmor_core_287:
                            pyarmor_core_337 += 2
                        if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] != dis.opmap['STORE_NAME']:
                            pyarmor_core_302(pyarmor_core_123)
                        pyarmor_core_337 += 2
                        if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == dis.opmap['RETURN_VALUE']:
                            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337]
                            break
                        else:
                            while pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] == pyarmor_core_287:
                                pyarmor_core_337 += 2
                            if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] in pyarmor_core_345:
                                continue
                            if pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] != dis.opmap['RETURN_CONST']:
                                pyarmor_core_302(pyarmor_core_123)
                            pyarmor_core_298[pyarmor_core_336 + pyarmor_core_337] = pyarmor_core_284
                            pyarmor_core_337 += 2
                            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_337] = pyarmor_core_298[pyarmor_core_336:pyarmor_core_336 + pyarmor_core_337]
                            break
                    pyarmor_core_9 += pyarmor_core_337
                elif pyarmor_core_344 not in (dis.opmap['RETURN_VALUE'],):
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_338 = pyarmor_core_334 - pyarmor_core_9 - 8 >> 1
                pyarmor_core_301(pyarmor_core_298, pyarmor_core_9, pyarmor_core_335, pyarmor_core_338)
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
        pyarmor_core_339 = [dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.exitindex & 255, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0]
        pyarmor_core_340 = pyarmor_core_324.exitindex >> 8
        while pyarmor_core_340:
            pyarmor_core_339[2:2] = (dis.opmap['EXTENDED_ARG'], pyarmor_core_340 & 255)
            pyarmor_core_340 >>= 8
        pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos + len(pyarmor_core_339)
        pyarmor_core_324.co_code = bytes(pyarmor_core_298) + bytes(pyarmor_core_339)
        return pyarmor_core_324

    def _patch_co_code_py311(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        pyarmor_core_324 = pyarmor_core_305()
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)

        def pyarmor_core_326(pyarmor_core_33):
            pyarmor_core_298[pyarmor_core_33:pyarmor_core_33 + 2] = (pyarmor_core_282, randint(0, 255))
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_328 = pyarmor_core_310.offset - 6
        pyarmor_core_324.assertindex = pyarmor_core_298[3 + pyarmor_core_328]
        if not pyarmor_core_290(pyarmor_core_123.co_consts[pyarmor_core_324.assertindex]):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
        if pyarmor_core_310.offset != 30 + pyarmor_core_328:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.enterindex = pyarmor_core_298[11 + pyarmor_core_328]
        pyarmor_core_324.argindex = pyarmor_core_298[15 + pyarmor_core_328]
        pyarmor_core_324.headsize = pyarmor_core_310.offset + 2
        pyarmor_core_330 = dis.opmap['RESUME']
        if pyarmor_core_324.headsize > 255:
            pyarmor_core_298[:12] = (dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.enterindex, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0)
            pyarmor_core_324.headsize = pyarmor_core_310.offset - pyarmor_core_328 + 2
            for pyarmor_core_3 in range(12, pyarmor_core_324.headsize, 2):
                pyarmor_core_326(pyarmor_core_3)
            pyarmor_core_298[pyarmor_core_310.offset - pyarmor_core_328:pyarmor_core_310.offset] = pyarmor_core_123.co_code[:pyarmor_core_328]
            pyarmor_core_298[pyarmor_core_310.offset:pyarmor_core_310.offset + 2] = (pyarmor_core_330, 0)
            pyarmor_core_328 = 0
        else:
            if pyarmor_core_298[pyarmor_core_328] == pyarmor_core_330:
                pyarmor_core_326(pyarmor_core_328)
            else:
                pyarmor_core_331 = [pyarmor_core_3 for pyarmor_core_3 in range(0, 1 + pyarmor_core_328, 2) if pyarmor_core_298[pyarmor_core_3] == pyarmor_core_330]
                if len(pyarmor_core_331) != 1:
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_298[pyarmor_core_331[0]] = pyarmor_core_282
            pyarmor_core_326(2 + pyarmor_core_328)
            pyarmor_core_298[4 + pyarmor_core_328:18 + pyarmor_core_328] = (dis.opmap['PUSH_NULL'], 0, pyarmor_core_284, pyarmor_core_324.enterindex, pyarmor_core_284, pyarmor_core_324.argindex, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RESUME'], 0)
            for pyarmor_core_3 in range(18 + pyarmor_core_328, pyarmor_core_310.offset + 2, 2):
                pyarmor_core_326(pyarmor_core_3)
        if no_wrap:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
            pyarmor_core_324.footsize = 0
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        pyarmor_core_346 = pyarmor_core_310.offset > 28 + pyarmor_core_328
        if pyarmor_core_346:
            pyarmor_core_298[18 + pyarmor_core_328:28 + pyarmor_core_328] = (dis.opmap['JUMP_FORWARD'], 4, dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0)
        if pyarmor_core_325 > 200:
            pyarmor_core_16 = pyarmor_core_325 - 100
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset > pyarmor_core_16:
                    break
        else:
            pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_332 = iter(reversed(list(pyarmor_core_308)))
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        if not pyarmor_core_290(pyarmor_core_312.argval):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_312.arg
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'PUSH_EXC_INFO')
        pyarmor_core_324.footpos = pyarmor_core_310.offset
        pyarmor_core_310 = next(pyarmor_core_332)
        if pyarmor_core_310.opname not in ('RETURN_VALUE',):
            if pyarmor_core_22.oi_wrap_mode == 1 or not pyarmor_core_346:
                pyarmor_core_304(pyarmor_core_123, pyarmor_core_310.opname)
                pyarmor_core_22._patch_raise_varargs_py311(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298)
                pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
                pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos
                pyarmor_core_324.co_code = bytes(pyarmor_core_298)
                return pyarmor_core_324
            return pyarmor_core_22._patch_wrap_co_code_py311(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_328)
        pyarmor_core_324.endins2 = pyarmor_core_310
        pyarmor_core_310 = next(pyarmor_core_332)
        if pyarmor_core_310.opname == 'LOAD_CONST':
            pyarmor_core_324.valueins2 = pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        if not pyarmor_core_310:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        if pyarmor_core_310.arg != pyarmor_core_324.exitindex:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_312 = pyarmor_core_310
        for pyarmor_core_310 in pyarmor_core_332:
            if pyarmor_core_310.opname != 'EXTENDED_ARG':
                break
        if pyarmor_core_310.opname != 'PUSH_NULL':
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.footpos2 = pyarmor_core_310.offset
        pyarmor_core_334 = pyarmor_core_324.footpos2
        if hasattr(pyarmor_core_324, 'valueins2'):
            pyarmor_core_347 = pyarmor_core_324.valueins2.offset
            pyarmor_core_348 = 2
            while pyarmor_core_298[pyarmor_core_347 - pyarmor_core_348] == pyarmor_core_287:
                pyarmor_core_348 += 2
            pyarmor_core_16 = pyarmor_core_324.footpos2
            pyarmor_core_349 = pyarmor_core_324.endins2.offset
            pyarmor_core_298[pyarmor_core_16 + pyarmor_core_348:pyarmor_core_349] = pyarmor_core_298[pyarmor_core_16:pyarmor_core_349 - pyarmor_core_348]
            pyarmor_core_334 += pyarmor_core_348
            pyarmor_core_16 = pyarmor_core_324.footpos2
            pyarmor_core_349 = pyarmor_core_324.endins2.offset
            pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + pyarmor_core_348] = pyarmor_core_123.co_code[pyarmor_core_349 - pyarmor_core_348:pyarmor_core_349]
        pyarmor_core_350 = pyarmor_core_312.offset - pyarmor_core_324.footpos2
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.offset >= pyarmor_core_324.headsize:
                break

        def pyarmor_core_352(pyarmor_core_351, arg=None):
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset > pyarmor_core_324.footpos2:
                    return
                if pyarmor_core_351 == pyarmor_core_310.opname and arg == pyarmor_core_310.arg:
                    return pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_352(pyarmor_core_312.opname, arg=pyarmor_core_312.arg)
        while pyarmor_core_310:
            pyarmor_core_9 = pyarmor_core_310.offset - pyarmor_core_350
            pyarmor_core_353 = pyarmor_core_352('RETURN_VALUE')
            if not pyarmor_core_353:
                pyarmor_core_302(pyarmor_core_123)
            if pyarmor_core_298[pyarmor_core_353.offset - 2] == pyarmor_core_284:
                pyarmor_core_354 = pyarmor_core_353.offset - 2
                while pyarmor_core_298[pyarmor_core_354 - 2] == pyarmor_core_287:
                    pyarmor_core_354 -= 2
                pyarmor_core_355 = pyarmor_core_353.offset - pyarmor_core_354
                pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_355] = pyarmor_core_123.co_code[pyarmor_core_354:pyarmor_core_354 + pyarmor_core_355]
                pyarmor_core_9 += pyarmor_core_355
            assert pyarmor_core_353.offset - pyarmor_core_9 > 8
            pyarmor_core_338 = pyarmor_core_334 - pyarmor_core_9 - 8 >> 1
            pyarmor_core_301(pyarmor_core_298, pyarmor_core_9, dis.opmap['JUMP_FORWARD'], pyarmor_core_338)
            pyarmor_core_310 = pyarmor_core_352(pyarmor_core_312.opname, arg=pyarmor_core_312.arg)
        for pyarmor_core_33 in (pyarmor_core_324.footpos, pyarmor_core_324.footpos2):
            while pyarmor_core_298[pyarmor_core_33] != dis.opmap['PRECALL']:
                pyarmor_core_33 += 2
            pyarmor_core_298[pyarmor_core_33:pyarmor_core_33 + 4] = (dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0)
            pyarmor_core_33 += 4
            while pyarmor_core_298[pyarmor_core_33] != pyarmor_core_283:
                pyarmor_core_326(pyarmor_core_33)
                pyarmor_core_33 += 2
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
        pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos2
        pyarmor_core_324.co_code = bytes(pyarmor_core_298)
        return pyarmor_core_324

    def _patch_raise_varargs(pyarmor_core_22, pyarmor_core_324, pyarmor_core_123, pyarmor_core_298):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_356 = pyarmor_core_324.exitindex
        pyarmor_core_357 = getattr(pyarmor_core_324, 'footpos2', getattr(pyarmor_core_324, 'footpos'))

        def pyarmor_core_352():
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset >= pyarmor_core_357:
                    return
                if 'LOAD_CONST' == pyarmor_core_310.opname and pyarmor_core_356 == pyarmor_core_310.arg:
                    return pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_352()
        while pyarmor_core_310:
            pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
            for pyarmor_core_310 in pyarmor_core_308:
                pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
                if pyarmor_core_310.opname == 'POP_TOP':
                    break
            pyarmor_core_310 = pyarmor_core_352()

    def _patch_raise_varargs_py311(pyarmor_core_22, pyarmor_core_324, pyarmor_core_123, pyarmor_core_298):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_356 = pyarmor_core_324.exitindex

        def pyarmor_core_352():
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset >= pyarmor_core_324.footpos:
                    return
                if 'LOAD_CONST' == pyarmor_core_310.opname and pyarmor_core_356 == pyarmor_core_310.arg:
                    return pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_352()
        while pyarmor_core_310:
            pyarmor_core_9 = pyarmor_core_310.offset - 2
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.opname == 'POP_TOP':
                    for pyarmor_core_3 in range(pyarmor_core_9, pyarmor_core_310.offset + 1, 2):
                        pyarmor_core_298[pyarmor_core_3] = pyarmor_core_282
                    break
            pyarmor_core_310 = pyarmor_core_352()

    def _patch_assert_mode(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_358 = pyarmor_core_22.ctx.python_version[1]
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        if pyarmor_core_358 > 10:
            pyarmor_core_359 = pyarmor_core_298[pyarmor_core_310.offset - 3]
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
            pyarmor_core_298[pyarmor_core_310.offset - 4:pyarmor_core_310.offset + 2] = (pyarmor_core_282, 0) * 3
        else:
            pyarmor_core_359 = pyarmor_core_298[pyarmor_core_310.offset - 5]
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
            pyarmor_core_298[pyarmor_core_310.offset - 6:pyarmor_core_310.offset + 2] = (pyarmor_core_282, 0) * 4
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_code', pyarmor_core_298)
        pyarmor_core_320 = [1 << pyarmor_core_22.impt['CO_MARSHAL_ARMOR_FUNC_OFF'], 0, 0, 0]
        pyarmor_core_320.extend(pyarmor_core_294(1, pyarmor_core_359))
        pyarmor_core_320.insert(0, len(pyarmor_core_320))
        pyarmor_core_319 = list(pyarmor_core_123.co_consts)
        pyarmor_core_319[pyarmor_core_359] = pyarmor_core_289('assert')
        pyarmor_core_319.append(bytes(pyarmor_core_320))
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_consts', tuple(pyarmor_core_319))
        pyarmor_core_321 = pyarmor_core_123.co_flags | pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_flags', pyarmor_core_321)

    def _patch_wrap_co_code_py38(pyarmor_core_22, pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_360):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'SETUP_FINALLY')
        pyarmor_core_324.footpos = pyarmor_core_312.offset + 2 + pyarmor_core_312.arg
        pyarmor_core_298[12 + pyarmor_core_360:14 + pyarmor_core_360] = pyarmor_core_298[8 + pyarmor_core_360:10 + pyarmor_core_360]
        pyarmor_core_338 = pyarmor_core_324.footpos - pyarmor_core_360 - 10
        pyarmor_core_298[pyarmor_core_360:pyarmor_core_360 + 2] = (dis.opmap['JUMP_FORWARD'], 10)
        pyarmor_core_301(pyarmor_core_298, 2 + pyarmor_core_360, dis.opmap['CALL_FINALLY'], pyarmor_core_338)
        pyarmor_core_298[pyarmor_core_360 + 10:pyarmor_core_360 + 12] = (pyarmor_core_286, 0)
        pyarmor_core_361 = (dis.opmap['JUMP_ABSOLUTE'], pyarmor_core_360 + 2)
        while True:
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'CALL_FINALLY')
            if not pyarmor_core_310:
                break
            if pyarmor_core_310.arg + pyarmor_core_310.offset == pyarmor_core_312.arg + pyarmor_core_312.offset:
                pyarmor_core_16 = pyarmor_core_310.offset
                pyarmor_core_298[pyarmor_core_16] = pyarmor_core_282
                pyarmor_core_16 -= 2
                while pyarmor_core_298[pyarmor_core_16] == pyarmor_core_287:
                    pyarmor_core_298[pyarmor_core_16] = pyarmor_core_282
                    pyarmor_core_16 -= 2
                pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'RETURN_VALUE')
                if not pyarmor_core_310:
                    pyarmor_core_302(pyarmor_core_310)
                pyarmor_core_16 = pyarmor_core_310.offset
                pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + 2] = pyarmor_core_361
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_33 = pyarmor_core_324.footpos
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.offset == pyarmor_core_33:
                break
        if pyarmor_core_310.opcode not in (pyarmor_core_284, pyarmor_core_287):
            pyarmor_core_302(pyarmor_core_123)
        if pyarmor_core_310.opcode == pyarmor_core_287:
            pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'LOAD_CONST')
            if not (pyarmor_core_310 and pyarmor_core_290(pyarmor_core_310.argval)):
                pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_310.arg
        for pyarmor_core_310 in pyarmor_core_308:
            pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
            if pyarmor_core_310.opname == 'MAKE_FUNCTION':
                break
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
        pyarmor_core_324.footsize = len(pyarmor_core_298) - pyarmor_core_324.footpos
        pyarmor_core_324.co_code = bytes(pyarmor_core_298)
        return pyarmor_core_324

    def _patch_wrap_co_code_py310(pyarmor_core_22, pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_360):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_312 = pyarmor_core_22._next_ins(pyarmor_core_308, 'SETUP_FINALLY')
        pyarmor_core_324.footpos = pyarmor_core_312.offset + 2 + pyarmor_core_312.arg * 2
        pyarmor_core_298[pyarmor_core_360:pyarmor_core_360 + 8] = (dis.opmap['JUMP_FORWARD'], 3, dis.opmap['CALL_FUNCTION'], 1, pyarmor_core_283, randint(0, 255), pyarmor_core_286, 0)
        pyarmor_core_361 = (dis.opmap['JUMP_ABSOLUTE'], pyarmor_core_360 + 2 >> 1)
        pyarmor_core_362 = 0 if pyarmor_core_324.exitindex < 255 else 2 if pyarmor_core_324.exitindex < 65535 else 4 if pyarmor_core_324.exitindex < 16777215 else 6
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.offset >= pyarmor_core_324.footpos:
                break
            if pyarmor_core_310.opcode == pyarmor_core_284 and pyarmor_core_310.arg == pyarmor_core_324.exitindex:
                pyarmor_core_363 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
                pyarmor_core_364 = pyarmor_core_22._next_ins(pyarmor_core_308, 'RETURN_VALUE')
                if not (pyarmor_core_363 and pyarmor_core_364 and (pyarmor_core_364.offset - pyarmor_core_363.offset < 8)):
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_9 = pyarmor_core_310.offset - pyarmor_core_362
                pyarmor_core_348 = pyarmor_core_364.offset - pyarmor_core_363.offset - 2
                if pyarmor_core_348:
                    pyarmor_core_365 = pyarmor_core_363.offset + 2
                    pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_348] = pyarmor_core_298[pyarmor_core_365:pyarmor_core_365 + pyarmor_core_348]
                pyarmor_core_43 = pyarmor_core_9 + pyarmor_core_348
                pyarmor_core_298[pyarmor_core_43:pyarmor_core_43 + pyarmor_core_362 + 2] = pyarmor_core_123.co_code[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_362 + 2]
                pyarmor_core_43 += pyarmor_core_362 + 2
                pyarmor_core_298[pyarmor_core_43:pyarmor_core_43 + 2] = pyarmor_core_123.co_code[pyarmor_core_310.offset + 6:pyarmor_core_310.offset + 8]
                pyarmor_core_298[pyarmor_core_43 + 2:pyarmor_core_43 + 4] = pyarmor_core_361
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
        pyarmor_core_324.footsize = len(pyarmor_core_298) - pyarmor_core_324.footpos
        pyarmor_core_324.co_code = bytes(pyarmor_core_298)
        return pyarmor_core_324

    def _patch_wrap_co_code_py311(pyarmor_core_22, pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_360):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_366 = pyarmor_core_360 + 20
        pyarmor_core_361 = dis.opmap['JUMP_BACKWARD']
        pyarmor_core_362 = 0 if pyarmor_core_324.exitindex < 255 else 2 if pyarmor_core_324.exitindex < 65535 else 4 if pyarmor_core_324.exitindex < 16777215 else 6
        pyarmor_core_9 = -1
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.offset >= pyarmor_core_324.footpos:
                break
            if pyarmor_core_310.opname == 'PUSH_NULL':
                pyarmor_core_9 = pyarmor_core_310.offset
            elif pyarmor_core_310.opcode == pyarmor_core_284 and pyarmor_core_310.arg == pyarmor_core_324.exitindex:
                pyarmor_core_362 = pyarmor_core_310.offset - pyarmor_core_9
                if pyarmor_core_9 == -1 or pyarmor_core_362 > 8:
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_363 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
                pyarmor_core_364 = pyarmor_core_22._next_ins(pyarmor_core_308, 'RETURN_VALUE')
                if not (pyarmor_core_363 and pyarmor_core_364 and (pyarmor_core_364.offset - pyarmor_core_363.offset < 8)):
                    pyarmor_core_302(pyarmor_core_123)
                pyarmor_core_348 = pyarmor_core_364.offset - pyarmor_core_363.offset - 2
                if pyarmor_core_348:
                    pyarmor_core_365 = pyarmor_core_363.offset + 2
                    pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_348] = pyarmor_core_298[pyarmor_core_365:pyarmor_core_365 + pyarmor_core_348]
                pyarmor_core_43 = pyarmor_core_9 + pyarmor_core_348
                pyarmor_core_298[pyarmor_core_43:pyarmor_core_43 + pyarmor_core_362 + 2] = pyarmor_core_123.co_code[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_362 + 2]
                pyarmor_core_43 += pyarmor_core_362 + 2
                pyarmor_core_298[pyarmor_core_43:pyarmor_core_43 + 2] = pyarmor_core_123.co_code[pyarmor_core_310.offset + 4:pyarmor_core_310.offset + 6]
                pyarmor_core_43 += 2
                pyarmor_core_301(pyarmor_core_298, pyarmor_core_43, pyarmor_core_361, pyarmor_core_43 + 8 - pyarmor_core_366 >> 1)
                pyarmor_core_43 += 8
                while pyarmor_core_43 < pyarmor_core_363.offset:
                    pyarmor_core_298[pyarmor_core_43] = pyarmor_core_282
                    pyarmor_core_43 += 2
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298, offset=1)
        pyarmor_core_324.footsize = len(pyarmor_core_298) - pyarmor_core_324.footpos
        pyarmor_core_324.co_code = bytes(pyarmor_core_298)
        return pyarmor_core_324

    def _patch_co_object(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        pyarmor_core_358 = pyarmor_core_22.ctx.python_version[1]
        if pyarmor_core_358 == 11:
            return pyarmor_core_22._patch_co_code_py311(pyarmor_core_123, no_wrap)
        elif pyarmor_core_358 == 12:
            return pyarmor_core_22._patch_co_code_py312(pyarmor_core_123, no_wrap)
        elif pyarmor_core_358 == 13:
            return pyarmor_core_22._patch_co_code_py313(pyarmor_core_123, no_wrap)
        elif pyarmor_core_358 >= 14:
            return pyarmor_core_22._patch_co_code_py31X(pyarmor_core_123, no_wrap)
        pyarmor_core_324 = pyarmor_core_305()
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                break
        else:
            return
        pyarmor_core_360 = pyarmor_core_310.offset - 6
        pyarmor_core_324.assertindex = pyarmor_core_298[1 + pyarmor_core_360]
        if not pyarmor_core_290(pyarmor_core_123.co_consts[pyarmor_core_324.assertindex]):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'POP_TOP')
        if pyarmor_core_310.offset != 18 + pyarmor_core_360:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.enterindex = pyarmor_core_298[9 + pyarmor_core_360]
        pyarmor_core_324.argindex = pyarmor_core_298[15 + pyarmor_core_360]
        pyarmor_core_324.headsize = pyarmor_core_310.offset + 2
        for pyarmor_core_3 in (0, 2, 4, 6, 10, 12):
            pyarmor_core_298[pyarmor_core_3 + pyarmor_core_360] = pyarmor_core_282
            pyarmor_core_298[pyarmor_core_3 + 1 + pyarmor_core_360] = randint(0, 255)
        if no_wrap:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
            pyarmor_core_324.footsize = 0
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        if pyarmor_core_358 == 8:
            return pyarmor_core_22._patch_wrap_co_code_py38(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_360)
        if pyarmor_core_325 > 200:
            pyarmor_core_16 = pyarmor_core_325 - 100
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset > pyarmor_core_16:
                    break
        else:
            pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_332 = iter(reversed(list(pyarmor_core_308)))
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        for pyarmor_core_310 in pyarmor_core_332:
            if pyarmor_core_310.opname == 'EXTENDED_ARG':
                pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
                continue
            break
        if not pyarmor_core_290(pyarmor_core_310.argval):
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_324.exitindex = pyarmor_core_310.arg
        for pyarmor_core_310 in pyarmor_core_332:
            if pyarmor_core_310.opname != 'EXTENDED_ARG':
                break
        pyarmor_core_324.footpos = pyarmor_core_310.offset - 2
        if pyarmor_core_358 < 9:
            pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
            if pyarmor_core_358 == 8:
                pyarmor_core_3 = pyarmor_core_324.footpos
                pyarmor_core_367 = dis.opmap['CALL_FUNCTION']
                while pyarmor_core_3 < pyarmor_core_325:
                    if pyarmor_core_298[pyarmor_core_3] == pyarmor_core_367:
                        pyarmor_core_298[pyarmor_core_3] = pyarmor_core_283
                        break
                    pyarmor_core_3 += 2
            pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos
            pyarmor_core_324.co_code = bytes(pyarmor_core_298)
            return pyarmor_core_324
        if pyarmor_core_310.opname not in ('RETURN_VALUE', 'JUMP_FORWARD'):
            if pyarmor_core_22.oi_wrap_mode == 1:
                pyarmor_core_304(pyarmor_core_123, pyarmor_core_310.opname)
                pyarmor_core_22._patch_raise_varargs(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298)
                pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
                pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos
                pyarmor_core_324.co_code = bytes(pyarmor_core_298)
                return pyarmor_core_324
            return pyarmor_core_22._patch_wrap_co_code_py310(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298, pyarmor_core_360)
        pyarmor_core_324.endins2 = pyarmor_core_310
        pyarmor_core_310 = next(pyarmor_core_332)
        if pyarmor_core_310.opname == 'LOAD_CONST':
            pyarmor_core_324.valueins2 = pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'MAKE_FUNCTION')
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_332, 'LOAD_CONST')
        pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
        for pyarmor_core_310 in pyarmor_core_332:
            if pyarmor_core_310.opname == 'EXTENDED_ARG':
                pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_282
                continue
            break
        if not pyarmor_core_290(pyarmor_core_310.argval) or pyarmor_core_310.arg != pyarmor_core_324.exitindex:
            pyarmor_core_302(pyarmor_core_123)
        pyarmor_core_312 = pyarmor_core_310
        for pyarmor_core_310 in pyarmor_core_332:
            if pyarmor_core_310.opname != 'EXTENDED_ARG':
                break
        pyarmor_core_324.footpos2 = pyarmor_core_310.offset + 2
        pyarmor_core_334 = pyarmor_core_324.footpos2
        if hasattr(pyarmor_core_324, 'valueins2'):
            pyarmor_core_347 = pyarmor_core_324.valueins2.offset
            pyarmor_core_348 = 2
            while pyarmor_core_298[pyarmor_core_347 - pyarmor_core_348] == pyarmor_core_287:
                pyarmor_core_348 += 2
            pyarmor_core_16 = pyarmor_core_324.footpos2
            pyarmor_core_349 = pyarmor_core_324.endins2.offset
            pyarmor_core_298[pyarmor_core_16 + pyarmor_core_348:pyarmor_core_349] = pyarmor_core_298[pyarmor_core_16:pyarmor_core_349 - pyarmor_core_348]
            pyarmor_core_334 += pyarmor_core_348
            pyarmor_core_16 = pyarmor_core_324.footpos2
            pyarmor_core_349 = pyarmor_core_324.endins2.offset
            pyarmor_core_298[pyarmor_core_16:pyarmor_core_16 + pyarmor_core_348] = pyarmor_core_123.co_code[pyarmor_core_349 - pyarmor_core_348:pyarmor_core_349]
        elif pyarmor_core_324.endins2.opname == 'JUMP_FORWARD':

            def pyarmor_core_368():
                pyarmor_core_22._patch_raise_varargs(pyarmor_core_324, pyarmor_core_123, pyarmor_core_298)
                pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
                pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos2
                pyarmor_core_324.co_code = bytes(pyarmor_core_298)
                return pyarmor_core_324
            if pyarmor_core_22.oi_wrap_mode == 1:
                return pyarmor_core_368()
            pyarmor_core_16 = pyarmor_core_324.endins2.offset
            pyarmor_core_347 = pyarmor_core_16 + 2 + pyarmor_core_324.endins2.arg
            pyarmor_core_348 = 0
            while pyarmor_core_298[pyarmor_core_347 + pyarmor_core_348] == pyarmor_core_287:
                pyarmor_core_348 += 2
            if pyarmor_core_298[pyarmor_core_347 + pyarmor_core_348] not in (pyarmor_core_284,):
                return pyarmor_core_368()
            pyarmor_core_348 += 2
            if pyarmor_core_298[pyarmor_core_347 + pyarmor_core_348] not in (pyarmor_core_286,):
                return pyarmor_core_368()
            pyarmor_core_9 = pyarmor_core_334
            pyarmor_core_334 += pyarmor_core_348
            pyarmor_core_298[pyarmor_core_347:pyarmor_core_347 + pyarmor_core_348] = pyarmor_core_298[pyarmor_core_16 - pyarmor_core_348:pyarmor_core_16]
            pyarmor_core_298[pyarmor_core_9 + pyarmor_core_348:pyarmor_core_16] = pyarmor_core_298[pyarmor_core_9:pyarmor_core_16 - pyarmor_core_348]
            pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_348] = pyarmor_core_123.co_code[pyarmor_core_347:pyarmor_core_347 + pyarmor_core_348]
        pyarmor_core_350 = pyarmor_core_312.offset - pyarmor_core_324.footpos2
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.offset >= pyarmor_core_324.headsize:
                break

        def pyarmor_core_352(pyarmor_core_351, arg=None):
            for pyarmor_core_310 in pyarmor_core_308:
                if pyarmor_core_310.offset >= pyarmor_core_324.footpos2:
                    return
                if pyarmor_core_351 == pyarmor_core_310.opname and arg == pyarmor_core_310.arg:
                    return pyarmor_core_310
        pyarmor_core_310 = pyarmor_core_352(pyarmor_core_312.opname, arg=pyarmor_core_312.arg)
        while pyarmor_core_310:
            pyarmor_core_9 = pyarmor_core_310.offset - pyarmor_core_350
            pyarmor_core_353 = pyarmor_core_352('RETURN_VALUE')
            if not pyarmor_core_353:
                pyarmor_core_302(pyarmor_core_123)
            if pyarmor_core_298[pyarmor_core_353.offset - 2] == pyarmor_core_284:
                pyarmor_core_354 = pyarmor_core_353.offset - 2
                while pyarmor_core_298[pyarmor_core_354 - 2] == pyarmor_core_287:
                    pyarmor_core_354 -= 2
                pyarmor_core_355 = pyarmor_core_353.offset - pyarmor_core_354
                pyarmor_core_298[pyarmor_core_9:pyarmor_core_9 + pyarmor_core_355] = pyarmor_core_298[pyarmor_core_354:pyarmor_core_354 + pyarmor_core_355]
                pyarmor_core_9 += pyarmor_core_355
            assert pyarmor_core_353.offset - pyarmor_core_9 > 8
            pyarmor_core_338 = pyarmor_core_334 - pyarmor_core_9 - 8
            if pyarmor_core_358 > 9:
                pyarmor_core_338 >>= 1
            pyarmor_core_301(pyarmor_core_298, pyarmor_core_9, dis.opmap['JUMP_FORWARD'], pyarmor_core_338)
            pyarmor_core_310 = pyarmor_core_352(pyarmor_core_312.opname, arg=pyarmor_core_312.arg)
        pyarmor_core_22._patch_store_ins(pyarmor_core_123, pyarmor_core_298)
        pyarmor_core_324.footsize = pyarmor_core_325 - pyarmor_core_324.footpos2
        pyarmor_core_324.co_code = bytes(pyarmor_core_298)
        return pyarmor_core_324

    def _patch_store_ins(pyarmor_core_22, pyarmor_core_123, pyarmor_core_298, offset=3):
        pyarmor_core_308 = dis.get_instructions(pyarmor_core_123)
        pyarmor_core_310 = pyarmor_core_22._next_ins(pyarmor_core_308, 'MAKE_FUNCTION')
        if not pyarmor_core_310:
            return
        pyarmor_core_369 = pyarmor_core_123.co_code[pyarmor_core_310.offset - offset]
        pyarmor_core_310 = next(pyarmor_core_308)
        if pyarmor_core_310.opname == 'STORE_FAST':
            pyarmor_core_351 = dis.opmap['LOAD_FAST']
        elif pyarmor_core_310.opname == 'STORE_NAME':
            pyarmor_core_351 = dis.opmap['LOAD_NAME']
        else:
            return
        pyarmor_core_296 = pyarmor_core_310.arg
        for pyarmor_core_310 in pyarmor_core_308:
            if pyarmor_core_310.opcode == pyarmor_core_351 and pyarmor_core_310.arg == pyarmor_core_296:
                pyarmor_core_298[pyarmor_core_310.offset] = pyarmor_core_284
                pyarmor_core_298[pyarmor_core_310.offset + 1] = pyarmor_core_369

    def _patch_co_consts(pyarmor_core_22, pyarmor_core_123, pyarmor_core_324, no_wrap=False):
        pyarmor_core_319 = list(pyarmor_core_123.co_consts)
        pyarmor_core_370 = 0 if no_wrap else 1
        pyarmor_core_319[pyarmor_core_324.assertindex] = pyarmor_core_289('assert')
        pyarmor_core_319[pyarmor_core_324.enterindex] = pyarmor_core_289('enter')
        if pyarmor_core_370:
            pyarmor_core_319[pyarmor_core_324.exitindex] = pyarmor_core_289('exit')
        pyarmor_core_371 = len(pyarmor_core_324.co_code) - pyarmor_core_324.footsize - pyarmor_core_324.headsize
        pyarmor_core_372 = getattr(pyarmor_core_324, 'ivmode', 1)
        pyarmor_core_373 = getattr(pyarmor_core_324, 'ivpos', 0)
        pyarmor_core_374 = 1 if getattr(pyarmor_core_324, 'jit_iv', 0) else 0
        pyarmor_core_375 = pack('8x') if pyarmor_core_374 else b''
        pyarmor_core_376 = 1 if pyarmor_core_22.ob_mix_argnames else 0
        pyarmor_core_377 = 1 if pyarmor_core_22.ob_clear_frame_locals else 0
        pyarmor_core_378 = pack('QBBBBII', 0, pyarmor_core_370 | pyarmor_core_372 << 1 | pyarmor_core_374 << 2 | pyarmor_core_377 << 4, pyarmor_core_373, 0, pyarmor_core_324.headsize, pyarmor_core_371, 0)
        pyarmor_core_319[pyarmor_core_324.argindex] = pyarmor_core_378 + pyarmor_core_375
        pyarmor_core_320 = [2 + pyarmor_core_370 << pyarmor_core_22.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << pyarmor_core_22.impt['CO_MARSHAL_FIX_CO_JIT_OFF'] | pyarmor_core_376 << pyarmor_core_22.impt['CO_MARSHAL_MIX_ARGNAMES_OFF'], 0, 0, 0]
        pyarmor_core_320.extend(pyarmor_core_294(1, pyarmor_core_324.assertindex))
        pyarmor_core_320.extend(pyarmor_core_294(2, pyarmor_core_324.enterindex))
        if pyarmor_core_370:
            pyarmor_core_320.extend(pyarmor_core_294(3, pyarmor_core_324.exitindex))
        pyarmor_core_320.extend(pyarmor_core_294(pyarmor_core_374, pyarmor_core_324.argindex))
        pyarmor_core_320.insert(0, len(pyarmor_core_320))
        pyarmor_core_319.append(bytes(pyarmor_core_320))
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_consts', tuple(pyarmor_core_319))

    def _check_co_info(pyarmor_core_22, pyarmor_core_123, pyarmor_core_324):
        if pyarmor_core_123.co_flags & pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']:
            pyarmor_core_302(pyarmor_core_123, 'CO_PYTRANSFORM3 conflicts')
        if pyarmor_core_324.headsize > 255 or pyarmor_core_324.headsize < 12:
            pyarmor_core_302(pyarmor_core_123, 'invalid co header size')
        pyarmor_core_379 = getattr(pyarmor_core_324, 'footsize', 0)
        if pyarmor_core_379 and (pyarmor_core_379 > 65525 or pyarmor_core_379 < 12):
            pyarmor_core_302(pyarmor_core_123, 'invalid co footer size')
        pyarmor_core_246 = (pyarmor_core_324.assertindex, pyarmor_core_324.enterindex, pyarmor_core_324.argindex)
        if any([pyarmor_core_38 > 255 for pyarmor_core_38 in pyarmor_core_246]):
            pyarmor_core_302(pyarmor_core_123, 'big co argindex')
        if getattr(pyarmor_core_324, 'exitindex', -1) in pyarmor_core_246 or len(set(pyarmor_core_246)) != 3:
            pyarmor_core_302(pyarmor_core_123, 'co_info inner error')

    def _set_co_iv(pyarmor_core_22, pyarmor_core_123, pyarmor_core_324, no_wrap=False):
        pyarmor_core_380 = pyarmor_core_281
        pyarmor_core_17 = 1 if no_wrap else randint(0, 1)
        pyarmor_core_33 = len(pyarmor_core_324.co_code) - pyarmor_core_324.footsize
        pyarmor_core_324.iv = pyarmor_core_324.co_code[:pyarmor_core_380] if pyarmor_core_17 else pyarmor_core_324.co_code[pyarmor_core_33:pyarmor_core_33 + pyarmor_core_380]
        pyarmor_core_324.ivmode = pyarmor_core_17
        if pyarmor_core_22.ob_enable_jit:
            pyarmor_core_324.jit_iv = pyarmor_core_22.jit_iv
            pyarmor_core_324.iv = bytes([pyarmor_core_54 ^ pyarmor_core_381 for (pyarmor_core_54, pyarmor_core_381) in zip(pyarmor_core_324.iv, pyarmor_core_324.jit_iv)])

    def patch_co_object(pyarmor_core_22, pyarmor_core_123, no_wrap=False):
        if pyarmor_core_22._only_assert_mode:
            pyarmor_core_22._patch_assert_mode(pyarmor_core_123)
            return
        pyarmor_core_324 = pyarmor_core_22._patch_co_object(pyarmor_core_123, no_wrap)
        if pyarmor_core_324:
            pyarmor_core_22._check_co_info(pyarmor_core_123, pyarmor_core_324)
            pyarmor_core_22._set_co_iv(pyarmor_core_123, pyarmor_core_324, no_wrap=no_wrap)
            pyarmor_core_22._patch_co_consts(pyarmor_core_123, pyarmor_core_324, no_wrap)
            pyarmor_core_298 = pyarmor_core_324.co_code
            pyarmor_core_22.impt['generate_co_code'](pyarmor_core_22.impt['self'], pyarmor_core_22.ctx, pyarmor_core_123, pyarmor_core_298, len(pyarmor_core_298), pyarmor_core_324.headsize | pyarmor_core_324.footsize << 16, pyarmor_core_324.iv)
            pyarmor_core_321 = pyarmor_core_123.co_flags | pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']
            pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_flags', pyarmor_core_321)
        else:
            for pyarmor_core_310 in dis.get_instructions(pyarmor_core_123):
                if pyarmor_core_22._is_patched_ins(pyarmor_core_310):
                    pyarmor_core_302(pyarmor_core_123)
                if pyarmor_core_310.opname == 'LOAD_NAME' and pyarmor_core_310.argval == '__assert_armored__':
                    pyarmor_core_302(pyarmor_core_123)
        return pyarmor_core_324

    @resoptions
    def handle(pyarmor_core_22, pyarmor_core_106):
        logger.debug('patch co')
        pyarmor_core_22._only_assert_mode = not pyarmor_core_22.oi_obf_code and any([pyarmor_core_22.ob_enable_rft, pyarmor_core_22.ob_assert_call, pyarmor_core_22.ob_assert_import, pyarmor_core_22.ob_mix_str])
        if pyarmor_core_22.ob_enable_jit:
            pyarmor_core_22.jit_iv = pyarmor_core_382(pyarmor_core_22.ctx).handle(pyarmor_core_106)
        pyarmor_core_383 = pyarmor_core_22.ctx.exclude_co_names

        def pyarmor_core_384(pyarmor_core_123):
            return not any([pyarmor_core_123.co_flags & pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3'], pyarmor_core_123.co_name in pyarmor_core_383, pyarmor_core_290(pyarmor_core_123)])

        def pyarmor_core_385(pyarmor_core_123):
            if pyarmor_core_384(pyarmor_core_123) and pyarmor_core_22.patch_co_object(pyarmor_core_123, pyarmor_core_386):
                pyarmor_core_22.trace(pyarmor_core_106, pyarmor_core_123)
            for pyarmor_core_38 in pyarmor_core_123.co_consts:
                if isinstance(pyarmor_core_38, type(pyarmor_core_123)):
                    pyarmor_core_385(pyarmor_core_38)
            if pyarmor_core_22.ob_mix_coname:
                pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_name', '')
        pyarmor_core_386 = not pyarmor_core_22.ob_wrap_mode
        pyarmor_core_385(pyarmor_core_106.mco)

class pyarmor_core_387(object):

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22.imptbl = pyarmor_core_1

    def _rand_iv(pyarmor_core_22, n=pyarmor_core_281):
        return [randint(1, 255) for pyarmor_core_38 in range(n)]

    def _build_iv_jit(pyarmor_core_22, pyarmor_core_150):
        pyarmor_core_388 = 1
        pyarmor_core_389 = 2
        pyarmor_core_390 = 3
        pyarmor_core_391 = 4
        pyarmor_core_392 = 5
        pyarmor_core_393 = 6
        pyarmor_core_394 = 7
        pyarmor_core_395 = 8
        pyarmor_core_396 = 9
        pyarmor_core_397 = 10
        pyarmor_core_398 = 11
        (pyarmor_core_399, pyarmor_core_400, pyarmor_core_401, pyarmor_core_402, pyarmor_core_403, pyarmor_core_404, pyarmor_core_38, pyarmor_core_405) = range(8)

        def pyarmor_core_406(pyarmor_core_44):
            pyarmor_core_310 = []
            pyarmor_core_407 = randchoice(pyarmor_core_408)
            if pyarmor_core_409[pyarmor_core_407] in (None, 'FP'):
                pyarmor_core_409[pyarmor_core_407] = randint(2, 126)
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_407 << 4 | 9, pyarmor_core_409[pyarmor_core_407] & 255])
            for pyarmor_core_33 in range(randint(1, 3)):
                pyarmor_core_410 = randchoice(pyarmor_core_408)
                pyarmor_core_351 = randchoice([pyarmor_core_389, pyarmor_core_390, pyarmor_core_393])
                pyarmor_core_411 = randint(2, 126)
                if pyarmor_core_407 == pyarmor_core_410:
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | 9, pyarmor_core_411])
                else:
                    pyarmor_core_409[pyarmor_core_410] = pyarmor_core_411
                    pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_410 << 4 | 9, pyarmor_core_411])
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | pyarmor_core_410])
                if pyarmor_core_351 == pyarmor_core_389:
                    pyarmor_core_409[pyarmor_core_407] += pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_390:
                    pyarmor_core_409[pyarmor_core_407] -= pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_393:
                    pyarmor_core_409[pyarmor_core_407] ^= pyarmor_core_411
                pyarmor_core_409[pyarmor_core_407] &= 255
            if pyarmor_core_409[pyarmor_core_407] > pyarmor_core_44:
                pyarmor_core_310.extend([pyarmor_core_390, pyarmor_core_407 << 4 | 9, pyarmor_core_409[pyarmor_core_407] - pyarmor_core_44])
            elif pyarmor_core_409[pyarmor_core_407] < pyarmor_core_44:
                pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 9, pyarmor_core_44 - pyarmor_core_409[pyarmor_core_407]])
            pyarmor_core_409[pyarmor_core_407] = pyarmor_core_44
            if not pyarmor_core_412 == pyarmor_core_407:
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_412 << 4 | pyarmor_core_407])
                pyarmor_core_409[pyarmor_core_412] = pyarmor_core_44
            return pyarmor_core_310

        def pyarmor_core_413(pyarmor_core_220):
            pyarmor_core_310 = []
            pyarmor_core_407 = pyarmor_core_414
            while pyarmor_core_407 == pyarmor_core_412:
                pyarmor_core_407 = randchoice(pyarmor_core_408)
            pyarmor_core_310.extend([pyarmor_core_397, pyarmor_core_407 << 3 | pyarmor_core_405, 0])
            pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 9, pyarmor_core_281])
            if pyarmor_core_220:
                pyarmor_core_310.extend([pyarmor_core_398, 1 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412, pyarmor_core_220])
            else:
                pyarmor_core_310.extend([pyarmor_core_396, 1 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412])
            pyarmor_core_409[pyarmor_core_407] = 'FP'
            return pyarmor_core_310
        pyarmor_core_415 = 6
        pyarmor_core_408 = tuple(range(pyarmor_core_415))
        pyarmor_core_412 = None
        pyarmor_core_414 = randchoice(pyarmor_core_408)
        pyarmor_core_409 = [None] * pyarmor_core_415
        pyarmor_core_416 = []
        pyarmor_core_49 = []
        pyarmor_core_33 = len(pyarmor_core_150)
        while len(pyarmor_core_416) < pyarmor_core_33:
            pyarmor_core_417 = randint(0, pyarmor_core_33 - 1)
            if pyarmor_core_417 not in pyarmor_core_416:
                pyarmor_core_416.append(pyarmor_core_417)
        for pyarmor_core_220 in pyarmor_core_416:
            pyarmor_core_44 = pyarmor_core_150[pyarmor_core_220]
            pyarmor_core_412 = randchoice(pyarmor_core_408)
            pyarmor_core_49.extend(pyarmor_core_406(pyarmor_core_44) + pyarmor_core_413(pyarmor_core_220))
        pyarmor_core_49.append(pyarmor_core_388)
        return bytes(pyarmor_core_49)

    def _build_jit_data(pyarmor_core_22, pyarmor_core_418):
        pyarmor_core_19 = pyarmor_core_22.imptbl['generate_module_data'](pyarmor_core_22.imptbl['self'], pyarmor_core_22.ctx, pyarmor_core_418, -1)
        if pyarmor_core_19 is None:
            pyarmor_core_19 = b''.join([pyarmor_core_22._build_iv_jit(pyarmor_core_150) for pyarmor_core_150 in pyarmor_core_418])
        pyarmor_core_64 = pack('IIII', len(pyarmor_core_19) + 16, 0, 16, 0)
        return pyarmor_core_64 + pyarmor_core_19

    def _list_co(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_49 = [pyarmor_core_123]
        for pyarmor_core_38 in pyarmor_core_123.co_consts:
            if type(pyarmor_core_38) == type(pyarmor_core_123) and (not pyarmor_core_290(pyarmor_core_38)):
                pyarmor_core_49.extend(pyarmor_core_22._list_co(pyarmor_core_38))
        return pyarmor_core_49

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_419 = pyarmor_core_22._list_co(pyarmor_core_106.mco)
        pyarmor_core_418 = [pyarmor_core_22._rand_iv() for pyarmor_core_38 in pyarmor_core_419]
        pyarmor_core_106.jit_iv = (pyarmor_core_419, pyarmor_core_418)
        pyarmor_core_106.jit_data = pyarmor_core_22._build_jit_data(pyarmor_core_418)

class pyarmor_core_420(object):

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22.imptbl = pyarmor_core_1

    def _rand_iv(pyarmor_core_22, n=pyarmor_core_281):
        return [randint(1, 255) for pyarmor_core_38 in range(n)]

    def _build_iv_jit(pyarmor_core_22, pyarmor_core_150):
        pyarmor_core_388 = 1
        pyarmor_core_389 = 2
        pyarmor_core_390 = 3
        pyarmor_core_391 = 4
        pyarmor_core_392 = 5
        pyarmor_core_393 = 6
        pyarmor_core_394 = 7
        pyarmor_core_395 = 8
        pyarmor_core_396 = 9
        pyarmor_core_397 = 10
        pyarmor_core_398 = 11
        (pyarmor_core_399, pyarmor_core_400, pyarmor_core_401, pyarmor_core_402, pyarmor_core_403, pyarmor_core_404, pyarmor_core_38, pyarmor_core_405) = range(8)

        def pyarmor_core_421():
            return randint(1, 4294967295)

        def pyarmor_core_422(pyarmor_core_38):
            return [pyarmor_core_38 & 255, pyarmor_core_38 >> 8 & 255, pyarmor_core_38 >> 16 & 255, pyarmor_core_38 >> 24 & 255]

        def pyarmor_core_406(pyarmor_core_44):
            pyarmor_core_310 = []
            pyarmor_core_407 = randchoice(pyarmor_core_408)
            if pyarmor_core_409[pyarmor_core_407] in (None, 'FP'):
                pyarmor_core_409[pyarmor_core_407] = pyarmor_core_421()
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_407 << 4 | 8] + pyarmor_core_422(pyarmor_core_409[pyarmor_core_407]))
            for pyarmor_core_33 in range(randint(1, 3)):
                pyarmor_core_410 = randchoice(pyarmor_core_408)
                pyarmor_core_351 = randchoice([pyarmor_core_389, pyarmor_core_390, pyarmor_core_393])
                pyarmor_core_411 = pyarmor_core_421()
                if pyarmor_core_407 == pyarmor_core_410:
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | 8] + pyarmor_core_422(pyarmor_core_411))
                else:
                    pyarmor_core_409[pyarmor_core_410] = pyarmor_core_411
                    pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_410 << 4 | 8] + pyarmor_core_422(pyarmor_core_411))
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | pyarmor_core_410])
                if pyarmor_core_351 == pyarmor_core_389:
                    pyarmor_core_409[pyarmor_core_407] += pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_390:
                    pyarmor_core_409[pyarmor_core_407] -= pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_393:
                    pyarmor_core_409[pyarmor_core_407] ^= pyarmor_core_411
                pyarmor_core_409[pyarmor_core_407] &= 4294967295
            if pyarmor_core_409[pyarmor_core_407] > pyarmor_core_44:
                pyarmor_core_411 = pyarmor_core_422(pyarmor_core_409[pyarmor_core_407] - pyarmor_core_44)
                pyarmor_core_310.extend([pyarmor_core_390, pyarmor_core_407 << 4 | 8] + pyarmor_core_411)
            elif pyarmor_core_409[pyarmor_core_407] < pyarmor_core_44:
                pyarmor_core_411 = pyarmor_core_422(pyarmor_core_44 - pyarmor_core_409[pyarmor_core_407])
                pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 8] + pyarmor_core_411)
            pyarmor_core_409[pyarmor_core_407] = pyarmor_core_44
            if not pyarmor_core_412 == pyarmor_core_407:
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_412 << 4 | pyarmor_core_407])
                pyarmor_core_409[pyarmor_core_412] = pyarmor_core_44
            return pyarmor_core_310

        def pyarmor_core_413(pyarmor_core_220):
            pyarmor_core_310 = []
            pyarmor_core_407 = pyarmor_core_414
            while pyarmor_core_407 == pyarmor_core_412:
                pyarmor_core_407 = randchoice(pyarmor_core_408)
            pyarmor_core_310.extend([pyarmor_core_397, pyarmor_core_407 << 3 | pyarmor_core_405, 0])
            pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 9, pyarmor_core_281])
            if pyarmor_core_220:
                pyarmor_core_310.extend([pyarmor_core_398, 2 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412, pyarmor_core_220 * 4])
            else:
                pyarmor_core_310.extend([pyarmor_core_396, 2 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412])
            pyarmor_core_409[pyarmor_core_407] = 'FP'
            return pyarmor_core_310
        pyarmor_core_415 = 6
        pyarmor_core_408 = tuple(range(pyarmor_core_415))
        pyarmor_core_412 = None
        pyarmor_core_414 = randchoice(pyarmor_core_408)
        pyarmor_core_409 = [None] * pyarmor_core_415
        pyarmor_core_416 = []
        pyarmor_core_49 = []
        pyarmor_core_150 = unpack('III', bytes(pyarmor_core_150))
        pyarmor_core_33 = len(pyarmor_core_150)
        while len(pyarmor_core_416) < pyarmor_core_33:
            pyarmor_core_417 = randint(0, pyarmor_core_33 - 1)
            if pyarmor_core_417 not in pyarmor_core_416:
                pyarmor_core_416.append(pyarmor_core_417)
        for pyarmor_core_220 in pyarmor_core_416:
            pyarmor_core_44 = pyarmor_core_150[pyarmor_core_220]
            pyarmor_core_412 = randchoice(pyarmor_core_408)
            pyarmor_core_49.extend(pyarmor_core_406(pyarmor_core_44) + pyarmor_core_413(pyarmor_core_220))
        pyarmor_core_49.append(pyarmor_core_388)
        return bytes(pyarmor_core_49)

    def _build_jit_data(pyarmor_core_22, pyarmor_core_418):
        pyarmor_core_19 = pyarmor_core_22.imptbl['generate_module_data'](pyarmor_core_22.imptbl['self'], pyarmor_core_22.ctx, pyarmor_core_418, -1)
        if pyarmor_core_19 is None:
            pyarmor_core_19 = b''.join([pyarmor_core_22._build_iv_jit(pyarmor_core_150) for pyarmor_core_150 in pyarmor_core_418])
        pyarmor_core_64 = pack('IIII', len(pyarmor_core_19) + 16, 0, 16, 0)
        return pyarmor_core_64 + pyarmor_core_19

    def _list_co(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_49 = [pyarmor_core_123]
        for pyarmor_core_38 in pyarmor_core_123.co_consts:
            if type(pyarmor_core_38) == type(pyarmor_core_123) and (not pyarmor_core_290(pyarmor_core_38)):
                pyarmor_core_49.extend(pyarmor_core_22._list_co(pyarmor_core_38))
        return pyarmor_core_49

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_419 = pyarmor_core_22._list_co(pyarmor_core_106.mco)
        pyarmor_core_418 = [pyarmor_core_22._rand_iv() for pyarmor_core_38 in pyarmor_core_419]
        pyarmor_core_106.jit_iv = (pyarmor_core_419, pyarmor_core_418)
        pyarmor_core_106.jit_data = pyarmor_core_22._build_jit_data(pyarmor_core_418)

class pyarmor_core_382(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def _rand_iv(pyarmor_core_22, n=pyarmor_core_281):
        return [randint(1, 255) for pyarmor_core_38 in range(n)]

    def _build_iv_jit(pyarmor_core_22, pyarmor_core_150):
        pyarmor_core_388 = 1
        pyarmor_core_389 = 2
        pyarmor_core_390 = 3
        pyarmor_core_391 = 4
        pyarmor_core_392 = 5
        pyarmor_core_393 = 6
        pyarmor_core_394 = 7
        pyarmor_core_395 = 8
        pyarmor_core_396 = 9
        pyarmor_core_397 = 10
        pyarmor_core_398 = 11
        (pyarmor_core_399, pyarmor_core_400, pyarmor_core_401, pyarmor_core_402, pyarmor_core_403, pyarmor_core_404, pyarmor_core_38, pyarmor_core_405) = range(8)
        pyarmor_core_254 = pyarmor_core_22.ctx.jit_iv_threshold

        def pyarmor_core_421():
            return randint(1, 2147483647)

        def pyarmor_core_422(pyarmor_core_38):
            return [pyarmor_core_38 & 255, pyarmor_core_38 >> 8 & 255, pyarmor_core_38 >> 16 & 255, pyarmor_core_38 >> 24 & 255]

        def pyarmor_core_406(pyarmor_core_44):
            pyarmor_core_310 = []
            pyarmor_core_407 = randchoice(pyarmor_core_408)
            if pyarmor_core_409[pyarmor_core_407] in (None, 'FP'):
                pyarmor_core_409[pyarmor_core_407] = pyarmor_core_421()
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_407 << 4 | 8] + pyarmor_core_422(pyarmor_core_409[pyarmor_core_407]))
            for pyarmor_core_33 in range(randint(pyarmor_core_254, pyarmor_core_254 + 8)):
                pyarmor_core_410 = randchoice(pyarmor_core_408)
                pyarmor_core_351 = randchoice([pyarmor_core_389, pyarmor_core_390, pyarmor_core_393])
                pyarmor_core_411 = pyarmor_core_421()
                if pyarmor_core_407 == pyarmor_core_410:
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | 8] + pyarmor_core_422(pyarmor_core_411))
                else:
                    pyarmor_core_409[pyarmor_core_410] = pyarmor_core_411
                    pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_410 << 4 | 8] + pyarmor_core_422(pyarmor_core_411))
                    pyarmor_core_310.extend([pyarmor_core_351, pyarmor_core_407 << 4 | pyarmor_core_410])
                if pyarmor_core_351 == pyarmor_core_389:
                    pyarmor_core_409[pyarmor_core_407] += pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_390:
                    pyarmor_core_409[pyarmor_core_407] -= pyarmor_core_411
                elif pyarmor_core_351 == pyarmor_core_393:
                    pyarmor_core_409[pyarmor_core_407] ^= pyarmor_core_411
                pyarmor_core_409[pyarmor_core_407] &= 4294967295
            if pyarmor_core_409[pyarmor_core_407] > pyarmor_core_44:
                pyarmor_core_411 = pyarmor_core_422(pyarmor_core_409[pyarmor_core_407] - pyarmor_core_44)
                pyarmor_core_310.extend([pyarmor_core_390, pyarmor_core_407 << 4 | 8] + pyarmor_core_411)
            elif pyarmor_core_409[pyarmor_core_407] < pyarmor_core_44:
                pyarmor_core_411 = pyarmor_core_422(pyarmor_core_44 - pyarmor_core_409[pyarmor_core_407])
                pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 8] + pyarmor_core_411)
            pyarmor_core_409[pyarmor_core_407] = pyarmor_core_44
            if not pyarmor_core_412 == pyarmor_core_407:
                pyarmor_core_310.extend([pyarmor_core_394, pyarmor_core_412 << 4 | pyarmor_core_407])
                pyarmor_core_409[pyarmor_core_412] = pyarmor_core_44
            return pyarmor_core_310

        def pyarmor_core_413(pyarmor_core_220):
            pyarmor_core_310 = []
            pyarmor_core_407 = pyarmor_core_414
            while pyarmor_core_407 == pyarmor_core_412:
                pyarmor_core_407 = randchoice(pyarmor_core_408)
            pyarmor_core_310.extend([pyarmor_core_397, pyarmor_core_407 << 3 | pyarmor_core_405, 0])
            pyarmor_core_310.extend([pyarmor_core_389, pyarmor_core_407 << 4 | 9, pyarmor_core_281])
            if pyarmor_core_220:
                pyarmor_core_310.extend([pyarmor_core_398, 2 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412, pyarmor_core_220 * 4])
            else:
                pyarmor_core_310.extend([pyarmor_core_396, 2 << 6 | pyarmor_core_407 << 3 | pyarmor_core_412])
            pyarmor_core_409[pyarmor_core_407] = 'FP'
            return pyarmor_core_310
        pyarmor_core_415 = 6
        pyarmor_core_408 = tuple(range(pyarmor_core_415))
        pyarmor_core_412 = None
        pyarmor_core_414 = randchoice(pyarmor_core_408)
        pyarmor_core_409 = [None] * pyarmor_core_415
        pyarmor_core_416 = []
        pyarmor_core_49 = []
        pyarmor_core_150 = unpack('III', bytes(pyarmor_core_150))
        pyarmor_core_33 = len(pyarmor_core_150)
        while len(pyarmor_core_416) < pyarmor_core_33:
            pyarmor_core_417 = randint(0, pyarmor_core_33 - 1)
            if pyarmor_core_417 not in pyarmor_core_416:
                pyarmor_core_416.append(pyarmor_core_417)
        for pyarmor_core_220 in pyarmor_core_416:
            pyarmor_core_44 = pyarmor_core_150[pyarmor_core_220]
            pyarmor_core_412 = randchoice(pyarmor_core_408)
            pyarmor_core_49.extend(pyarmor_core_406(pyarmor_core_44) + pyarmor_core_413(pyarmor_core_220))
        pyarmor_core_49.append(pyarmor_core_388)
        return bytes(pyarmor_core_49)

    def _build_jit_data(pyarmor_core_22, pyarmor_core_150):
        pyarmor_core_19 = pyarmor_core_22._build_iv_jit(pyarmor_core_150)
        pyarmor_core_64 = pack('IIII', len(pyarmor_core_19) + 16, 0, 16, 0)
        return pyarmor_core_64 + pyarmor_core_19

    def _count_co(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_33 = 1
        for pyarmor_core_38 in pyarmor_core_123.co_consts:
            if type(pyarmor_core_38) == type(pyarmor_core_123) and (not pyarmor_core_290(pyarmor_core_38)):
                pyarmor_core_33 += pyarmor_core_22._count_co(pyarmor_core_38)
        return pyarmor_core_33

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_150 = pyarmor_core_22._rand_iv()
        pyarmor_core_106.jit_data = pyarmor_core_22._build_jit_data(pyarmor_core_150)
        return pyarmor_core_150

class pyarmor_core_125(pyarmor_core_307):

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22.impt = pyarmor_core_1

    def _patch_co_object(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)
        pyarmor_core_358 = pyarmor_core_22.ctx.python_version[1]
        pyarmor_core_338 = pyarmor_core_325 + 6 if pyarmor_core_358 < 10 else pyarmor_core_325 + 6 >> 1
        pyarmor_core_423 = pyarmor_core_300(pyarmor_core_298, 0, dis.opmap['JUMP_FORWARD'], pyarmor_core_338)
        pyarmor_core_424 = bytearray(pyarmor_core_423 + 40)
        pyarmor_core_424[:8] = [pyarmor_core_282] * 8
        pyarmor_core_424[:pyarmor_core_423] = pyarmor_core_123.co_code[:pyarmor_core_423]
        pyarmor_core_16 = 8
        pyarmor_core_303 = dis.opmap['PUSH_NULL'] if pyarmor_core_358 > 10 else pyarmor_core_282
        pyarmor_core_424[pyarmor_core_16:pyarmor_core_16 + 2] = (pyarmor_core_303, randint(0, 255))
        pyarmor_core_16 += 2
        pyarmor_core_425 = len(pyarmor_core_123.co_consts)
        pyarmor_core_16 = pyarmor_core_300(pyarmor_core_424, pyarmor_core_16, pyarmor_core_284, pyarmor_core_425)
        pyarmor_core_16 = pyarmor_core_300(pyarmor_core_424, pyarmor_core_16, pyarmor_core_284, pyarmor_core_425 + 1)
        pyarmor_core_424[pyarmor_core_16:pyarmor_core_16 + 6] = (dis.opmap['BUILD_TUPLE'], 1, dis.opmap['CALL_FUNCTION_EX'], 0, dis.opmap['POP_TOP'], randint(0, 255))
        pyarmor_core_16 += 6
        if pyarmor_core_358 > 10:
            pyarmor_core_299 = dis.opmap['JUMP_BACKWARD']
            pyarmor_core_338 = pyarmor_core_16 + 8 >> 1
            pyarmor_core_16 = pyarmor_core_301(pyarmor_core_424, pyarmor_core_16, pyarmor_core_299, pyarmor_core_338)
        else:
            pyarmor_core_16 = pyarmor_core_300(pyarmor_core_424, pyarmor_core_16, dis.opmap['JUMP_ABSOLUTE'], 0)
        pyarmor_core_298 += pyarmor_core_424[:pyarmor_core_16]
        pyarmor_core_426 = bytes(pyarmor_core_298)
        pyarmor_core_379 = pyarmor_core_16 - pyarmor_core_423
        pyarmor_core_427 = 8 - pyarmor_core_423
        pyarmor_core_150 = bytes(pyarmor_core_424[8:20])
        pyarmor_core_22.impt['generate_co_code'](pyarmor_core_22.impt['self'], pyarmor_core_22.ctx, pyarmor_core_123, pyarmor_core_426, len(pyarmor_core_298), pyarmor_core_423 | pyarmor_core_379 << 16, pyarmor_core_150)
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_code', pyarmor_core_426)
        pyarmor_core_319 = list(pyarmor_core_123.co_consts)
        pyarmor_core_319.append(pyarmor_core_289('lambda'))
        pyarmor_core_378 = pack('QBBBBII', 0, 8, pyarmor_core_427, 0, pyarmor_core_423, pyarmor_core_325, 0)
        pyarmor_core_319.append(pyarmor_core_378)
        pyarmor_core_320 = [1 << pyarmor_core_22.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << pyarmor_core_22.impt['CO_MARSHAL_FIX_CO_JIT_OFF'], 0, 0, 0]
        pyarmor_core_320.extend(pyarmor_core_294(2, pyarmor_core_425))
        pyarmor_core_320.extend(pyarmor_core_294(0, pyarmor_core_425 + 1))
        pyarmor_core_320.insert(0, len(pyarmor_core_320))
        pyarmor_core_319.append(bytes(pyarmor_core_320))
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_consts', tuple(pyarmor_core_319))
        pyarmor_core_321 = pyarmor_core_123.co_flags | pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_flags', pyarmor_core_321)

    def handle_mco(pyarmor_core_22, pyarmor_core_46, pyarmor_core_124):

        def pyarmor_core_322(pyarmor_core_123):
            if pyarmor_core_124(pyarmor_core_123):
                pyarmor_core_22._patch_co_object(pyarmor_core_123)
            for pyarmor_core_38 in pyarmor_core_123.co_consts:
                if type(pyarmor_core_38) == type(pyarmor_core_123):
                    pyarmor_core_322(pyarmor_core_38)
        pyarmor_core_322(pyarmor_core_46)

class pyarmor_core_428(pyarmor_core_125):

    def handle(pyarmor_core_22, pyarmor_core_106):

        def pyarmor_core_124(pyarmor_core_123):
            return pyarmor_core_123.co_name == '<lambda>' and (not pyarmor_core_290(pyarmor_core_123))
        pyarmor_core_22.handle_mco(pyarmor_core_106.mco, pyarmor_core_124)

class pyarmor_core_429(pyarmor_core_307):

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22.impt = pyarmor_core_1

    def _patch_co_object(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_298 = bytearray(pyarmor_core_123.co_code)
        pyarmor_core_325 = len(pyarmor_core_298)
        pyarmor_core_425 = len(pyarmor_core_123.co_consts)
        pyarmor_core_358 = pyarmor_core_22.ctx.python_version[1]
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_code', pyarmor_core_298)
        pyarmor_core_319 = list(pyarmor_core_123.co_consts)
        pyarmor_core_319.append(pyarmor_core_289('lambda'))
        pyarmor_core_378 = pack('QBBBBII', 0, 8, 0, 0, headsize, pyarmor_core_325, 0)
        pyarmor_core_319[pyarmor_core_425 + 1] = pyarmor_core_378
        pyarmor_core_320 = [1 << pyarmor_core_22.impt['CO_MARSHAL_ARMOR_FUNC_OFF'] | 1 << pyarmor_core_22.impt['CO_MARSHAL_FIX_CO_JIT_OFF'], 0, 0, 0]
        pyarmor_core_320.extend(pyarmor_core_294(2, pyarmor_core_425))
        pyarmor_core_320.extend(pyarmor_core_294(0, pyarmor_core_425 + 1))
        pyarmor_core_320.insert(0, len(pyarmor_core_320))
        pyarmor_core_319.append(bytes(pyarmor_core_320))
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_consts', tuple(pyarmor_core_319))
        pyarmor_core_321 = pyarmor_core_123.co_flags | pyarmor_core_22.impt['CO_FLAG_PYTRANSFORM3']
        pyarmor_core_22.impt['fix_co_object'](pyarmor_core_123, b'co_flags', pyarmor_core_321)

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_22._patch_co_object(pyarmor_core_106.mco)

class pyarmor_core_143(object):
    PREFIX = '_var_var_'

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22.imptbl = pyarmor_core_1

    def _co_narg(pyarmor_core_22, pyarmor_core_123):
        pyarmor_core_430 = pyarmor_core_123.co_argcount + pyarmor_core_123.co_kwonlyargcount
        pyarmor_core_430 += 1 if pyarmor_core_123.co_flags & 4 else 0
        pyarmor_core_430 += 1 if pyarmor_core_123.co_flags & 8 else 0
        return pyarmor_core_430

    def _name_pool(pyarmor_core_22, pyarmor_core_102):
        if pyarmor_core_102.startswith('__'):
            return pyarmor_core_102
        if pyarmor_core_102 not in pyarmor_core_22._pool:
            pyarmor_core_22._pool.append(pyarmor_core_102)
        return pyarmor_core_22.PREFIX + str(pyarmor_core_22._pool.index(pyarmor_core_102))

    def _get_name_names(pyarmor_core_22, pyarmor_core_123):
        return [pyarmor_core_310.argval for pyarmor_core_310 in dis.get_instructions(pyarmor_core_123) if pyarmor_core_310.opname in ('LOAD_NAME', 'STROE_NAME')]

    def _get_import_names(pyarmor_core_22, pyarmor_core_123):
        return [pyarmor_core_310.argval for pyarmor_core_310 in dis.get_instructions(pyarmor_core_123) if pyarmor_core_310.opname in ('IMPORT_NAME', 'IMPORT_FROM')]

    def _get_attr_symbols(pyarmor_core_22, pyarmor_core_123):
        return [pyarmor_core_310.argval for pyarmor_core_310 in dis.get_instructions(pyarmor_core_123) if pyarmor_core_310.opname in ('LOAD_ATTR', 'STORE_ATTR')]

    def _handle_module_co(pyarmor_core_22, pyarmor_core_46):
        pyarmor_core_431 = {}
        pyarmor_core_432 = set(pyarmor_core_22._get_name_names(pyarmor_core_46))
        pyarmor_core_433 = set()
        for pyarmor_core_38 in pyarmor_core_46.co_names:
            if pyarmor_core_38 in pyarmor_core_432 and pyarmor_core_38 not in pyarmor_core_433:
                pyarmor_core_431.setdefault(pyarmor_core_38, pyarmor_core_22._name_pool(pyarmor_core_38))
        pyarmor_core_434 = [pyarmor_core_431.get(pyarmor_core_38, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_46.co_names]
        pyarmor_core_22.imptbl['fix_co_object'](pyarmor_core_46, 'co_names', tuple(pyarmor_core_434))

    def _handle_co(pyarmor_core_22, pyarmor_core_123, pyarmor_core_435):
        pyarmor_core_430 = pyarmor_core_22._co_narg(pyarmor_core_123)
        pyarmor_core_436 = {}
        for pyarmor_core_38 in pyarmor_core_123.co_cellvars:
            if pyarmor_core_38 not in pyarmor_core_123.co_varnames[:pyarmor_core_430]:
                pyarmor_core_436.setdefault(pyarmor_core_38, pyarmor_core_22._name_pool(pyarmor_core_38))
        for pyarmor_core_38 in pyarmor_core_123.co_varnames[pyarmor_core_430:]:
            pyarmor_core_436.setdefault(pyarmor_core_38, pyarmor_core_22._name_pool(pyarmor_core_38))
        pyarmor_core_437 = [pyarmor_core_436.get(pyarmor_core_38, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_123.co_cellvars]
        pyarmor_core_438 = [pyarmor_core_435.get(pyarmor_core_38, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_123.co_freevars]
        pyarmor_core_439 = list(pyarmor_core_123.co_varnames[:pyarmor_core_430])
        pyarmor_core_439.extend([pyarmor_core_436.get(pyarmor_core_38, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_123.co_varnames[pyarmor_core_430:]])
        pyarmor_core_440 = pyarmor_core_22.imptbl['fix_co_object']
        (pyarmor_core_441, pyarmor_core_358) = pyarmor_core_22.ctx.python_version[:2]
        if pyarmor_core_441 == 3 and pyarmor_core_358 < 11:
            pyarmor_core_440(pyarmor_core_123, b'co_cellvars', tuple(pyarmor_core_437))
            pyarmor_core_440(pyarmor_core_123, b'co_freevars', tuple(pyarmor_core_438))
            pyarmor_core_440(pyarmor_core_123, b'co_varnames', tuple(pyarmor_core_439))
        else:
            pyarmor_core_442 = pyarmor_core_440(pyarmor_core_123, b'co_freevars', None)
            pyarmor_core_443 = []
            (pyarmor_core_444, pyarmor_core_445, pyarmor_core_446) = (16, 64, 128)
            for (pyarmor_core_102, pyarmor_core_447) in zip(*pyarmor_core_442):
                try:
                    if pyarmor_core_447 & pyarmor_core_445:
                        pyarmor_core_443.append(pyarmor_core_437[pyarmor_core_123.co_cellvars.index(pyarmor_core_102)])
                    elif pyarmor_core_447 & pyarmor_core_446:
                        pyarmor_core_443.append(pyarmor_core_438[pyarmor_core_123.co_freevars.index(pyarmor_core_102)])
                    else:
                        pyarmor_core_443.append(pyarmor_core_439[pyarmor_core_123.co_varnames.index(pyarmor_core_102)])
                except ValueError:
                    pyarmor_core_443.append(pyarmor_core_102)
            pyarmor_core_440(pyarmor_core_123, b'co_varnames', tuple(pyarmor_core_443))
        pyarmor_core_435 = dict(zip(pyarmor_core_123.co_cellvars, pyarmor_core_437))
        for pyarmor_core_38 in [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_123.co_consts if isinstance(pyarmor_core_38, type(pyarmor_core_123))]:
            pyarmor_core_22._handle_co(pyarmor_core_38, pyarmor_core_435)

    def handle(pyarmor_core_22, pyarmor_core_106):
        pyarmor_core_46 = pyarmor_core_106.mco
        pyarmor_core_22._pool = []
        for pyarmor_core_123 in pyarmor_core_46.co_consts:
            if isinstance(pyarmor_core_123, type(pyarmor_core_46)):
                pyarmor_core_22._handle_co(pyarmor_core_123, {})

class pyarmor_core_448(Component):
    LOGNAME = 'cli.vmc'

    def __init__(pyarmor_core_22, pyarmor_core_23, pyarmor_core_1):
        super().__init__(pyarmor_core_23)
        pyarmor_core_22.impt = pyarmor_core_1

    def handle(pyarmor_core_22, pyarmor_core_106):
        if not getattr(pyarmor_core_106, 'vmcblocks', None):
            pyarmor_core_22.logger.info('no vmc blocks found')
            return
        pyarmor_core_22.logger.debug('patch vmc')
        pyarmor_core_440 = pyarmor_core_22.impt['fix_co_object']
        pyarmor_core_449 = pyarmor_core_106.vmcblocks
        pyarmor_core_46 = pyarmor_core_106.mco
        pyarmor_core_450 = type(pyarmor_core_46)
        pyarmor_core_318 = (None, None, None, None)
        pyarmor_core_451 = pyarmor_core_280.ECC_CONSTS
        pyarmor_core_452 = '__pyarmor_ecc_code_block_'
        pyarmor_core_317 = pyarmor_core_46.co_consts.index(pyarmor_core_451)
        pyarmor_core_22.logger.info('find vmc index: %s', pyarmor_core_317)
        pyarmor_core_106.vmcindex = pyarmor_core_317
        pyarmor_core_453 = pyarmor_core_454()

        def pyarmor_core_455(pyarmor_core_123):
            pyarmor_core_456 = list(pyarmor_core_123.co_consts)
            pyarmor_core_33 = 0
            for pyarmor_core_38 in pyarmor_core_123.co_consts:
                if isinstance(pyarmor_core_38, pyarmor_core_450):
                    pyarmor_core_455(pyarmor_core_38)
                elif isinstance(pyarmor_core_38, str) and pyarmor_core_38.startswith(pyarmor_core_452):
                    pyarmor_core_456[pyarmor_core_33] = pyarmor_core_453.build_vmcode(pyarmor_core_123, pyarmor_core_449[pyarmor_core_38])
                elif pyarmor_core_38 is pyarmor_core_451:
                    pyarmor_core_456[pyarmor_core_33] = pyarmor_core_318
                pyarmor_core_33 += 1
            pyarmor_core_440(pyarmor_core_123, b'co_consts', tuple(pyarmor_core_456))
        pyarmor_core_455(pyarmor_core_46)
import ast
import re
from fnmatch import fnmatchcase
pyarmor_core_457 = (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)

def pyarmor_core_253(pyarmor_core_251, pyarmor_core_226):
    if not pyarmor_core_226.level:
        return pyarmor_core_226.module
    if pyarmor_core_251.count('.') < pyarmor_core_226.level:
        pyarmor_core_261 = getattr(pyarmor_core_226, 'lineno', -1)
        raise RuntimeError('"%s" line %d relative import "%s" overflow' % (pyarmor_core_251, pyarmor_core_261, pyarmor_core_226.module))
    pyarmor_core_458 = pyarmor_core_251.split('.')[:-pyarmor_core_226.level]
    if pyarmor_core_226.module:
        pyarmor_core_458.append(pyarmor_core_226.module)
    return '.'.join(pyarmor_core_458)

def pyarmor_core_460(pyarmor_core_459):
    pyarmor_core_461 = []
    pyarmor_core_226 = pyarmor_core_459
    while isinstance(pyarmor_core_226, ast.Attribute) or isinstance(pyarmor_core_226, ast.Call) or isinstance(pyarmor_core_226, ast.Subscript):
        if isinstance(pyarmor_core_226, ast.Attribute):
            pyarmor_core_461.insert(0, pyarmor_core_226)
        pyarmor_core_226 = pyarmor_core_226.func if isinstance(pyarmor_core_226, ast.Call) else pyarmor_core_226.value
    if pyarmor_core_459 is not pyarmor_core_226:
        pyarmor_core_461.insert(0, pyarmor_core_226)
    return pyarmor_core_461

def pyarmor_core_462(pyarmor_core_461):
    return '.'.join([pyarmor_core_38.attr if isinstance(pyarmor_core_38, ast.Attribute) else pyarmor_core_38.id if isinstance(pyarmor_core_38, ast.Name) else pyarmor_core_462([pyarmor_core_38.func]) if isinstance(pyarmor_core_38, ast.Call) else pyarmor_core_462([pyarmor_core_38.value]) if isinstance(pyarmor_core_38, ast.Subscript) else '<%s>' % type(pyarmor_core_38.value).__name__ if isinstance(pyarmor_core_38, ast.Constant) else '<%s>' % type(pyarmor_core_38).__name__ for pyarmor_core_38 in pyarmor_core_461])

def pyarmor_core_463(pyarmor_core_459):
    pyarmor_core_226 = pyarmor_core_459
    while isinstance(pyarmor_core_226, ast.Attribute) or isinstance(pyarmor_core_226, ast.Call) or isinstance(pyarmor_core_226, ast.Subscript):
        if isinstance(pyarmor_core_226, ast.Call):
            for pyarmor_core_38 in pyarmor_core_226.args + pyarmor_core_226.keywords:
                yield pyarmor_core_38
        elif isinstance(pyarmor_core_226, ast.Subscript):
            yield pyarmor_core_226.slice
        pyarmor_core_226 = pyarmor_core_226.func if isinstance(pyarmor_core_226, ast.Call) else pyarmor_core_226.value
        yield pyarmor_core_226
    if pyarmor_core_459 is not pyarmor_core_226:
        yield pyarmor_core_226

def pyarmor_core_464(pyarmor_core_459):
    pyarmor_core_461 = []
    pyarmor_core_226 = pyarmor_core_459
    while isinstance(pyarmor_core_226, ast.Attribute) or isinstance(pyarmor_core_226, ast.Call) or isinstance(pyarmor_core_226, ast.Subscript):
        pyarmor_core_461.insert(0, pyarmor_core_226)
        if isinstance(pyarmor_core_226, ast.Attribute):
            pyarmor_core_226 = pyarmor_core_226.value
        elif isinstance(pyarmor_core_226, ast.Call):
            if isinstance(pyarmor_core_226.func, ast.Attribute):
                pyarmor_core_226 = pyarmor_core_226.func.value
            elif isinstance(pyarmor_core_226.func, (ast.Subscript, ast.Call)):
                pyarmor_core_226 = pyarmor_core_226.func
            else:
                break
        elif isinstance(pyarmor_core_226, ast.Subscript):
            if isinstance(pyarmor_core_226.value, ast.Attribute):
                pyarmor_core_226 = pyarmor_core_226.value.value
            elif isinstance(pyarmor_core_226.value, (ast.Subscript, ast.Call)):
                pyarmor_core_226 = pyarmor_core_226.value
            else:
                break
    else:
        if pyarmor_core_459 is not pyarmor_core_226:
            pyarmor_core_461.insert(0, pyarmor_core_226)
    return pyarmor_core_461

def pyarmor_core_465(pyarmor_core_102, pyarmor_core_71):
    """"""
    if pyarmor_core_71.startswith('*'):
        return pyarmor_core_102.endswith(pyarmor_core_71[1:])
    elif pyarmor_core_71.endswith('*'):
        return pyarmor_core_102.startswith(pyarmor_core_71[:-1])
    elif pyarmor_core_71.startswith('/'):
        return bool(re.match(pyarmor_core_71[1:-1], pyarmor_core_102))
    elif pyarmor_core_71.find(' ') > 0:
        return pyarmor_core_102 in pyarmor_core_71.split()
    else:
        return fnmatchcase(pyarmor_core_102, pyarmor_core_71)

def pyarmor_core_466(pyarmor_core_44, pyarmor_core_432, pyarmor_core_433):
    return (not pyarmor_core_432 or any([pyarmor_core_465(pyarmor_core_38, pyarmor_core_44) for pyarmor_core_38 in pyarmor_core_432])) and (not any([pyarmor_core_465(pyarmor_core_38, pyarmor_core_44) for pyarmor_core_38 in pyarmor_core_433]))

class pyarmor_core_245(object):
    """"""

    def __init__(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_22._tree = pyarmor_core_278
        pyarmor_core_22._stack = []

    @property
    def stack(pyarmor_core_22):
        return [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_22._stack if isinstance(pyarmor_core_38[0], pyarmor_core_457)]

    @property
    def domain(pyarmor_core_22):
        return '.'.join([pyarmor_core_38[0].name for pyarmor_core_38 in pyarmor_core_22.stack])

    @property
    def top(pyarmor_core_22, n=0):
        return pyarmor_core_22._stack[-n - 1]

    def travel(pyarmor_core_22, ignored=None, noattrs=('ctx',)):

        def pyarmor_core_385(pyarmor_core_226):
            for (pyarmor_core_233, pyarmor_core_467) in ast.iter_fields(pyarmor_core_226):
                if pyarmor_core_233 in noattrs:
                    continue
                if ignored and isinstance(pyarmor_core_467, ignored):
                    continue
                if isinstance(pyarmor_core_467, ast.AST):
                    pyarmor_core_22._stack.append((pyarmor_core_226, pyarmor_core_233))
                    yield pyarmor_core_467
                    for pyarmor_core_38 in pyarmor_core_385(pyarmor_core_467):
                        yield pyarmor_core_38
                    pyarmor_core_22._stack.pop()
                elif isinstance(pyarmor_core_467, list):
                    pyarmor_core_220 = 0
                    for pyarmor_core_177 in pyarmor_core_467:
                        if isinstance(pyarmor_core_177, ast.AST) and (not (ignored and isinstance(pyarmor_core_177, ignored))):
                            pyarmor_core_22._stack.append((pyarmor_core_226, pyarmor_core_233, pyarmor_core_220))
                            yield pyarmor_core_177
                            for pyarmor_core_38 in pyarmor_core_385(pyarmor_core_177):
                                yield pyarmor_core_38
                            pyarmor_core_22._stack.pop()
                        pyarmor_core_220 += 1
        for pyarmor_core_38 in pyarmor_core_385(pyarmor_core_22._tree):
            yield pyarmor_core_38

class pyarmor_core_241(object):

    def __init__(pyarmor_core_22, pyarmor_core_432, pyarmor_core_433, namepool=None):
        pyarmor_core_22._includes = pyarmor_core_432.splitlines() if pyarmor_core_432 else []
        pyarmor_core_22._excludes = pyarmor_core_433.splitlines() if pyarmor_core_433 else []
        if namepool:
            pyarmor_core_22._refactor_rules(namepool)

    def check(pyarmor_core_22, pyarmor_core_44):
        return pyarmor_core_466(pyarmor_core_44, pyarmor_core_22._includes, pyarmor_core_22._excludes)

    def _refactor_rules(pyarmor_core_22, pyarmor_core_468):

        def pyarmor_core_470(pyarmor_core_469):
            for pyarmor_core_71 in pyarmor_core_469[:]:
                if pyarmor_core_71.startswith('/'):
                    continue
                pyarmor_core_471 = ' '.join([pyarmor_core_468(pyarmor_core_38) if pyarmor_core_38.isidentifier() and pyarmor_core_468(pyarmor_core_38, test=True) else pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_71.split(' ')])
                if pyarmor_core_471 != pyarmor_core_71:
                    pyarmor_core_469.append(pyarmor_core_471)
        pyarmor_core_470(pyarmor_core_22._includes)
        pyarmor_core_470(pyarmor_core_22._excludes)

class pyarmor_core_472(pyarmor_core_241):

    def __init__(pyarmor_core_22, pyarmor_core_432, pyarmor_core_433, visitor=None):
        super().__init__(pyarmor_core_432, pyarmor_core_433)
        pyarmor_core_22._visitor = visitor

def pyarmor_core_473(pyarmor_core_226, pyarmor_core_251, pyarmor_core_71):
    pyarmor_core_33 = pyarmor_core_71.find(':')
    pyarmor_core_474 = '' if pyarmor_core_33 == -1 else pyarmor_core_71[:pyarmor_core_33]
    pyarmor_core_475 = pyarmor_core_71[pyarmor_core_33 + 1:]
    if pyarmor_core_251.startswith(pyarmor_core_474) or (pyarmor_core_474[:1] == '@' and pyarmor_core_226.lineno == int(pyarmor_core_474[1:])):
        pyarmor_core_476 = get_node_name(pyarmor_core_226)
        if pyarmor_core_476 is None:
            return False
        if pyarmor_core_475[0] == '=':
            return pyarmor_core_475[1:] == pyarmor_core_476
        elif pyarmor_core_475[0] == '+':
            return pyarmor_core_476.startswith(pyarmor_core_475)
        elif pyarmor_core_475[0] == '-':
            return pyarmor_core_476.endswith(pyarmor_core_475[1:])
        elif pyarmor_core_475[0] == '*':
            return False
        elif pyarmor_core_475[0] == '/':
            return pyarmor_core_476.find(pyarmor_core_475[1:]) > -1
        elif pyarmor_core_475[0] == '?':
            return re.search(pyarmor_core_475[:1], pyarmor_core_476) is not None
        else:
            return pyarmor_core_476 in pyarmor_core_475.split()
import ast

class pyarmor_core_477(dict):

    def __getattr__(pyarmor_core_22, pyarmor_core_233):
        if pyarmor_core_233 in pyarmor_core_22._FIELDS:
            return pyarmor_core_22[pyarmor_core_233]
        elif pyarmor_core_233[:3] == 'is_' and pyarmor_core_233[3:] in pyarmor_core_22:
            return pyarmor_core_22[pyarmor_core_233[3:]]
        raise AttributeError(pyarmor_core_233)

    def __setattr__(pyarmor_core_22, pyarmor_core_233, pyarmor_core_44):
        if pyarmor_core_233 in pyarmor_core_22._FIELDS:
            pyarmor_core_22[pyarmor_core_233] = pyarmor_core_44
        else:
            super().__setattr__(pyarmor_core_233, pyarmor_core_44)

    def __eq__(pyarmor_core_22, pyarmor_core_54):
        return pyarmor_core_22.name == pyarmor_core_54.name and pyarmor_core_22.cls == pyarmor_core_54.cls

class pyarmor_core_478(pyarmor_core_477):
    _FIELDS = ('name', 'cls')

    def __init__(pyarmor_core_22, pyarmor_core_102, cls='', **pyarmor_core_479):
        super().__init__(name=pyarmor_core_102, cls=cls, **pyarmor_core_479)

class pyarmor_core_480(pyarmor_core_477):
    _FIELDS = ('name', 'cls', 'fields', 'imports')

    def __init__(pyarmor_core_22, pyarmor_core_102, cls='class', **pyarmor_core_479):
        super().__init__(name=pyarmor_core_102, cls=cls, fields=[], imports={}, **pyarmor_core_479)
        pyarmor_core_22.bases = []

    def append(pyarmor_core_22, pyarmor_core_481):
        if pyarmor_core_481 and pyarmor_core_481 not in pyarmor_core_22.fields:
            pyarmor_core_22.fields.append(pyarmor_core_481)

    def find(pyarmor_core_22, pyarmor_core_102, inner=False):
        for pyarmor_core_38 in pyarmor_core_22.fields:
            if pyarmor_core_102 == pyarmor_core_38.name:
                return pyarmor_core_38
        if inner:
            return
        for pyarmor_core_38 in pyarmor_core_22.imports:
            if pyarmor_core_38 == pyarmor_core_102:
                return pyarmor_core_22.imports[pyarmor_core_38]
            elif pyarmor_core_38.endswith('.*'):
                for pyarmor_core_54 in pyarmor_core_22.imports[pyarmor_core_38]:
                    if pyarmor_core_102 == pyarmor_core_54.name:
                        return pyarmor_core_54

    def imp_node(pyarmor_core_22, pyarmor_core_226, qualname=''):
        if isinstance(pyarmor_core_226, ast.Import):
            for pyarmor_core_38 in pyarmor_core_226.names:
                pyarmor_core_482 = pyarmor_core_38.asname if pyarmor_core_38.asname else pyarmor_core_38.name
                pyarmor_core_482 = pyarmor_core_482.split('.')[0]
                pyarmor_core_102 = pyarmor_core_38.name.split('.')[0]
                pyarmor_core_22.imports[pyarmor_core_482] = pyarmor_core_478(pyarmor_core_102, 'import')
        elif isinstance(pyarmor_core_226, ast.ImportFrom):
            pyarmor_core_121 = pyarmor_core_253(qualname, pyarmor_core_226)
            for pyarmor_core_38 in pyarmor_core_226.names:
                pyarmor_core_482 = pyarmor_core_38.asname if pyarmor_core_38.asname else pyarmor_core_38.name
                pyarmor_core_102 = pyarmor_core_121 + '.' + pyarmor_core_38.name
                if pyarmor_core_482 == '*':
                    pyarmor_core_22.imports[pyarmor_core_121 + '.*'] = []
                else:
                    pyarmor_core_22.imports[pyarmor_core_482] = pyarmor_core_478(pyarmor_core_102, 'import')

    def add_node(pyarmor_core_22, pyarmor_core_226, cls=None):
        pyarmor_core_102 = pyarmor_core_226.id if isinstance(pyarmor_core_226, ast.Name) else pyarmor_core_226.name if isinstance(pyarmor_core_226, pyarmor_core_457) else None
        if not pyarmor_core_102:
            pyarmor_core_261 = getattr(pyarmor_core_226, 'lineno', -1)
            raise RuntimeError('type "%s" line %d has an invalid node "%s"' % (pyarmor_core_22.name, type(pyarmor_core_226).__name__, pyarmor_core_261))
        pyarmor_core_481 = pyarmor_core_22.find(pyarmor_core_102, inner=True)
        if pyarmor_core_481:
            if pyarmor_core_481.cls == '<?>' and cls and (cls != '<?>'):
                pyarmor_core_481.cls = cls
        else:
            cls = cls if cls is not None else 'class' if isinstance(pyarmor_core_226, ast.ClassDef) else 'function' if isinstance(pyarmor_core_226, pyarmor_core_457) else '<?>'
            pyarmor_core_22.append(pyarmor_core_478(pyarmor_core_102, cls))

    def extend(pyarmor_core_22, pyarmor_core_41):
        for pyarmor_core_38 in pyarmor_core_41:
            if not isinstance(pyarmor_core_38, pyarmor_core_478):
                raise RuntimeError('type "%s" extends invalid field "%s"' % pyarmor_core_38)
            pyarmor_core_22.append(pyarmor_core_38)

    def star_names(pyarmor_core_22):
        pyarmor_core_36 = [pyarmor_core_38.name for pyarmor_core_38 in pyarmor_core_22.fields]
        for pyarmor_core_38 in pyarmor_core_22.imports:
            if pyarmor_core_38.endswith('.*'):
                pyarmor_core_36.extend([pyarmor_core_38.name for pyarmor_core_38 in pyarmor_core_22.imports[pyarmor_core_38]])
            else:
                pyarmor_core_36.append(pyarmor_core_38)
        return [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_36 if not pyarmor_core_38.startswith('_')]

    def __str__(pyarmor_core_22):
        from json import dumps
        return dumps(pyarmor_core_22, indent=2)

class pyarmor_core_483(object):

    def __init__(pyarmor_core_22, pyarmor_core_23, name=None, node=None, co=None):
        pyarmor_core_22.ctx = pyarmor_core_23
        pyarmor_core_22._name = name
        pyarmor_core_22._node = node
        pyarmor_core_22._co = co

    def reset(pyarmor_core_22, name=None, node=None, co=None):
        pyarmor_core_22._name = name
        pyarmor_core_22._node = node
        pyarmor_core_22._co = co

    def log(pyarmor_core_22, pyarmor_core_252, pyarmor_core_226, pyarmor_core_30):
        pyarmor_core_261 = getattr(pyarmor_core_226, 'lineno', -1)
        logger.debug('%s:%s: %s', pyarmor_core_252, pyarmor_core_261, pyarmor_core_30)

    @property
    def using_modules(pyarmor_core_22):
        return pyarmor_core_22._get_using_modules(pyarmor_core_22._name, pyarmor_core_22._node)

    def rebuild(pyarmor_core_22):
        pyarmor_core_22._get_module_types(pyarmor_core_22._name, pyarmor_core_22._node)

    def _constant_type(pyarmor_core_22, pyarmor_core_44):
        return '<%s>' % type(pyarmor_core_44).__name__

    def _get_field_type(pyarmor_core_22, pyarmor_core_121, pyarmor_core_481):
        if pyarmor_core_481.cls == 'import':
            pyarmor_core_179 = pyarmor_core_481.name
        elif pyarmor_core_481.cls in ('class', 'module'):
            pyarmor_core_179 = pyarmor_core_121 + '.' + pyarmor_core_481.name
        elif pyarmor_core_481.cls in ('function',):
            pyarmor_core_179 = pyarmor_core_22.ctx.variable_types.get(pyarmor_core_121 + '.' + pyarmor_core_481.name)
        else:
            pyarmor_core_179 = pyarmor_core_481.cls
        return pyarmor_core_179

    def guess_type(pyarmor_core_22, pyarmor_core_251, pyarmor_core_484, pyarmor_core_226):
        pyarmor_core_485 = getattr(pyarmor_core_226, 'type_comment', None)
        if not pyarmor_core_485:
            pyarmor_core_486 = getattr(pyarmor_core_226, 'annotation', getattr(pyarmor_core_226, 'returns', None))
            if pyarmor_core_486:
                pyarmor_core_485 = pyarmor_core_486.id if isinstance(pyarmor_core_486, ast.Name) else getattr(pyarmor_core_486, 'value', getattr(pyarmor_core_486, 's', None))
        if pyarmor_core_485:
            pyarmor_core_27 = pyarmor_core_22.ctx.module_types.get(pyarmor_core_251)
            if pyarmor_core_27:
                pyarmor_core_481 = pyarmor_core_27.find(pyarmor_core_485)
                if pyarmor_core_481:
                    return pyarmor_core_22._get_field_type(pyarmor_core_251, pyarmor_core_481)
            return '<%s>' % pyarmor_core_485
        pyarmor_core_226 = getattr(pyarmor_core_226, 'value', None)
        if not (pyarmor_core_226 and isinstance(pyarmor_core_226, ast.AST)):
            return '<?>'
        if isinstance(pyarmor_core_226, ast.Constant):
            return pyarmor_core_22._constant_type(pyarmor_core_226.value)
        for pyarmor_core_38 in ('Num', 'Str', 'Bytes', 'NameConstant'):
            if isinstance(pyarmor_core_226, getattr(ast, pyarmor_core_38, type(None))):
                return pyarmor_core_22._constant_type(pyarmor_core_226.n if hasattr(pyarmor_core_226, 'n') else pyarmor_core_226.s if hasattr(pyarmor_core_226, 's') else pyarmor_core_226.value)
        pyarmor_core_27 = pyarmor_core_22.ctx.module_types.get(pyarmor_core_251)
        if not pyarmor_core_27:
            return '<?>'

        def pyarmor_core_487(pyarmor_core_211):
            if pyarmor_core_211 in pyarmor_core_22.ctx.module_types:
                return True
            pyarmor_core_102 = pyarmor_core_211.split('.')[-1]
            return pyarmor_core_102 and pyarmor_core_102.isidentifier() and pyarmor_core_102[0].isupper() and any([pyarmor_core_38.islower() or pyarmor_core_38.isdigit() for pyarmor_core_38 in pyarmor_core_102]) and (not all([pyarmor_core_38.isupper() or pyarmor_core_38.isdigit() or pyarmor_core_38 == '_' for pyarmor_core_38 in pyarmor_core_102]))
        if isinstance(pyarmor_core_226, ast.Name):
            pyarmor_core_481 = pyarmor_core_27.find(pyarmor_core_226.id)
            if pyarmor_core_481:
                return pyarmor_core_22._get_field_type(pyarmor_core_27.name, pyarmor_core_481)
            pyarmor_core_178 = '.'.join(pyarmor_core_484 + [pyarmor_core_226.id])
            return pyarmor_core_22.ctx.variable_types.get(pyarmor_core_178, '<?>')
        elif isinstance(pyarmor_core_226, ast.Call):
            if isinstance(pyarmor_core_226.func, ast.Name):
                pyarmor_core_481 = pyarmor_core_27.find(pyarmor_core_226.func.id)
                if pyarmor_core_481:
                    if pyarmor_core_481.cls == 'class':
                        return pyarmor_core_27.name + '.' + pyarmor_core_481.name
                    elif pyarmor_core_481.cls == 'import':
                        if pyarmor_core_487(pyarmor_core_481.name):
                            return pyarmor_core_481.name
                        else:
                            return pyarmor_core_22.ctx.variable_types.get(pyarmor_core_481.name, '(%s)' % pyarmor_core_481.name)
                    elif pyarmor_core_481.cls == 'function':
                        pyarmor_core_488 = pyarmor_core_27.name + '.' + pyarmor_core_481.name
                        return pyarmor_core_22.ctx.variable_types.get(pyarmor_core_488, '(%s)' % pyarmor_core_488)
        return '<?>'

    def _get_module_types(pyarmor_core_22, pyarmor_core_251, pyarmor_core_278):
        pyarmor_core_176 = pyarmor_core_22.ctx.variable_types
        pyarmor_core_489 = pyarmor_core_22.ctx.module_types
        pyarmor_core_490 = pyarmor_core_22.ctx.base_types[pyarmor_core_251] = []
        pyarmor_core_484 = []

        def pyarmor_core_491(pyarmor_core_226):
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_178 = '.'.join(pyarmor_core_484)
                if pyarmor_core_178 in pyarmor_core_489:
                    pyarmor_core_489[pyarmor_core_178].add_node(pyarmor_core_226)
                pyarmor_core_484.append(pyarmor_core_226.name)
                if isinstance(pyarmor_core_226, ast.ClassDef):
                    pyarmor_core_178 = '.'.join(pyarmor_core_484)
                    if pyarmor_core_178 in pyarmor_core_489:
                        pyarmor_core_22.log(pyarmor_core_251, pyarmor_core_226, 'duplicated type "%s"' % pyarmor_core_178)
                    pyarmor_core_492 = pyarmor_core_489[pyarmor_core_178] = pyarmor_core_480(pyarmor_core_178)
                    pyarmor_core_493 = [pyarmor_core_38.id for pyarmor_core_38 in pyarmor_core_226.bases if isinstance(pyarmor_core_38, ast.Name)]
                    if pyarmor_core_493:
                        pyarmor_core_490.append((pyarmor_core_492, pyarmor_core_493))
            for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                pyarmor_core_491(pyarmor_core_467)
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_484.pop()

        def pyarmor_core_495(pyarmor_core_178, pyarmor_core_226, pyarmor_core_494):
            pyarmor_core_494 = pyarmor_core_494 if pyarmor_core_494 else '<?>'
            if pyarmor_core_178 in pyarmor_core_489:
                pyarmor_core_489[pyarmor_core_178].add_node(pyarmor_core_226)
                pyarmor_core_481 = pyarmor_core_489[pyarmor_core_178].find(pyarmor_core_226.id)
                if pyarmor_core_481.cls in ('<?>', ''):
                    pyarmor_core_481.cls = pyarmor_core_494
            pyarmor_core_176[pyarmor_core_178 + '.' + pyarmor_core_226.id] = pyarmor_core_494

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Assign):
                pyarmor_core_178 = '.'.join(pyarmor_core_484)
                for pyarmor_core_88 in pyarmor_core_226.targets:
                    if isinstance(pyarmor_core_88, ast.Name):
                        pyarmor_core_496 = pyarmor_core_22.guess_type(pyarmor_core_251, pyarmor_core_484, pyarmor_core_226)
                        pyarmor_core_495(pyarmor_core_178, pyarmor_core_88, pyarmor_core_496)
                    elif isinstance(pyarmor_core_88, ast.Tuple):
                        for pyarmor_core_497 in pyarmor_core_88.elts:
                            if isinstance(pyarmor_core_497, ast.Name):
                                pyarmor_core_495(pyarmor_core_178, pyarmor_core_497, '<?>')
                            elif isinstance(pyarmor_core_497, ast.Attribute):
                                pass
                    elif isinstance(pyarmor_core_88, ast.Attribute) and isinstance(pyarmor_core_88.ctx, ast.Store):
                        pyarmor_core_498 = pyarmor_core_460(pyarmor_core_88)
                        pyarmor_core_459 = pyarmor_core_498.pop(0)
                        if isinstance(pyarmor_core_459, ast.Name) and len(pyarmor_core_498) == 1:
                            pyarmor_core_499 = '.'.join(pyarmor_core_484 + [pyarmor_core_459.id])
                            pyarmor_core_500 = pyarmor_core_176.get(pyarmor_core_499)
                            if pyarmor_core_500 and pyarmor_core_500 in pyarmor_core_489:
                                pyarmor_core_496 = pyarmor_core_22.guess_type(pyarmor_core_251, pyarmor_core_484, pyarmor_core_226)
                                pyarmor_core_481 = pyarmor_core_478(pyarmor_core_498[0].attr, cls=pyarmor_core_496)
                                pyarmor_core_489[pyarmor_core_500].extend([pyarmor_core_481])
                return
            elif isinstance(pyarmor_core_226, ast.AnnAssign):
                if isinstance(pyarmor_core_226.target, ast.Name):
                    pyarmor_core_178 = '.'.join(pyarmor_core_484)
                    pyarmor_core_486 = pyarmor_core_226.annotation
                    if isinstance(pyarmor_core_486, ast.Name):
                        pyarmor_core_496 = pyarmor_core_486.id
                    elif isinstance(pyarmor_core_486, ast.Attribute):
                        pyarmor_core_496 = pyarmor_core_462(pyarmor_core_460(pyarmor_core_486))
                    elif isinstance(pyarmor_core_486, ast.Subscript):
                        pyarmor_core_496 = getattr(pyarmor_core_486.value, 'id', '?')
                    else:
                        pyarmor_core_496 = '?'
                    if pyarmor_core_496 not in pyarmor_core_489:
                        pyarmor_core_496 = '<%s>' % pyarmor_core_496
                    pyarmor_core_495(pyarmor_core_178, pyarmor_core_226.target, pyarmor_core_496)
                return
            elif isinstance(pyarmor_core_226, ast.Import):
                pyarmor_core_178 = '.'.join(pyarmor_core_484)
                if pyarmor_core_178 in pyarmor_core_489:
                    pyarmor_core_489[pyarmor_core_178].imp_node(pyarmor_core_226)
                return
            elif isinstance(pyarmor_core_226, ast.ImportFrom):
                pyarmor_core_178 = '.'.join(pyarmor_core_484)
                if pyarmor_core_178 in pyarmor_core_489:
                    pyarmor_core_489[pyarmor_core_178].imp_node(pyarmor_core_226, pyarmor_core_251)
                return
            elif isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_229 = '.'.join(pyarmor_core_484)
                pyarmor_core_484.append(pyarmor_core_226.name)
                if hasattr(pyarmor_core_226, 'args'):
                    pyarmor_core_178 = '.'.join(pyarmor_core_484)
                    pyarmor_core_485 = pyarmor_core_22.guess_type(pyarmor_core_251, pyarmor_core_484, pyarmor_core_226)
                    pyarmor_core_176[pyarmor_core_178] = pyarmor_core_485
                    pyarmor_core_501 = pyarmor_core_229 in pyarmor_core_489 and pyarmor_core_229 != pyarmor_core_251 and ('staticmethod' not in pyarmor_core_226.decorator_list)
                    pyarmor_core_200 = pyarmor_core_226.args
                    pyarmor_core_502 = getattr(pyarmor_core_200, 'posonlyargs', []) + pyarmor_core_200.args + pyarmor_core_200.kwonlyargs
                    if pyarmor_core_200.args and pyarmor_core_501:
                        pyarmor_core_411 = pyarmor_core_200.args[0]
                        pyarmor_core_176[pyarmor_core_178 + '.' + pyarmor_core_411.arg] = pyarmor_core_229
                        pyarmor_core_502.remove(pyarmor_core_411)
                    for pyarmor_core_411 in pyarmor_core_502:
                        pyarmor_core_265 = pyarmor_core_411.arg
                        pyarmor_core_485 = pyarmor_core_22.guess_type(pyarmor_core_251, pyarmor_core_484, pyarmor_core_411)
                        pyarmor_core_176[pyarmor_core_178 + '.' + pyarmor_core_265] = pyarmor_core_485
            for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                pyarmor_core_385(pyarmor_core_467)
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_484.pop()
        pyarmor_core_489[pyarmor_core_251] = pyarmor_core_480(pyarmor_core_251, cls='module')
        pyarmor_core_484 = [pyarmor_core_251]
        pyarmor_core_491(pyarmor_core_278)
        pyarmor_core_484 = [pyarmor_core_251]
        pyarmor_core_385(pyarmor_core_278)

    def _get_using_modules(pyarmor_core_22, pyarmor_core_211, pyarmor_core_278):
        pyarmor_core_503 = set()

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Import):
                pyarmor_core_503.update([pyarmor_core_38.name for pyarmor_core_38 in pyarmor_core_226.names])
            elif isinstance(pyarmor_core_226, ast.ImportFrom):
                pyarmor_core_503.add(pyarmor_core_253(pyarmor_core_211, pyarmor_core_226))
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_503

    def _search_class_attrs(pyarmor_core_22, pyarmor_core_235):
        pyarmor_core_504 = set()

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Assign):
                for pyarmor_core_88 in pyarmor_core_226.targets:
                    if isinstance(pyarmor_core_88, ast.Attribute):
                        pyarmor_core_505 = []
                        while isinstance(pyarmor_core_88, ast.Attribute):
                            pyarmor_core_505.insert(0, pyarmor_core_88.attr)
                            pyarmor_core_88 = pyarmor_core_88.value
                        if isinstance(pyarmor_core_88, ast.Name):
                            if pyarmor_core_88.id == pyarmor_core_458:
                                pyarmor_core_504.add(pyarmor_core_505[0])
            elif isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_504.add(pyarmor_core_226)
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_458 = pyarmor_core_235.args.args[0].arg if pyarmor_core_235.args.args else '@'
        for pyarmor_core_38 in pyarmor_core_235.body:
            pyarmor_core_385(pyarmor_core_38)
        return pyarmor_core_504

    def _get_hidden_imports(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_506 = []
        pyarmor_core_507 = (ast.Constant, getattr(ast, 'Str', ast.Constant))

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Call) and isinstance(pyarmor_core_226.func, ast.Name) and (pyarmor_core_226.func.id in ('__import__', '__dict__')) and pyarmor_core_226.func.args and isinstance(pyarmor_core_226.func.args[0], pyarmor_core_507):
                pass
            elif isinstance(pyarmor_core_226, ast.Call) and isinstance(pyarmor_core_226.func, ast.Name) and (pyarmor_core_226.func.id in ('getattr', 'setattr')) and (len(pyarmor_core_226.args) > 1) and isinstance(pyarmor_core_226.args[0], ast.Name) and isinstance(pyarmor_core_226.args[1], pyarmor_core_507):
                pass
            for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_506

    def _get_body_names(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_498 = set()

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Assign):
                for pyarmor_core_88 in pyarmor_core_226.targets:
                    if isinstance(pyarmor_core_88, ast.Name):
                        pyarmor_core_498.add(pyarmor_core_88)
            elif isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_498.add(pyarmor_core_226)
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        for pyarmor_core_38 in pyarmor_core_226.body:
            pyarmor_core_385(pyarmor_core_38)
        return pyarmor_core_498

    def _get_module_names(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_508 = {}
        pyarmor_core_484 = []

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_484.append(pyarmor_core_226.name)
            elif isinstance(pyarmor_core_226, ast.Name):
                pyarmor_core_178 = '.'.join(pyarmor_core_484)
                pyarmor_core_508.setdefault(pyarmor_core_178, set())
                pyarmor_core_508[pyarmor_core_178].add(pyarmor_core_226.id)
                return
            for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                pyarmor_core_385(pyarmor_core_467)
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_484.pop()
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_508

    def _get_module_attrs(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_509 = set()

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Assign):
                for pyarmor_core_88 in pyarmor_core_226.targets:
                    if isinstance(pyarmor_core_88, ast.Name):
                        pyarmor_core_509.add(pyarmor_core_88.id)
            elif isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_509.add(pyarmor_core_226.name)
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)

        def pyarmor_core_510(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Global):
                pyarmor_core_509.update(pyarmor_core_226.names)
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_510(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        pyarmor_core_510(pyarmor_core_278)
        return pyarmor_core_509

    def _get_import_names(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_511 = {}

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.ImportFrom):
                pyarmor_core_102 = '.' * pyarmor_core_226.level + pyarmor_core_226.module if pyarmor_core_226.module else ''
                pyarmor_core_511.setdefault(pyarmor_core_102, set())
                pyarmor_core_511[pyarmor_core_102].update([pyarmor_core_38.name for pyarmor_core_38 in pyarmor_core_226.names])
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_511

    def _get_import_modules(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_512 = {}

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, ast.Import):
                for (pyarmor_core_102, pyarmor_core_482) in [(pyarmor_core_38.name, pyarmor_core_38.asname) for pyarmor_core_38 in pyarmor_core_226.names]:
                    pyarmor_core_512[pyarmor_core_482 if pyarmor_core_482 else pyarmor_core_102] = pyarmor_core_102
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_512

    def _get_import_attrs(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_509 = {}
        pyarmor_core_513 = ast.Attribute
        pyarmor_core_514 = ast.Name

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, pyarmor_core_513) and isinstance(pyarmor_core_226.value, pyarmor_core_514):
                pyarmor_core_102 = pyarmor_core_226.value.id
                if pyarmor_core_102 in pyarmor_core_22.import_modules:
                    pyarmor_core_509.setdefault(pyarmor_core_102, set())
                    pyarmor_core_509[pyarmor_core_102].add(pyarmor_core_226.attr)
            else:
                for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                    pyarmor_core_385(pyarmor_core_467)
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_509

    def _get_mapped_names(pyarmor_core_22, pyarmor_core_278):
        pyarmor_core_431 = {'': set(pyarmor_core_22._get_module_attrs(pyarmor_core_278))}
        pyarmor_core_484 = []

        def pyarmor_core_385(pyarmor_core_226):
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                if pyarmor_core_484:
                    pyarmor_core_178 = '.'.join(pyarmor_core_484)
                    pyarmor_core_431.setdefault(pyarmor_core_178, set())
                    pyarmor_core_431[pyarmor_core_178].add(pyarmor_core_226.name)
                pyarmor_core_484.append(pyarmor_core_226.name)
            for pyarmor_core_467 in ast.iter_child_nodes(pyarmor_core_226):
                pyarmor_core_385(pyarmor_core_467)
            if isinstance(pyarmor_core_226, pyarmor_core_457):
                pyarmor_core_484.pop()
        pyarmor_core_385(pyarmor_core_278)
        return pyarmor_core_431

class pyarmor_core_186(object):

    def __init__(pyarmor_core_22, pyarmor_core_23):
        pyarmor_core_22.ctx = pyarmor_core_23

    def _import_star_names(pyarmor_core_22, pyarmor_core_106, pyarmor_core_252):
        pyarmor_core_320 = pyarmor_core_22.ctx.module_types.get(pyarmor_core_252)
        if pyarmor_core_320:
            pyarmor_core_36 = pyarmor_core_320.get('exports', pyarmor_core_320.star_names())
            pyarmor_core_515 = []
            pyarmor_core_176 = pyarmor_core_22.ctx.variable_types
            for pyarmor_core_38 in pyarmor_core_36:
                pyarmor_core_481 = pyarmor_core_320.find(pyarmor_core_38)
                if pyarmor_core_481.cls == 'class':
                    pyarmor_core_515.append(pyarmor_core_252 + '.' + pyarmor_core_38)
                elif pyarmor_core_481.cls == 'import':
                    pyarmor_core_515.append(pyarmor_core_481.name)
                else:
                    pyarmor_core_515.append(pyarmor_core_176.get(pyarmor_core_252 + '.' + pyarmor_core_38, '<?>'))
            return zip(pyarmor_core_36, pyarmor_core_515)
        try:
            pyarmor_core_126 = __import__(pyarmor_core_252, {}, {}, ['__all__'], 0)
            pyarmor_core_36 = getattr(pyarmor_core_126, '__all__', [pyarmor_core_38 for pyarmor_core_38 in dir(pyarmor_core_126) if pyarmor_core_38[:1] != '_'])
            pyarmor_core_515 = [type(getattr(pyarmor_core_126, pyarmor_core_38)).__name__ for pyarmor_core_38 in pyarmor_core_36]
            return zip(pyarmor_core_36, pyarmor_core_515)
        except ModuleNotFoundError as pyarmor_core_47:
            logger.error('import "%s" failed: %s', pyarmor_core_252, str(pyarmor_core_47))
            logger.error('please add extra path to PYTHONPATH to fix it')
            raise RuntimeError('could not handle "from %s import *" in the module "%s"' % (pyarmor_core_252, pyarmor_core_106.fullname))

    def _get_export_names(pyarmor_core_22, pyarmor_core_516):
        for pyarmor_core_226 in ast.walk(pyarmor_core_516.mtree):
            if isinstance(pyarmor_core_226, ast.Assign) and isinstance(pyarmor_core_226.targets[0], ast.Name) and (pyarmor_core_226.targets[0].id == '__all__'):
                if isinstance(pyarmor_core_226.value, ast.Constant):
                    pyarmor_core_517 = pyarmor_core_226.value
                elif isinstance(pyarmor_core_226.value, (ast.List, ast.Tuple)):
                    pyarmor_core_517 = [getattr(pyarmor_core_38, 's', getattr(pyarmor_core_38, 'value', None)) for pyarmor_core_38 in pyarmor_core_226.value.elts]
                else:
                    pyarmor_core_517 = None
                if not (isinstance(pyarmor_core_517, (list, tuple)) and all([isinstance(pyarmor_core_38, str) for pyarmor_core_38 in pyarmor_core_517])):
                    logger.error('invalid "__all__" in the module "%s": %s', pyarmor_core_516.fullname, ast.dump(pyarmor_core_226.value))
                    raise RuntimeError('"%s.__all__" is not a string list' % pyarmor_core_516.fullname)
                return pyarmor_core_517

    def _format_export_names(pyarmor_core_22, pyarmor_core_106, pyarmor_core_518):
        pyarmor_core_49 = []
        if pyarmor_core_518:
            pyarmor_core_27 = pyarmor_core_22.ctx.module_types[pyarmor_core_106.pkgname]
            for pyarmor_core_38 in pyarmor_core_518:
                pyarmor_core_481 = pyarmor_core_27.find(pyarmor_core_38)
                if not pyarmor_core_481:
                    logger.error('module "%s" exports "%s" in the "__all__", but not defined it', pyarmor_core_106.fullname, pyarmor_core_38)
                    raise RuntimeError('invalid module "%s"' % pyarmor_core_106.fullname)
                if pyarmor_core_481.cls == 'import':
                    pyarmor_core_49.append(pyarmor_core_481.name)
                pyarmor_core_49.append('%s.%s' % (pyarmor_core_106.pkgname, pyarmor_core_38))
        return pyarmor_core_49

    def _normalize_export_names(pyarmor_core_22):
        pyarmor_core_489 = pyarmor_core_22.ctx.module_types
        pyarmor_core_519 = pyarmor_core_22.ctx.rft_export_names
        pyarmor_core_520 = [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_519 if pyarmor_core_38 in pyarmor_core_489]
        for pyarmor_core_102 in pyarmor_core_520:
            pyarmor_core_521 = pyarmor_core_489[pyarmor_core_102]
            pyarmor_core_517 = ['.'.join([pyarmor_core_102, pyarmor_core_38]) for pyarmor_core_38 in pyarmor_core_521.star_names()]
            pyarmor_core_519.update([pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_517 if pyarmor_core_38 not in pyarmor_core_520])

    def _format_module_types(pyarmor_core_22):
        pyarmor_core_489 = pyarmor_core_22.ctx.module_types
        pyarmor_core_176 = pyarmor_core_22.ctx.variable_types
        pyarmor_core_522 = [pyarmor_core_38.split('.')[0] for pyarmor_core_38 in pyarmor_core_489]
        pyarmor_core_523 = {}
        for pyarmor_core_524 in pyarmor_core_522:
            pyarmor_core_523[pyarmor_core_524] = set([pyarmor_core_38.split('.')[1] for pyarmor_core_38 in pyarmor_core_489 if pyarmor_core_38.startswith(pyarmor_core_524 + '.')])
        pyarmor_core_25 = '.__init__'
        pyarmor_core_525 = [pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_489 if pyarmor_core_38.endswith(pyarmor_core_25)]
        for pyarmor_core_38 in pyarmor_core_525:
            pyarmor_core_489[pyarmor_core_38.replace(pyarmor_core_25, '')] = pyarmor_core_489.pop(pyarmor_core_38)
            pyarmor_core_526 = [pyarmor_core_295 for pyarmor_core_295 in pyarmor_core_176 if pyarmor_core_176[pyarmor_core_295].startswith(pyarmor_core_38)]
            for pyarmor_core_295 in pyarmor_core_526:
                pyarmor_core_527 = pyarmor_core_295.replace(pyarmor_core_25, '', 1)
                pyarmor_core_176[pyarmor_core_527] = pyarmor_core_176.pop(pyarmor_core_295)
        for pyarmor_core_524 in pyarmor_core_522:
            pyarmor_core_489.setdefault(pyarmor_core_524, pyarmor_core_480(pyarmor_core_524, cls='module'))
            pyarmor_core_489[pyarmor_core_524].extend([pyarmor_core_478(pyarmor_core_38, cls='module') for pyarmor_core_38 in pyarmor_core_523[pyarmor_core_524]])

    def _format_base_types(pyarmor_core_22, pyarmor_core_27, pyarmor_core_528, pyarmor_core_121):
        pyarmor_core_489 = pyarmor_core_22.ctx.module_types
        for (pyarmor_core_492, pyarmor_core_493) in pyarmor_core_528:
            for pyarmor_core_102 in pyarmor_core_493:
                pyarmor_core_481 = pyarmor_core_27.find(pyarmor_core_102)
                if pyarmor_core_481:
                    if pyarmor_core_481.cls == 'import':
                        pyarmor_core_38 = pyarmor_core_489.get(pyarmor_core_481.name, None)
                        if pyarmor_core_38:
                            pyarmor_core_492.bases.append(pyarmor_core_38)
                    elif pyarmor_core_481.cls == 'class':
                        pyarmor_core_179 = pyarmor_core_121 + '.' + pyarmor_core_481.name
                        pyarmor_core_38 = pyarmor_core_489.get(pyarmor_core_179, None)
                        if pyarmor_core_38:
                            pyarmor_core_492.bases.append(pyarmor_core_38)

    def process(pyarmor_core_22, clean=True):
        pyarmor_core_24 = pyarmor_core_22.ctx.cfg['builder']
        pyarmor_core_180 = pyarmor_core_22.ctx.cmd_options
        pyarmor_core_181 = pyarmor_core_180.get('enable_rft', pyarmor_core_24.getboolean('enable_rft'))
        pyarmor_core_130 = pyarmor_core_24.get('encoding')
        pyarmor_core_529 = pyarmor_core_181 and pyarmor_core_24.getboolean('rft_auto_export')
        pyarmor_core_530 = {}
        pyarmor_core_22.ctx.base_types = {}

        def pyarmor_core_531():
            for pyarmor_core_106 in pyarmor_core_22.ctx.resources:
                for pyarmor_core_516 in pyarmor_core_106:
                    if not pyarmor_core_516.is_script():
                        continue
                    yield pyarmor_core_516
        for pyarmor_core_516 in pyarmor_core_531():
            if not pyarmor_core_516.mtree:
                pyarmor_core_516.reparse(encoding=pyarmor_core_130)
            pyarmor_core_36 = pyarmor_core_22._get_export_names(pyarmor_core_516)
            if pyarmor_core_36:
                pyarmor_core_530[pyarmor_core_516.fullname] = pyarmor_core_36
        for pyarmor_core_516 in pyarmor_core_531():
            pyarmor_core_251 = pyarmor_core_516.fullname
            pyarmor_core_320 = pyarmor_core_483(pyarmor_core_22.ctx, pyarmor_core_251, pyarmor_core_516.mtree)
            pyarmor_core_320.rebuild()
            pyarmor_core_22.ctx.module_relations[pyarmor_core_516.pkgname] = pyarmor_core_320.using_modules
            pyarmor_core_517 = pyarmor_core_530.get(pyarmor_core_251)
            if pyarmor_core_517:
                pyarmor_core_22.ctx.module_types[pyarmor_core_251]['exports'] = pyarmor_core_517
        pyarmor_core_22._format_module_types()

        def pyarmor_core_532(pyarmor_core_516, pyarmor_core_481):
            if pyarmor_core_481.cls == '':
                logger.warning('type unknown "%s.%s"', pyarmor_core_516.fullname, pyarmor_core_481.name)
        for pyarmor_core_516 in pyarmor_core_531():
            pyarmor_core_251 = pyarmor_core_516.fullname
            pyarmor_core_27 = pyarmor_core_22.ctx.module_types.get(pyarmor_core_516.pkgname)
            pyarmor_core_528 = pyarmor_core_22.ctx.base_types.get(pyarmor_core_251)
            if pyarmor_core_528:
                pyarmor_core_22._format_base_types(pyarmor_core_27, pyarmor_core_528, pyarmor_core_516.pkgname)
            for (pyarmor_core_102, pyarmor_core_481) in pyarmor_core_27.imports.items():
                if pyarmor_core_102.endswith('.*'):
                    pyarmor_core_533 = pyarmor_core_102[:-2]
                    for (pyarmor_core_38, pyarmor_core_534) in pyarmor_core_22._import_star_names(pyarmor_core_516, pyarmor_core_533):
                        pyarmor_core_481.append(pyarmor_core_478(pyarmor_core_38, cls=pyarmor_core_534))
            [pyarmor_core_532(pyarmor_core_516, pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_27.fields]
        pyarmor_core_22.ctx.base_types = None
        if pyarmor_core_529:
            pyarmor_core_519 = pyarmor_core_22.ctx.rft_export_names
            for pyarmor_core_516 in pyarmor_core_531():
                pyarmor_core_518 = pyarmor_core_530.get(pyarmor_core_516.fullname)
                pyarmor_core_519.update(pyarmor_core_22._format_export_names(pyarmor_core_516, pyarmor_core_518))
            pyarmor_core_22._normalize_export_names()
        if clean:
            [pyarmor_core_516.clean() for pyarmor_core_516 in pyarmor_core_531()]
from collections import namedtuple
from marshal import dumps as marshal_dumps
pyarmor_core_535 = 0
pyarmor_core_536 = 127
pyarmor_core_537 = 1
pyarmor_core_538 = 2
pyarmor_core_539 = 3
pyarmor_core_540 = 6
pyarmor_core_541 = 8
pyarmor_core_542 = 12
pyarmor_core_543 = 14
pyarmor_core_544 = 16
pyarmor_core_545 = 18
pyarmor_core_546 = 20
pyarmor_core_547 = 30
pyarmor_core_548 = 32
pyarmor_core_549 = 33
pyarmor_core_550 = 34
pyarmor_core_551 = 38
pyarmor_core_552 = 40
pyarmor_core_553 = 42
pyarmor_core_554 = 43
pyarmor_core_555 = 45
pyarmor_core_556 = 46
pyarmor_core_557 = 48
pyarmor_core_558 = 49
pyarmor_core_559 = 51
pyarmor_core_560 = 60
pyarmor_core_561 = 62
pyarmor_core_562 = 64
pyarmor_core_563 = 66
pyarmor_core_564 = 70
pyarmor_core_565 = 72
pyarmor_core_566 = 100
pyarmor_core_567 = 101
pyarmor_core_568 = 103
pyarmor_core_569 = 105
pyarmor_core_570 = 224
pyarmor_core_571 = 128
pyarmor_core_572 = 130
pyarmor_core_573 = 132
pyarmor_core_574 = 134
pyarmor_core_575 = 136
pyarmor_core_576 = 138
pyarmor_core_577 = 140
pyarmor_core_578 = 141
pyarmor_core_579 = 150
pyarmor_core_580 = 151
pyarmor_core_581 = 152
pyarmor_core_582 = 160
pyarmor_core_583 = 161
pyarmor_core_584 = 165
pyarmor_core_585 = 169
pyarmor_core_586 = 170
pyarmor_core_587 = 171
pyarmor_core_588 = 172
pyarmor_core_589 = 173
pyarmor_core_590 = 174
pyarmor_core_591 = 175
pyarmor_core_592 = 176
pyarmor_core_593 = 177
pyarmor_core_594 = 178
pyarmor_core_595 = 179
pyarmor_core_596 = 180
pyarmor_core_597 = 181
pyarmor_core_598 = 182
pyarmor_core_599 = 183
pyarmor_core_600 = 241
pyarmor_core_601 = bytes([pyarmor_core_535])
pyarmor_core_602 = bytes([pyarmor_core_570])
pyarmor_core_603 = bytes([pyarmor_core_579])
pyarmor_core_604 = bytes([pyarmor_core_580])
pyarmor_core_605 = bytes([pyarmor_core_566])
pyarmor_core_606 = bytes([pyarmor_core_551])
pyarmor_core_607 = bytes([pyarmor_core_549])
pyarmor_core_608 = bytes([pyarmor_core_550])
pyarmor_core_609 = bytes([pyarmor_core_557])
pyarmor_core_610 = bytes([pyarmor_core_559])
pyarmor_core_611 = bytes([pyarmor_core_555])
pyarmor_core_612 = bytes([pyarmor_core_553])
pyarmor_core_613 = bytes([pyarmor_core_571])
pyarmor_core_614 = bytes([pyarmor_core_538])
pyarmor_core_615 = bytes([pyarmor_core_582])
pyarmor_core_616 = bytes([pyarmor_core_539])
pyarmor_core_617 = bytes([pyarmor_core_577])
pyarmor_core_618 = bytes([pyarmor_core_594])
pyarmor_core_619 = 0
pyarmor_core_620 = 1
pyarmor_core_621 = 2
pyarmor_core_622 = 3
pyarmor_core_623 = 4
pyarmor_core_624 = 5
pyarmor_core_625 = 6
pyarmor_core_626 = 7
pyarmor_core_627 = 8
pyarmor_core_628 = 9
pyarmor_core_629 = 10
pyarmor_core_630 = 11
pyarmor_core_631 = 7
pyarmor_core_632 = 8
pyarmor_core_633 = 9
pyarmor_core_634 = 10
pyarmor_core_635 = 11
pyarmor_core_636 = 12
pyarmor_core_637 = 13
pyarmor_core_638 = 14
pyarmor_core_639 = 15
pyarmor_core_640 = 16
pyarmor_core_641 = 17
pyarmor_core_642 = 18
pyarmor_core_643 = 19
pyarmor_core_644 = 20
pyarmor_core_645 = 21
pyarmor_core_646 = 22
pyarmor_core_647 = 23
pyarmor_core_648 = 24
pyarmor_core_649 = 25
pyarmor_core_650 = 26
pyarmor_core_651 = 27
pyarmor_core_652 = 28
pyarmor_core_653 = 29
pyarmor_core_654 = 30
pyarmor_core_655 = 31
pyarmor_core_656 = 32
pyarmor_core_657 = 33
pyarmor_core_658 = 34
pyarmor_core_659 = 35
pyarmor_core_660 = 36
pyarmor_core_661 = 37
pyarmor_core_662 = 38
pyarmor_core_663 = 75
pyarmor_core_664 = 76
pyarmor_core_665 = namedtuple('VmcStackItem', 'node, f_names, f_consts, f_localvars, f_freevars')
pyarmor_core_666 = namedtuple('VmcBlockItem', 'items, m_consts')
pyarmor_core_667 = namedtuple('VmcExprItem', 'item, m_consts')

class pyarmor_core_454(ast.NodeVisitor):
    """"""

    def __init__(pyarmor_core_22):
        pyarmor_core_22.co = None
        pyarmor_core_22.f_consts = None

    def build_vmcode(pyarmor_core_22, pyarmor_core_123, pyarmor_core_668):
        pyarmor_core_22.co = pyarmor_core_123
        pyarmor_core_22.f_consts = pyarmor_core_668.m_consts
        if isinstance(pyarmor_core_668, pyarmor_core_667):
            assert isinstance(pyarmor_core_668.item, ast.AST)
            return b''.join([pyarmor_core_604, pyarmor_core_22.visit(pyarmor_core_668.item)])
        assert isinstance(pyarmor_core_668, pyarmor_core_666)
        pyarmor_core_50 = pyarmor_core_668.items
        return b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_50]) + pyarmor_core_603

    def get_cell(pyarmor_core_22, pyarmor_core_102):
        """"""
        pyarmor_core_123 = pyarmor_core_22.co
        pyarmor_core_16 = pyarmor_core_123.co_nlocals
        if pyarmor_core_102 in pyarmor_core_123.co_cellvars:
            return pyarmor_core_16 + pyarmor_core_123.co_cellvars.index(pyarmor_core_102)
        if pyarmor_core_102 in pyarmor_core_123.co_freevars:
            pyarmor_core_16 += len(pyarmor_core_123.co_cellvars)
            return pyarmor_core_16 + pyarmor_core_123.co_freevars.index(pyarmor_core_102)

    def get_local(pyarmor_core_22, pyarmor_core_102):
        try:
            return pyarmor_core_22.co.co_varnames.index(pyarmor_core_102)
        except ValueError:
            pass

    def get_name_index(pyarmor_core_22, pyarmor_core_102):
        pyarmor_core_33 = pyarmor_core_22.get_cell(pyarmor_core_102)
        if pyarmor_core_33 is not None:
            return (2, pyarmor_core_33)
        pyarmor_core_33 = pyarmor_core_22.get_local(pyarmor_core_102)
        if pyarmor_core_33 is not None:
            return (0, pyarmor_core_33)
        assert pyarmor_core_102 in pyarmor_core_22.f_consts
        return (1, pyarmor_core_22.f_consts.index(pyarmor_core_102))

    def _load_name_ins(pyarmor_core_22, pyarmor_core_102):
        """"""
        (pyarmor_core_3, pyarmor_core_33) = pyarmor_core_22.get_name_index(pyarmor_core_102)
        pyarmor_core_669 = [pyarmor_core_545, pyarmor_core_543, pyarmor_core_546]
        return pyarmor_core_22._make_ins(pyarmor_core_669[pyarmor_core_3], pyarmor_core_33)

    def _store_name_ins(pyarmor_core_22, pyarmor_core_102):
        """"""
        (pyarmor_core_3, pyarmor_core_33) = pyarmor_core_22.get_name_index(pyarmor_core_102)
        pyarmor_core_669 = [pyarmor_core_573, pyarmor_core_572, pyarmor_core_575]
        return pyarmor_core_22._make_ins(pyarmor_core_669[pyarmor_core_3], pyarmor_core_33)

    def _delete_name_ins(pyarmor_core_22, pyarmor_core_102):
        """"""
        (pyarmor_core_3, pyarmor_core_33) = pyarmor_core_22.get_name_index(pyarmor_core_102)
        pyarmor_core_669 = [pyarmor_core_588, pyarmor_core_586, pyarmor_core_592]
        return pyarmor_core_22._make_ins(pyarmor_core_669[pyarmor_core_3], pyarmor_core_33)

    def get_returns(pyarmor_core_22, pyarmor_core_670):
        """"""
        pyarmor_core_33 = len(pyarmor_core_670)
        pyarmor_core_310 = pack('<BH', pyarmor_core_600, pyarmor_core_33)
        pyarmor_core_671 = b''.join([pack('<H', pyarmor_core_22.get_local(pyarmor_core_38)) for pyarmor_core_38 in pyarmor_core_670])
        return b''.join([pyarmor_core_310, pyarmor_core_671])

    def _make_ins(pyarmor_core_22, pyarmor_core_351, pyarmor_core_33):
        assert pyarmor_core_33 <= 4294967295, 'too big operand (%s)' % pyarmor_core_33
        return pack('BB', pyarmor_core_351, pyarmor_core_33) if pyarmor_core_33 < 256 else pack('<BBH', pyarmor_core_351 + 1, 0, pyarmor_core_33) if pyarmor_core_33 < 65535 else pack('<BBI', pyarmor_core_351 + 1, 1, pyarmor_core_33)

    def _make_jmp_ins(pyarmor_core_22, pyarmor_core_33):
        assert abs(pyarmor_core_33) <= 2147483647, 'too big jump offset (%s)' % pyarmor_core_33
        return pack('BB', pyarmor_core_581, pyarmor_core_33) if pyarmor_core_33 < 256 else pack('<BH', pyarmor_core_581 + 1, pyarmor_core_33) if pyarmor_core_33 < 65535 else pack('<BI', pyarmor_core_581 + 2, pyarmor_core_33)

    def _make_loop_ins(pyarmor_core_22, pyarmor_core_351, pyarmor_core_672, pyarmor_core_673):
        pyarmor_core_33 = max(pyarmor_core_672, pyarmor_core_673)
        assert pyarmor_core_33 <= 2147483647, 'too big loop size (%s)' % pyarmor_core_33
        return pack('BBB', pyarmor_core_351, pyarmor_core_672, pyarmor_core_673) if pyarmor_core_33 < 256 else pack('<BHH', pyarmor_core_351 + 1, pyarmor_core_672, pyarmor_core_673) if pyarmor_core_33 < 65535 else pack('<BII', pyarmor_core_351 + 2, pyarmor_core_672, pyarmor_core_673)

    def _make_store_target(pyarmor_core_22, pyarmor_core_88):
        """"""
        if isinstance(pyarmor_core_88, ast.Tuple):
            pyarmor_core_33 = len(pyarmor_core_88.elts)
            return pyarmor_core_22._make_ins(pyarmor_core_576, pyarmor_core_33) + b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_88.elts])
        else:
            return pyarmor_core_22.visit(pyarmor_core_88)

    def _make_arg(pyarmor_core_22, pyarmor_core_411):
        if pyarmor_core_411 is None:
            return pyarmor_core_601
        pyarmor_core_33 = pyarmor_core_22.f_consts.index(pyarmor_core_411)
        return pyarmor_core_22._make_ins(pyarmor_core_542, pyarmor_core_33)

    def visit_Name(pyarmor_core_22, pyarmor_core_226):
        if isinstance(pyarmor_core_226.ctx, ast.Load):
            return pyarmor_core_22._load_name_ins(pyarmor_core_226.id)
        elif isinstance(pyarmor_core_226.ctx, ast.Store):
            return pyarmor_core_22._store_name_ins(pyarmor_core_226.id)
        elif isinstance(pyarmor_core_226.ctx, ast.Del):
            return pyarmor_core_22._delete_name_ins(pyarmor_core_226.id)

    def visit_Constant(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_33 = pyarmor_core_22.f_consts.index(pyarmor_core_226.value)
        return pyarmor_core_22._make_ins(pyarmor_core_542, pyarmor_core_33)

    def visit_Call(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_430 = len(pyarmor_core_226.args)
        pyarmor_core_674 = len(pyarmor_core_226.keywords)
        pyarmor_core_675 = len([pyarmor_core_38 for pyarmor_core_38 in pyarmor_core_226.args if isinstance(pyarmor_core_38, ast.Starred)])
        pyarmor_core_676 = len([pyarmor_core_417 for pyarmor_core_417 in pyarmor_core_226.keywords if pyarmor_core_417.arg is None])
        pyarmor_core_235 = pyarmor_core_22.visit(pyarmor_core_226.func)
        if pyarmor_core_430 == 0 and pyarmor_core_674 == 0:
            return pack('BB', pyarmor_core_567, 0) + pyarmor_core_235
        if pyarmor_core_675 == 0 and pyarmor_core_676 == 0:
            if pyarmor_core_674 == 0:
                pyarmor_core_310 = pyarmor_core_22._make_ins(pyarmor_core_567, pyarmor_core_430)
                pyarmor_core_677 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.args])
                return b''.join([pyarmor_core_310, pyarmor_core_677, pyarmor_core_235])
            pyarmor_core_310 = pyarmor_core_22._make_ins(pyarmor_core_568, pyarmor_core_430)
            pyarmor_core_677 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.args])
            pyarmor_core_678 = b''.join([pyarmor_core_22._make_arg(pyarmor_core_38.arg) + pyarmor_core_22.visit(pyarmor_core_38.value) for pyarmor_core_38 in pyarmor_core_226.keywords])
            return b''.join([pyarmor_core_310, pyarmor_core_677, pyarmor_core_678, pyarmor_core_601, pyarmor_core_235])
        if pyarmor_core_430 == 1 and pyarmor_core_675 == 1:
            pyarmor_core_296 = pyarmor_core_22.visit(pyarmor_core_226.args[0].value)
            if pyarmor_core_674 == 1 and pyarmor_core_676 == 1:
                pyarmor_core_679 = pyarmor_core_22.visit(pyarmor_core_226.keywords[0].value)
                return b''.join([pyarmor_core_605, pyarmor_core_296, pyarmor_core_679, pyarmor_core_235])
            elif pyarmor_core_674 == 0:
                pyarmor_core_679 = pyarmor_core_601
                return b''.join([pyarmor_core_605, pyarmor_core_296, pyarmor_core_679, pyarmor_core_235])
        if pyarmor_core_674 == 1 and pyarmor_core_676 == 1 and (pyarmor_core_430 == 0):
            pyarmor_core_296 = pyarmor_core_601
            pyarmor_core_679 = pyarmor_core_22.visit(pyarmor_core_226.keywords[0].value)
            return b''.join([pyarmor_core_605, pyarmor_core_296, pyarmor_core_679, pyarmor_core_235])
        pyarmor_core_310 = pyarmor_core_22._make_ins(pyarmor_core_569, pyarmor_core_674)
        pyarmor_core_677 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.args])
        pyarmor_core_678 = b''.join([pyarmor_core_22._make_arg(pyarmor_core_38.arg) + pyarmor_core_22.visit(pyarmor_core_38.value) for pyarmor_core_38 in pyarmor_core_226.keywords])
        return b''.join([pyarmor_core_310, pyarmor_core_677, pyarmor_core_601, pyarmor_core_678, pyarmor_core_235])

    def visit_BoolOp(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_351 = pyarmor_core_540 if isinstance(pyarmor_core_226.op, ast.Or) else pyarmor_core_541
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.values])
        return b''.join([pyarmor_core_22._make_ins(pyarmor_core_351, len(pyarmor_core_227) + 1), pyarmor_core_227, pyarmor_core_601])

    def visit_UnaryOp(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_680 = {'Invert': pyarmor_core_651, 'UAdd': pyarmor_core_656, 'USub': pyarmor_core_654, 'Not': pyarmor_core_633}
        pyarmor_core_303 = type(pyarmor_core_226.op).__name__
        pyarmor_core_310 = [pack('BB', pyarmor_core_537, pyarmor_core_680[pyarmor_core_303])]
        pyarmor_core_310.append(pyarmor_core_22.visit(pyarmor_core_226.operand))
        return b''.join(pyarmor_core_310)

    def visit_BinOp(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_680 = {'Add': pyarmor_core_631, 'Sub': pyarmor_core_660, 'Mult': pyarmor_core_653, 'Div': pyarmor_core_661, 'Mod': pyarmor_core_634, 'FloorDiv': pyarmor_core_636, 'MatMult': pyarmor_core_663, 'Pow': pyarmor_core_657, 'LShift': pyarmor_core_652, 'RShift': pyarmor_core_659, 'BitOr': pyarmor_core_655, 'BitXor': pyarmor_core_662, 'BitAnd': pyarmor_core_632}
        pyarmor_core_303 = type(pyarmor_core_226.op).__name__
        pyarmor_core_310 = [pack('BB', pyarmor_core_538, pyarmor_core_680[pyarmor_core_303])]
        pyarmor_core_310.append(pyarmor_core_22.visit(pyarmor_core_226.left))
        pyarmor_core_310.append(pyarmor_core_22.visit(pyarmor_core_226.right))
        return b''.join(pyarmor_core_310)

    def visit_Compare(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_680 = {'Eq': bytes([pyarmor_core_621]), 'NotEq': bytes([pyarmor_core_622]), 'Lt': bytes([pyarmor_core_619]), 'LtE': bytes([pyarmor_core_620]), 'Gt': bytes([pyarmor_core_623]), 'GtE': bytes([pyarmor_core_624]), 'Is': bytes([pyarmor_core_627]), 'IsNot': bytes([pyarmor_core_628]), 'In': bytes([pyarmor_core_625]), 'NotIn': bytes([pyarmor_core_626])}
        pyarmor_core_681 = [pyarmor_core_22.visit(pyarmor_core_226.left)]
        for (pyarmor_core_682, pyarmor_core_683) in zip(pyarmor_core_226.ops, pyarmor_core_226.comparators):
            pyarmor_core_681.append(pyarmor_core_680[type(pyarmor_core_682).__name__])
            pyarmor_core_681.append(pyarmor_core_22.visit(pyarmor_core_683))
        pyarmor_core_681.append(pyarmor_core_602)
        pyarmor_core_227 = b''.join(pyarmor_core_681)
        return pyarmor_core_22._make_ins(pyarmor_core_539, len(pyarmor_core_227)) + pyarmor_core_227

    def visit_Starred(pyarmor_core_22, pyarmor_core_226):
        if isinstance(pyarmor_core_226.ctx, (ast.Store, ast.Load)):
            return pyarmor_core_606 + pyarmor_core_22.visit(pyarmor_core_226.value)
        raise NotImplementedError(ast.unparse(pyarmor_core_226))

    def visit_Attribute(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_220 = pyarmor_core_22.f_consts.index(pyarmor_core_226.attr)
        if isinstance(pyarmor_core_226.ctx, ast.Del):
            return pyarmor_core_22._make_ins(pyarmor_core_590, pyarmor_core_220)
        elif isinstance(pyarmor_core_226.ctx, ast.Store):
            return b''.join([pyarmor_core_22._make_ins(pyarmor_core_574, pyarmor_core_220), pyarmor_core_22.visit(pyarmor_core_226.value)])
        else:
            return b''.join([pyarmor_core_22._make_ins(pyarmor_core_547, pyarmor_core_220), pyarmor_core_22.visit(pyarmor_core_226.value)])

    def visit_Slice(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_310 = [pyarmor_core_607]
        for pyarmor_core_233 in ('lower', 'upper', 'step'):
            pyarmor_core_295 = getattr(pyarmor_core_226, pyarmor_core_233, None)
            pyarmor_core_310.append(pyarmor_core_601 if pyarmor_core_295 is None else pyarmor_core_22.visit(pyarmor_core_295))
        return b''.join(pyarmor_core_310)

    def visit_Subscript(pyarmor_core_22, pyarmor_core_226):
        return b''.join([pyarmor_core_608 if isinstance(pyarmor_core_226.ctx, ast.Load) else pyarmor_core_617 if isinstance(pyarmor_core_226.ctx, ast.Store) else pyarmor_core_618, pyarmor_core_22.visit(pyarmor_core_226.slice), pyarmor_core_22.visit(pyarmor_core_226.value)])

    def visit_IfExp(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_684 = pyarmor_core_22.visit(pyarmor_core_226.test)
        pyarmor_core_227 = pyarmor_core_22.visit(pyarmor_core_226.body)
        pyarmor_core_685 = pyarmor_core_22.visit(pyarmor_core_226.orelse)
        pyarmor_core_686 = pyarmor_core_22._make_jmp_ins(len(pyarmor_core_685))
        pyarmor_core_16 = len(pyarmor_core_227) + len(pyarmor_core_686)
        pyarmor_core_310 = pyarmor_core_22._make_ins(pyarmor_core_564, pyarmor_core_16)
        return b''.join([pyarmor_core_310, pyarmor_core_684, pyarmor_core_227, pyarmor_core_686, pyarmor_core_685])

    def visit_Dict(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_687 = [pyarmor_core_22.visit(pyarmor_core_38) if pyarmor_core_38 else pyarmor_core_601 for pyarmor_core_38 in pyarmor_core_226.keys]
        pyarmor_core_688 = [pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.values]
        pyarmor_core_227 = b''.join([pyarmor_core_417 + pyarmor_core_295 for (pyarmor_core_417, pyarmor_core_295) in zip(pyarmor_core_687, pyarmor_core_688)])
        return b''.join([pyarmor_core_609, pyarmor_core_227, pyarmor_core_601, pyarmor_core_601] if any([pyarmor_core_38 is None for pyarmor_core_38 in pyarmor_core_226.keys]) else [pyarmor_core_22._make_ins(pyarmor_core_556, len(pyarmor_core_226.keys)), pyarmor_core_227])

    def visit_Set(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.elts])
        return b''.join([pyarmor_core_610, pyarmor_core_227, pyarmor_core_601] if any([isinstance(pyarmor_core_38, ast.Starred) for pyarmor_core_38 in pyarmor_core_226.elts]) else [pyarmor_core_22._make_ins(pyarmor_core_558, len(pyarmor_core_226.elts)), pyarmor_core_227])

    def visit_List(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.elts])
        return b''.join([pyarmor_core_611, pyarmor_core_227, pyarmor_core_601] if any([isinstance(pyarmor_core_38, ast.Starred) for pyarmor_core_38 in pyarmor_core_226.elts]) else [pyarmor_core_22._make_ins(pyarmor_core_554, len(pyarmor_core_226.elts)), pyarmor_core_227])

    def visit_Tuple(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.elts])
        return b''.join([pyarmor_core_612, pyarmor_core_227, pyarmor_core_601] if any([isinstance(pyarmor_core_38, ast.Starred) for pyarmor_core_38 in pyarmor_core_226.elts]) else [pyarmor_core_22._make_ins(pyarmor_core_552, len(pyarmor_core_226.elts)), pyarmor_core_227])

    def visit_comprehension(pyarmor_core_22, pyarmor_core_689):
        assert not pyarmor_core_689.is_async
        pyarmor_core_690 = pyarmor_core_689.ifs
        if pyarmor_core_690:
            pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_690])
            pyarmor_core_684 = b''.join([pyarmor_core_22._make_ins(pyarmor_core_541, len(pyarmor_core_227) + 1), pyarmor_core_227, pyarmor_core_601]) if len(pyarmor_core_690) > 1 else pyarmor_core_227
        else:
            pyarmor_core_684 = pyarmor_core_602
        return b''.join([pyarmor_core_22.visit(pyarmor_core_689.iter), pyarmor_core_22._make_store_target(pyarmor_core_689.target), pyarmor_core_684])

    def _build_xxxxcomp(pyarmor_core_22, pyarmor_core_226, pyarmor_core_691):
        pyarmor_core_692 = b''.join([pyarmor_core_22.visit_comprehension(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.generators])
        if any([pyarmor_core_38.ifs for pyarmor_core_38 in pyarmor_core_226.generators]):
            pyarmor_core_227 = b''.join([pyarmor_core_692, pyarmor_core_601, pyarmor_core_22.visit(pyarmor_core_226.elt)])
            return b''.join([pyarmor_core_22._make_ins(pyarmor_core_691, len(pyarmor_core_227)), pyarmor_core_227])
        return b''.join([pyarmor_core_22._make_ins(pyarmor_core_691, 0), pyarmor_core_692, pyarmor_core_601, pyarmor_core_22.visit(pyarmor_core_226.elt)])

    def visit_ListComp(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22._build_xxxxcomp(pyarmor_core_226, pyarmor_core_560)

    def visit_SetComp(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22._build_xxxxcomp(pyarmor_core_226, pyarmor_core_562)

    def visit_DictComp(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_692 = b''.join([pyarmor_core_22.visit_comprehension(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.generators])
        if any([pyarmor_core_38.ifs for pyarmor_core_38 in pyarmor_core_226.generators]):
            pyarmor_core_227 = b''.join([pyarmor_core_692, pyarmor_core_601, pyarmor_core_22.visit(pyarmor_core_226.key), pyarmor_core_22.visit(pyarmor_core_226.value)])
            return b''.join([pyarmor_core_22._make_ins(pyarmor_core_561, len(pyarmor_core_227)), pyarmor_core_227])
        return b''.join([pyarmor_core_22._make_ins(pyarmor_core_561, 0), pyarmor_core_692, pyarmor_core_601, pyarmor_core_22.visit(pyarmor_core_226.key), pyarmor_core_22.visit(pyarmor_core_226.value)])

    def visit_GeneratorExp(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22._build_xxxxcomp(pyarmor_core_226, pyarmor_core_563)

    def visit_JoinedStr(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_310 = [pyarmor_core_22._make_ins(pyarmor_core_565, len(pyarmor_core_226.values))]
        pyarmor_core_310.extend([b''.join([pyarmor_core_22.visit(pyarmor_core_38), b'\x00']) if isinstance(pyarmor_core_38, ast.Constant) else pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.values])
        return b''.join(pyarmor_core_310)

    def visit_FormattedValue(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_693 = pyarmor_core_226.conversion
        pyarmor_core_694 = pyarmor_core_226.format_spec
        return b''.join([pyarmor_core_22.visit(pyarmor_core_226.value), b'\xff' if pyarmor_core_693 == -1 else pack('B', pyarmor_core_693), pyarmor_core_22.visit(pyarmor_core_694) if pyarmor_core_694 else pyarmor_core_601])

    def visit_TemplateStr(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_JoinedStr(pyarmor_core_226)

    def visit_Interpolation(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_FormattedValue(pyarmor_core_226)

    def visit_Assign(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_44 = pyarmor_core_22.visit(pyarmor_core_226.value)
        pyarmor_core_695 = b''.join([pyarmor_core_22._make_store_target(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.targets])
        return b''.join([pyarmor_core_613, pyarmor_core_44, pyarmor_core_695, pyarmor_core_601])

    def visit_AugAssign(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_680 = {'Add': bytes([pyarmor_core_638]), 'Sub': bytes([pyarmor_core_647]), 'Mult': bytes([pyarmor_core_642]), 'Div': bytes([pyarmor_core_648]), 'Mod': bytes([pyarmor_core_645]), 'FloorDiv': bytes([pyarmor_core_640]), 'MatMult': bytes([pyarmor_core_664]), 'Pow': bytes([pyarmor_core_644]), 'LShift': bytes([pyarmor_core_641]), 'RShift': bytes([pyarmor_core_646]), 'BitOr': bytes([pyarmor_core_643]), 'BitXor': bytes([pyarmor_core_649]), 'BitAnd': bytes([pyarmor_core_639])}
        pyarmor_core_696 = pyarmor_core_22.visit(pyarmor_core_226.value)
        pyarmor_core_226.target.ctx = ast.Load()
        pyarmor_core_697 = pyarmor_core_22.visit(pyarmor_core_226.target)
        pyarmor_core_226.target.ctx = ast.Store()
        pyarmor_core_88 = pyarmor_core_22.visit(pyarmor_core_226.target)
        pyarmor_core_303 = type(pyarmor_core_226.op).__name__
        return b''.join([pyarmor_core_613, pyarmor_core_614, pyarmor_core_680[pyarmor_core_303], pyarmor_core_697, pyarmor_core_696, pyarmor_core_88, pyarmor_core_601])

    def visit_AnnAssign(pyarmor_core_22, pyarmor_core_226):
        if pyarmor_core_226.value is None:
            return b''
        pyarmor_core_44 = pyarmor_core_22.visit(pyarmor_core_226.value)
        pyarmor_core_88 = pyarmor_core_22.visit(pyarmor_core_226.target)
        return b''.join([pyarmor_core_613, pyarmor_core_44, pyarmor_core_88, pyarmor_core_601])

    def visit_NamedExpr(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_44 = pyarmor_core_22.visit(pyarmor_core_226.value)
        pyarmor_core_88 = pyarmor_core_22.visit(pyarmor_core_226.target)
        return b''.join([pyarmor_core_613, pyarmor_core_44, pyarmor_core_88, pyarmor_core_601])

    def visit_Expr(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit(pyarmor_core_226.value)

    def visit_If(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_684 = pyarmor_core_22.visit(pyarmor_core_226.test)
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.body])
        if pyarmor_core_226.orelse:
            pyarmor_core_685 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.orelse])
            pyarmor_core_686 = pyarmor_core_22._make_jmp_ins(len(pyarmor_core_685))
        else:
            (pyarmor_core_686, pyarmor_core_685) = (b'', b'')
        pyarmor_core_698 = pyarmor_core_22._make_jmp_ins(len(pyarmor_core_227) + len(pyarmor_core_686))
        return b''.join([pyarmor_core_615, pyarmor_core_684, pyarmor_core_698, pyarmor_core_227, pyarmor_core_686, pyarmor_core_685])

    def visit_For(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_699 = pyarmor_core_22._make_store_target(pyarmor_core_226.target)
        pyarmor_core_700 = pyarmor_core_22.visit(pyarmor_core_226.iter)
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.body])
        pyarmor_core_685 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.orelse]) if pyarmor_core_226.orelse else b''
        pyarmor_core_10 = bytes([pyarmor_core_585, 1])
        pyarmor_core_701 = len(pyarmor_core_699) + len(pyarmor_core_227) + len(pyarmor_core_10)
        pyarmor_core_702 = len(pyarmor_core_685)
        return b''.join([pyarmor_core_22._make_loop_ins(pyarmor_core_583, pyarmor_core_701, pyarmor_core_702), pyarmor_core_700, pyarmor_core_699, pyarmor_core_227, pyarmor_core_10, pyarmor_core_685])

    def visit_While(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_684 = pyarmor_core_22.visit(pyarmor_core_226.test)
        pyarmor_core_227 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.body])
        pyarmor_core_10 = bytes([pyarmor_core_585, 1])
        pyarmor_core_685 = b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.orelse]) if pyarmor_core_226.orelse else b''
        pyarmor_core_701 = len(pyarmor_core_684) + len(pyarmor_core_227) + len(pyarmor_core_10)
        pyarmor_core_702 = len(pyarmor_core_685)
        return b''.join([pyarmor_core_22._make_loop_ins(pyarmor_core_584, pyarmor_core_701, pyarmor_core_702), pyarmor_core_684, pyarmor_core_227, pyarmor_core_10, pyarmor_core_685])

    def visit_Break(pyarmor_core_22, pyarmor_core_226):
        return pack('BB', pyarmor_core_585, 255)

    def visit_Continue(pyarmor_core_22, pyarmor_core_226):
        return pack('BB', pyarmor_core_585, 1)

    def visit_Pass(pyarmor_core_22, pyarmor_core_226):
        return b''

    def visit_Delete(pyarmor_core_22, pyarmor_core_226):
        return b''.join([pyarmor_core_22.visit(pyarmor_core_38) for pyarmor_core_38 in pyarmor_core_226.targets])

    def visit_Raise(pyarmor_core_22, pyarmor_core_226):
        raise NotImplementedError(ast.unparse(pyarmor_core_226))

    def visit_Try(pyarmor_core_22, pyarmor_core_226):
        raise NotImplementedError(ast.unparse(pyarmor_core_226))

    def visit_With(pyarmor_core_22, pyarmor_core_226):
        raise NotImplementedError(ast.unparse(pyarmor_core_226))

    def visit_Return(pyarmor_core_22, pyarmor_core_226):
        raise NotImplementedError(ast.unparse(pyarmor_core_226))

    def visit_TypeAlias(pyarmor_core_22, pyarmor_core_226):
        return b''

    def visit_Assert(pyarmor_core_22, pyarmor_core_226):
        return b''

class pyarmor_core_703(ast.NodeVisitor):
    """"""

    def __init__(pyarmor_core_22):
        pyarmor_core_22.names = set()
        pyarmor_core_22.ext_globals = set()
        pyarmor_core_22.non_locals = set()

    def _clear(pyarmor_core_22):
        pyarmor_core_22.names.clear()
        pyarmor_core_22.ext_globals.clear()
        pyarmor_core_22.non_locals.clear()

    def get_globals(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_22._clear()
        pyarmor_core_22.visit(pyarmor_core_226)
        return pyarmor_core_22.names

    def get_names(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_22._clear()
        pyarmor_core_200 = pyarmor_core_226.args
        for pyarmor_core_38 in pyarmor_core_200.posonlyargs + pyarmor_core_200.args + pyarmor_core_200.kwonlyargs:
            pyarmor_core_22.names.add(pyarmor_core_38.arg)
        if pyarmor_core_200.vararg:
            pyarmor_core_22.names.add(pyarmor_core_200.vararg.arg)
        if pyarmor_core_200.kwarg:
            pyarmor_core_22.names.add(pyarmor_core_200.kwarg.arg)
        for pyarmor_core_38 in pyarmor_core_226.body:
            pyarmor_core_22.visit(pyarmor_core_38)
        return pyarmor_core_22.names

    def visit_ClassDef(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.names.add(pyarmor_core_226.name)

    def visit_FunctionDef(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.names.add(pyarmor_core_226.name)

    def visit_AsyncFunctionDef(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.names.add(pyarmor_core_226.name)

    def visit_Name(pyarmor_core_22, pyarmor_core_226):
        if isinstance(pyarmor_core_226.ctx, ast.Store):
            pyarmor_core_22.names.add(pyarmor_core_226.id)

    def visit_Import(pyarmor_core_22, pyarmor_core_226):
        for pyarmor_core_38 in pyarmor_core_226.names:
            pyarmor_core_22.names.add(pyarmor_core_38.asname if pyarmor_core_38.asname else pyarmor_core_38.name)

    def visit_ImportFrom(pyarmor_core_22, pyarmor_core_226):
        for pyarmor_core_38 in pyarmor_core_226.names:
            pyarmor_core_22.names.add(pyarmor_core_38.asname if pyarmor_core_38.asname else pyarmor_core_38.name)

    def visit_Global(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.names.difference_update(pyarmor_core_226.names)
        pyarmor_core_22.ext_globals.update(pyarmor_core_226.names)

    def visit_Nonlocal(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.names.difference_update(pyarmor_core_226.names)
        pyarmor_core_22.non_locals.update(pyarmor_core_226.names)

class pyarmor_core_280(ast.NodeTransformer):
    ECC_VAR = '_pyarmor_ecc_var'
    ECC_CONSTS = ()
    (F_INIT_INDEX, F_VMM_INDEX) = (1, 2)
    F_BUILTINS = []
    F_NOT_NODES = (ast.ClassDef, ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith, ast.Return, ast.Yield, ast.YieldFrom, ast.Try, ast.With, ast.Raise, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)

    def __init__(pyarmor_core_22):
        pyarmor_core_22.counter = 0
        pyarmor_core_22.stack = []
        pyarmor_core_22.f_globals = []
        pyarmor_core_22.f_builtins = []
        pyarmor_core_22.f_blocks = {}
        pyarmor_core_22.not_node_types = pyarmor_core_22.F_NOT_NODES + tuple([getattr(ast, pyarmor_core_38) for pyarmor_core_38 in ('Match', 'TryStar') if hasattr(ast, pyarmor_core_38)])

    @property
    def f_consts(pyarmor_core_22):
        """"""
        if pyarmor_core_22.stack:
            return pyarmor_core_22.stack[-1].f_consts

    @property
    def f_names(pyarmor_core_22):
        """"""
        if pyarmor_core_22.stack:
            return pyarmor_core_22.stack[-1].f_names

    @property
    def f_localvars(pyarmor_core_22):
        """"""
        if pyarmor_core_22.stack:
            return pyarmor_core_22.stack[-1].f_localvars

    @property
    def f_freevars(pyarmor_core_22):
        """"""
        if pyarmor_core_22.stack:
            return pyarmor_core_22.stack[-1].f_freevars

    def push_const(pyarmor_core_22, pyarmor_core_44):
        if pyarmor_core_22.stack:
            pyarmor_core_704 = pyarmor_core_22.stack[-1].f_consts
            if pyarmor_core_44 not in pyarmor_core_704:
                pyarmor_core_704.append(pyarmor_core_44)

    def init_module(pyarmor_core_22, pyarmor_core_226):
        if not pyarmor_core_22.F_BUILTINS:
            import builtins
            pyarmor_core_22.F_BUILTINS = dir(builtins)
        pyarmor_core_22.f_builtins.extend(pyarmor_core_22.F_BUILTINS)
        pyarmor_core_22.f_globals.extend(pyarmor_core_703().get_globals(pyarmor_core_226))

    def init_func(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_22.f_names[:] = pyarmor_core_703().get_names(pyarmor_core_226)

    def enter_scope(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.stack.append(pyarmor_core_665(pyarmor_core_226, f_names=[], f_consts=[], f_localvars=set(), f_freevars=set()))

    def exit_scope(pyarmor_core_22):
        pyarmor_core_22.stack.pop()

    def is_localvar(pyarmor_core_22, pyarmor_core_102):
        if pyarmor_core_22.stack:
            return pyarmor_core_102 in pyarmor_core_22.stack[-1].f_names

    def is_freevar(pyarmor_core_22, pyarmor_core_102):
        """"""
        for pyarmor_core_177 in reversed(pyarmor_core_22.stack[:-1]):
            if pyarmor_core_102 in pyarmor_core_177.f_names:
                return True

    def is_global(pyarmor_core_22, pyarmor_core_38):
        return not (pyarmor_core_22.is_localvar(pyarmor_core_38) or pyarmor_core_22.is_freevar(pyarmor_core_38))

    def is_builtin(pyarmor_core_22, pyarmor_core_38):
        return pyarmor_core_38 not in pyarmor_core_22.f_globals and pyarmor_core_38 in pyarmor_core_22.f_builtins

    def _get_module_start(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_9 = False if ast.get_docstring(pyarmor_core_226) else 0
        for pyarmor_core_705 in iter(pyarmor_core_226.body):
            if pyarmor_core_9 is False:
                pyarmor_core_9 = 1
            elif isinstance(pyarmor_core_705, ast.ImportFrom) and pyarmor_core_705.module == '__future__':
                pyarmor_core_9 += 1
            else:
                break
        return pyarmor_core_9

    def has_difficult_node(pyarmor_core_22, pyarmor_core_226):
        """"""
        for pyarmor_core_38 in ast.walk(pyarmor_core_226):
            if isinstance(pyarmor_core_38, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return getattr(pyarmor_core_38.generators[0], 'is_async', 0)
            if isinstance(pyarmor_core_38, pyarmor_core_22.not_node_types):
                return True

    def map_block(pyarmor_core_22, pyarmor_core_706, stmt=True):
        """"""
        pyarmor_core_22.counter += 1
        pyarmor_core_707 = '__pyarmor_ecc_code_block_%d__' % pyarmor_core_22.counter
        for pyarmor_core_705 in pyarmor_core_706:
            for pyarmor_core_38 in ast.walk(pyarmor_core_705):
                if isinstance(pyarmor_core_38, ast.Constant):
                    pyarmor_core_22.push_const(pyarmor_core_38.value)
                elif isinstance(pyarmor_core_38, ast.Attribute):
                    pyarmor_core_22.push_const(pyarmor_core_38.attr)
                elif isinstance(pyarmor_core_38, ast.Name):
                    if pyarmor_core_22.is_freevar(pyarmor_core_38.id):
                        pyarmor_core_22.f_freevars.add(pyarmor_core_38.id)
                    elif pyarmor_core_22.is_global(pyarmor_core_38.id):
                        pyarmor_core_22.push_const(pyarmor_core_38.id)
                    elif isinstance(pyarmor_core_38.ctx, ast.Store):
                        pyarmor_core_22.f_localvars.add(pyarmor_core_38.id)
                elif isinstance(pyarmor_core_38, ast.keyword):
                    if pyarmor_core_38.arg:
                        pyarmor_core_22.push_const(pyarmor_core_38.arg)
        pyarmor_core_22.f_blocks[pyarmor_core_707] = pyarmor_core_666(pyarmor_core_706, pyarmor_core_22.f_consts) if stmt else pyarmor_core_667(pyarmor_core_706[0], pyarmor_core_22.f_consts)
        pyarmor_core_708 = ast.Call(func=ast.Subscript(value=ast.Constant(value=pyarmor_core_22.ECC_CONSTS), slice=ast.Constant(value=pyarmor_core_22.F_VMM_INDEX), ctx=ast.Load()), args=[ast.Tuple(elts=[ast.Name(id=pyarmor_core_22.ECC_VAR, ctx=ast.Load()), ast.Constant(value=pyarmor_core_707)], ctx=ast.Load())], keywords=[])
        return ast.Expr(value=pyarmor_core_708) if stmt else pyarmor_core_708

    def fix_header(pyarmor_core_22, pyarmor_core_226, pyarmor_core_9):
        """"""
        pyarmor_core_200 = tuple(pyarmor_core_22.f_consts) if pyarmor_core_22.f_consts else None
        pyarmor_core_709 = [ast.Assign(targets=[ast.Name(id=pyarmor_core_22.ECC_VAR, ctx=ast.Store())], value=ast.Call(func=ast.Subscript(value=ast.Constant(value=pyarmor_core_22.ECC_CONSTS), slice=ast.Constant(value=pyarmor_core_22.F_INIT_INDEX), ctx=ast.Load()), args=[ast.Constant(value=pyarmor_core_200)], keywords=[]))]
        if pyarmor_core_22.f_freevars or pyarmor_core_22.f_localvars:
            pyarmor_core_710 = ast.Tuple(elts=[ast.Name(id=pyarmor_core_38, ctx=ast.Load()) for pyarmor_core_38 in pyarmor_core_22.f_freevars], ctx=ast.Load()) if pyarmor_core_22.f_freevars else ast.List(elts=[], ctx=ast.Load())
            pyarmor_core_711 = ast.Tuple(elts=[ast.Name(id=pyarmor_core_38, ctx=ast.Store()) for pyarmor_core_38 in pyarmor_core_22.f_localvars], ctx=ast.Store()) if pyarmor_core_22.f_localvars else ast.Name(id=pyarmor_core_22.ECC_VAR, ctx=ast.Store())
            pyarmor_core_709.append(ast.If(test=ast.UnaryOp(op=ast.Not(), operand=ast.Name(id=pyarmor_core_22.ECC_VAR, ctx=ast.Load())), body=[ast.Assign(targets=[pyarmor_core_711], value=pyarmor_core_710)], orelse=[]))
        pyarmor_core_226.body[pyarmor_core_9:pyarmor_core_9] = pyarmor_core_709

    def visit_ClassDef(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.enter_scope(pyarmor_core_226)
        pyarmor_core_712 = (ast.FunctionDef, ast.ClassDef)
        pyarmor_core_226.body = [pyarmor_core_22.visit(pyarmor_core_705) if isinstance(pyarmor_core_705, pyarmor_core_712) else pyarmor_core_705 for pyarmor_core_705 in iter(pyarmor_core_226.body)]
        pyarmor_core_22.exit_scope()
        return pyarmor_core_226

    def _handle_body(pyarmor_core_22, pyarmor_core_709, start=0):
        assert isinstance(pyarmor_core_709, list)
        pyarmor_core_713 = iter(pyarmor_core_709)
        pyarmor_core_227 = [next(pyarmor_core_713) for pyarmor_core_3 in range(start)]
        pyarmor_core_706 = []
        for pyarmor_core_705 in pyarmor_core_713:
            if pyarmor_core_22.has_difficult_node(pyarmor_core_705):
                if pyarmor_core_706:
                    pyarmor_core_227.append(pyarmor_core_22.map_block(pyarmor_core_706))
                    pyarmor_core_706 = []
                pyarmor_core_227.append(pyarmor_core_22.visit(pyarmor_core_705))
            else:
                pyarmor_core_706.append(pyarmor_core_705)
        if pyarmor_core_706:
            pyarmor_core_227.append(pyarmor_core_22.map_block(pyarmor_core_706))
        return pyarmor_core_227

    def _handle_expr(pyarmor_core_22, pyarmor_core_226):
        return None if pyarmor_core_226 is None else pyarmor_core_226 if pyarmor_core_22.has_difficult_node(pyarmor_core_226) else pyarmor_core_22.map_block([pyarmor_core_226], stmt=False)

    def visit_Module(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.init_module(pyarmor_core_226)
        pyarmor_core_22.enter_scope(pyarmor_core_226)
        pyarmor_core_9 = pyarmor_core_22._get_module_start(pyarmor_core_226)
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body, pyarmor_core_9)
        pyarmor_core_22.fix_header(pyarmor_core_226, pyarmor_core_9)
        pyarmor_core_22.exit_scope()
        return pyarmor_core_226

    def visit_FunctionDef(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_22.enter_scope(pyarmor_core_226)
        pyarmor_core_22.init_func(pyarmor_core_226)
        pyarmor_core_9 = 1 if ast.get_docstring(pyarmor_core_226) else 0
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body, pyarmor_core_9)
        pyarmor_core_22.fix_header(pyarmor_core_226, pyarmor_core_9)
        pyarmor_core_22.exit_scope()
        return pyarmor_core_226

    def visit_Constant(pyarmor_core_22, pyarmor_core_226):
        """"""
        pyarmor_core_44 = pyarmor_core_226.value
        if isinstance(pyarmor_core_44, tuple) and len(pyarmor_core_44) == 0:
            return ast.Call(func=ast.Name(id='tuple', ctx=ast.Load()), args=[ast.List(elts=[], ctx=ast.Load())], keywords=[])
        return pyarmor_core_226

    def visit_If(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_226.test = pyarmor_core_22._handle_expr(pyarmor_core_226.test)
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body)
        pyarmor_core_226.orelse = pyarmor_core_22._handle_body(pyarmor_core_226.orelse)
        return pyarmor_core_226

    def visit_Return(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_226.value = pyarmor_core_22._handle_expr(pyarmor_core_226.value)
        return pyarmor_core_226

    def visit_Try(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body)
        for pyarmor_core_714 in pyarmor_core_226.handlers:
            pyarmor_core_714.body = pyarmor_core_22._handle_body(pyarmor_core_714.body)
        pyarmor_core_226.orelse = pyarmor_core_22._handle_body(pyarmor_core_226.orelse)
        pyarmor_core_226.finalbody = pyarmor_core_22._handle_body(pyarmor_core_226.finalbody)
        return pyarmor_core_226

    def visit_TryStar(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_Try(pyarmor_core_226)

    def visit_With(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body)
        return pyarmor_core_226

    def visit_match_case(pyarmor_core_22, pyarmor_core_226):
        pyarmor_core_226.body = pyarmor_core_22._handle_body(pyarmor_core_226.body)
        return pyarmor_core_226

    def visit_AsyncFunctionDef(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_FunctionDef(pyarmor_core_226)

    def visit_AsyncFor(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_For(pyarmor_core_226)

    def visit_AsyncWith(pyarmor_core_22, pyarmor_core_226):
        return pyarmor_core_22.visit_With(pyarmor_core_226)
pyarmor_core_715 = Template('$shebang# Pyarmor VMC $rev, requires: pyarmor_mini >= 3.0\nfrom $pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, $body, 2)')

def pyarmor_core_716(pyarmor_core_278, **pyarmor_core_206):
    pyarmor_core_279 = pyarmor_core_280()
    pyarmor_core_279.visit(pyarmor_core_278)
    ast.fix_missing_locations(pyarmor_core_278)
    return pyarmor_core_279.f_blocks

def pyarmor_core_717(pyarmor_core_19, miver=1, head=32, cindex=0):
    pyarmor_core_325 = len(pyarmor_core_19)
    pyarmor_core_360 = head
    pyarmor_core_718 = 0
    pyarmor_core_64 = pack('<7sBBB6xIIII', b'PYARVMC', miver, *sys.version_info[:2], pyarmor_core_360, pyarmor_core_325, cindex, pyarmor_core_718)
    return pyarmor_core_64

def pyarmor_core_719(pyarmor_core_123, miver=1, head=32, cindex=0):
    pyarmor_core_720 = marshal_dumps(pyarmor_core_123)
    pyarmor_core_64 = pyarmor_core_717(pyarmor_core_720, miver, head, cindex)
    return pyarmor_core_64 + pyarmor_core_720

def pyarmor_core_721():
    try:
        from pyarmor.mini.pyarmor_mini import __pyarmor__ as builder
        return builder
    except ModuleNotFoundError:
        raise RuntimeError('please install pyarmor.mini package')

def pyarmor_core_722(pyarmor_core_123, pyarmor_core_449):
    pyarmor_core_723 = pyarmor_core_721()

    def pyarmor_core_724(*pyarmor_core_200):
        return pyarmor_core_723(pyarmor_core_200, b'', -1)
    pyarmor_core_450 = type(pyarmor_core_123)
    pyarmor_core_318 = (None, None, None, None)
    pyarmor_core_451 = pyarmor_core_280.ECC_CONSTS
    pyarmor_core_452 = '__pyarmor_ecc_code_block_'
    pyarmor_core_453 = pyarmor_core_454().build_vmcode

    def pyarmor_core_455(pyarmor_core_123):
        pyarmor_core_456 = list(pyarmor_core_123.co_consts)
        pyarmor_core_33 = 0
        for pyarmor_core_38 in pyarmor_core_123.co_consts:
            if isinstance(pyarmor_core_38, pyarmor_core_450):
                pyarmor_core_455(pyarmor_core_38)
            elif isinstance(pyarmor_core_38, str) and pyarmor_core_38.startswith(pyarmor_core_452):
                pyarmor_core_456[pyarmor_core_33] = pyarmor_core_453(pyarmor_core_123, pyarmor_core_449[pyarmor_core_38])
            elif pyarmor_core_38 is pyarmor_core_451:
                pyarmor_core_456[pyarmor_core_33] = pyarmor_core_318
            pyarmor_core_33 += 1
        pyarmor_core_724(pyarmor_core_123, pyarmor_core_123.co_consts, tuple(pyarmor_core_456))
    pyarmor_core_455(pyarmor_core_123)

def vmc_build(pyarmor_core_82, pyarmor_core_237, pyarmor_core_111, **pyarmor_core_206):
    pyarmor_core_725 = os.path.join(pyarmor_core_111, pyarmor_core_82)
    pyarmor_core_449 = pyarmor_core_716(pyarmor_core_237)
    if pyarmor_core_206.get('debug'):
        with open(pyarmor_core_725.replace('.py', '.rft.py'), 'w') as pyarmor_core_75:
            pyarmor_core_75.write(ast.unparse(pyarmor_core_237))
    pyarmor_core_726 = pyarmor_core_206.get('optimize', -1)
    pyarmor_core_727 = '<frozen %s>' % pyarmor_core_82
    pyarmor_core_123 = compile(pyarmor_core_237, pyarmor_core_727, 'exec', optimize=pyarmor_core_726)
    pyarmor_core_728 = pyarmor_core_123.co_consts.index(pyarmor_core_280.ECC_CONSTS)
    pyarmor_core_722(pyarmor_core_123, pyarmor_core_449)
    pyarmor_core_729 = pyarmor_core_206.get('rev', 1)
    pyarmor_core_227 = pyarmor_core_719(pyarmor_core_123, miver=pyarmor_core_729, cindex=pyarmor_core_728)
    os.makedirs(os.path.dirname(pyarmor_core_725), exist_ok=True)
    with open(pyarmor_core_725, 'w') as pyarmor_core_75:
        pyarmor_core_75.write(pyarmor_core_715.substitute(shebang=pyarmor_core_206.get('shebang', ''), pyarmor_mini=pyarmor_core_206.get('mini_import_from', 'pyarmor_mini'), rev=pyarmor_core_729, body=repr(pyarmor_core_227)))
import ast as pyarmmor__1
import dis as pyarmmor__2
import logging as pyarmmor__3
import logging.config
import os as pyarmmor__4
import marshal as pyarmmor__5
import struct as pyarmmor__6
import sys as pyarmmor__7
from string import Template as pyarmmor__8
pyarmmor__9 = pyarmmor__8('$shebang# Pyarmor MINI $rev, requires: pyarmor_mini >= 1.0\nfrom $pyarmor_mini import __pyarmor__\n__pyarmor__(__name__, $body)')
pyarmmor__10 = {'builtins': (b'\xb7S,?~\xfa\xbe\xa2\x97\xd0\xd5\xd9g\x04\xdcl', b'\x96\xaf\xd2\xfa\xcc\x97\xe3\x01\xceYQ\xbf\xb9\xc3\x98', b'\xd1\xb4\t\x0e\xb7Y\x83\xec\xa7\x04\xec\x95\x8cj\xfc'), 'keyiv': None}
pyarmmor__11 = logging.getLogger('cli.mini')

def pyarmmor__14(n=16):
    from random import randrange as pyarmmor__12
    return [pyarmmor__12(1, 255) for pyarmmor__13 in range(n)]

def pyarmmor__23(pyarmmor__15, miver=1, head=80, cindex=0):
    pyarmmor__16 = [len(pyarmmor__17) for pyarmmor__17 in pyarmmor__10['builtins']]
    pyarmmor__18 = len(pyarmmor__15)
    pyarmmor__19 = head + sum(pyarmmor__16)
    pyarmmor__20 = 0
    pyarmmor__21 = pyarmmor__10['keyiv']
    pyarmmor__22 = pyarmmor__6.pack('<7sBBBBBBBBBIIII48s', b'PYARMIN', miver, *pyarmmor__7.version_info[:2], head, head + pyarmmor__16[0], head + pyarmmor__16[0] + pyarmmor__16[1], *pyarmmor__16, pyarmmor__19, pyarmmor__18, cindex, pyarmmor__20, pyarmmor__21)
    return pyarmmor__22

def pyarmmor__26(pyarmmor__24, miver=1, head=80, cindex=0):
    pyarmmor__25 = pyarmmor__5.dumps(pyarmmor__24)
    pyarmmor__22 = pyarmmor__23(pyarmmor__25, miver, head, cindex)
    pyarmmor__11.debug('header size is %d', len(pyarmmor__22))
    return pyarmmor__22 + b''.join(pyarmmor__10['builtins']) + pyarmmor__25

def pyarmmor__37(pyarmmor__24, pyarmmor__27):
    pyarmmor__28 = type(pyarmmor__24)
    pyarmmor__29 = pyarmmor__2.opmap['LOAD_CONST']
    pyarmmor__30 = pyarmmor__2.opmap['BUILD_LIST']
    pyarmmor__31 = pyarmmor__2.opmap['NOP']

    def pyarmmor__36(pyarmmor__24):
        pyarmmor__32 = bytearray(pyarmmor__24.co_code)
        pyarmmor__33 = pyarmmor__2.get_instructions(pyarmmor__24)
        for pyarmmor__34 in pyarmmor__33:
            if pyarmmor__34.opcode == pyarmmor__29 and pyarmmor__34.argval == pyarmmor__27:
                for pyarmmor__34 in pyarmmor__33:
                    if pyarmmor__34.opcode == pyarmmor__30 and pyarmmor__34.arg == 1:
                        pyarmmor__35 = pyarmmor__34.offset
                        pyarmmor__32[pyarmmor__35:pyarmmor__35 + 2] = (pyarmmor__31, 0)
                        break
        [pyarmmor__36(pyarmmor__17) for pyarmmor__17 in pyarmmor__24.co_consts if isinstance(pyarmmor__17, pyarmmor__28)]
    pyarmmor__36(pyarmmor__24)

def pyarmmor__39():
    try:
        from pyarmor.mini.pyarmor_mini import __pyarmor__ as pyarmmor__38
        return pyarmmor__38
    except ModuleNotFoundError:
        raise RuntimeError('please install pyarmor.mini package')

def pyarmmor__41(pyarmmor__24, pyarmmor__40):
    pyarmmor__38 = pyarmmor__39()
    return pyarmmor__38((pyarmmor__24, pyarmmor__24.co_consts, pyarmmor__40), b'', -1)

def pyarmmor__45(pyarmmor__42, ptlen=16):
    pyarmmor__38 = pyarmmor__39()
    pyarmmor__22 = pyarmmor__23('')
    pyarmmor__15 = pyarmmor__42.encode('utf-8') if isinstance(pyarmmor__42, str) else pyarmmor__42
    pyarmmor__43 = len(pyarmmor__15) & ptlen - 1
    pyarmmor__43 = ptlen - pyarmmor__43 if pyarmmor__43 else 0
    pyarmmor__44 = bytes(pyarmmor__14(pyarmmor__43))
    return pyarmmor__38(bytes([pyarmmor__43]) + pyarmmor__15 + pyarmmor__44, pyarmmor__22, -2)

def pyarmmor__51(pyarmmor__24):
    import builtins as pyarmmor__46
    pyarmmor__47 = pyarmmor__2.opmap['LOAD_GLOBAL']
    pyarmmor__28 = type(pyarmmor__24)
    pyarmmor__48 = dir(pyarmmor__46)
    pyarmmor__49 = []

    def pyarmmor__50(pyarmmor__24):
        for pyarmmor__34 in pyarmmor__2.get_instructions(pyarmmor__24):
            if pyarmmor__34.opcode == pyarmmor__47:
                if pyarmmor__34.argval in pyarmmor__48:
                    pyarmmor__49.append(pyarmmor__34.argval)
        [pyarmmor__50(pyarmmor__17) for pyarmmor__17 in pyarmmor__24.co_consts if isinstance(pyarmmor__17, pyarmmor__28)]
    pyarmmor__50(pyarmmor__24)
    return set(pyarmmor__49)

def pyarmmor__83(pyarmmor__52, **pyarmmor__53):
    pyarmmor__24 = compile(pyarmmor__52, '<str>', 'exec')
    pyarmmor__54 = pyarmmor__53.get('mini_rft_builtin', 1)
    pyarmmor__55 = pyarmmor__53.get('mini_rft_setattr', 0)
    pyarmmor__56 = pyarmmor__53.get('mini_rft_getattr', 0)
    pyarmmor__57 = pyarmmor__53.get('mini_rft_import', 1)
    pyarmmor__58 = pyarmmor__53.get('mini_rft_str', 0)
    pyarmmor__59 = list(pyarmmor__51(pyarmmor__24)) if pyarmmor__54 else []
    pyarmmor__11.debug('got bulitins: %s', pyarmmor__59)
    pyarmmor__60 = tuple([pyarmmor__45(pyarmmor__17) for pyarmmor__17 in pyarmmor__59])
    pyarmmor__60 += pyarmmor__10['builtins']
    pyarmmor__61 = pyarmmor__1.List(elts=[pyarmmor__1.Constant(value=pyarmmor__60)], ctx=pyarmmor__1.Load())
    if not pyarmmor__53.get('advanced', None):
        pyarmmor__61 = pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=0), ctx=pyarmmor__1.Load())

    def pyarmmor__62(pyarmmor__17):
        return pyarmmor__17.id in pyarmmor__59 and isinstance(pyarmmor__17.ctx, pyarmmor__1.Load)

    class pyarmmor__82(pyarmmor__1.NodeTransformer):

        def visit_Name(self, node):
            if pyarmmor__62(node):
                pyarmmor__11.debug('line %d: reform builtin "%s"', node.lineno, node.id)
                pyarmmor__63 = pyarmmor__59.index(node.id)
                pyarmmor__64 = pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=node.ctx)
                pyarmmor__1.copy_location(pyarmmor__64, node)
                return pyarmmor__64
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str):
                if not pyarmmor__58:
                    return node
                pyarmmor__11.debug('line %d: protect str "%s"', node.lineno, node.value)
                pyarmmor__63 = len(pyarmmor__59)
                pyarmmor__65 = pyarmmor__45(node.value)
                pyarmmor__64 = pyarmmor__1.Call(func=pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=pyarmmor__1.Load()), args=[pyarmmor__1.Constant(value=pyarmmor__65)], keywords=[])
                pyarmmor__1.copy_location(pyarmmor__64, node)
                return pyarmmor__64
            elif isinstance(node.value, (int, float)):
                pass
            return node

        def visit_Attribute(self, node):
            if isinstance(node.ctx, pyarmmor__1.Store) or not pyarmmor__56:
                return node
            pyarmmor__11.debug('line %d: attr "%s"', node.lineno, node.attr)
            pyarmmor__63 = len(pyarmmor__59) + 1
            pyarmmor__66 = pyarmmor__45(node.attr)
            pyarmmor__67 = [node.value, pyarmmor__1.Constant(value=pyarmmor__66)]
            pyarmmor__64 = pyarmmor__1.Call(func=pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=pyarmmor__1.Load()), args=[pyarmmor__1.Tuple(elts=pyarmmor__67, ctx=pyarmmor__1.Load())], keywords=[])
            pyarmmor__1.copy_location(pyarmmor__64, node)
            return pyarmmor__64

        def visit_Assign(self, node):
            if not pyarmmor__55:
                return node
            if isinstance(node.targets[0], pyarmmor__1.Attribute):
                pyarmmor__63 = len(pyarmmor__59) + 1
                pyarmmor__68 = node.targets[0]
                pyarmmor__66 = pyarmmor__45(pyarmmor__68.attr)
                pyarmmor__67 = [pyarmmor__68.value, pyarmmor__1.Constant(value=pyarmmor__66), node.value]
                pyarmmor__64 = pyarmmor__1.Call(func=pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=pyarmmor__1.Load()), args=[pyarmmor__1.Tuple(elts=pyarmmor__67, ctx=pyarmmor__1.Load())], keywords=[])
                pyarmmor__1.copy_location(pyarmmor__64, node)
                return pyarmmor__64
            return node

        def visit_Import(self, node):
            if not pyarmmor__57:
                return node
            pyarmmor__69 = ', '.join([pyarmmor__17.name for pyarmmor__17 in node.names])
            pyarmmor__11.debug('line %d: import "%s"', node.lineno, pyarmmor__69)

            def pyarmmor__71(pyarmmor__70):
                pyarmmor__15 = b'\x01' + pyarmmor__70.encode('utf-8') + b'\x00\x00'
                return pyarmmor__45(pyarmmor__15)
            pyarmmor__63 = len(pyarmmor__59) + 2
            pyarmmor__72 = [pyarmmor__1.Call(func=pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=pyarmmor__1.Load()), args=[pyarmmor__1.Constant(value=pyarmmor__71(pyarmmor__17.name))], keywords=[]) for pyarmmor__17 in node.names]
            pyarmmor__73 = pyarmmor__1.Store()
            pyarmmor__74 = [pyarmmor__17.asname if pyarmmor__17.asname else pyarmmor__17.name for pyarmmor__17 in node.names]
            pyarmmor__75 = [pyarmmor__1.Name(id=pyarmmor__17, ctx=pyarmmor__73) for pyarmmor__17 in pyarmmor__74]
            pyarmmor__76 = len(pyarmmor__75) > 1
            if pyarmmor__76:
                pyarmmor__75 = [pyarmmor__1.Tuple(elts=pyarmmor__75, ctx=pyarmmor__73)]
                pyarmmor__72 = pyarmmor__1.Tuple(elts=pyarmmor__72, ctx=pyarmmor__1.Load())
            pyarmmor__64 = pyarmmor__1.Assign(targets=pyarmmor__75, value=pyarmmor__72 if pyarmmor__76 else pyarmmor__72[0])
            pyarmmor__1.copy_location(pyarmmor__64, node)
            return pyarmmor__64

        def visit_ImportFrom(self, node):
            if not pyarmmor__57:
                return node
            pyarmmor__11.debug('line %d: import from "%s"', node.lineno, node.module)
            pyarmmor__63 = len(pyarmmor__59) + 2
            pyarmmor__77 = len(node.names)
            pyarmmor__69 = [pyarmmor__17.name.encode('utf-8') for pyarmmor__17 in node.names]
            pyarmmor__78 = [bytes([len(pyarmmor__17)]) for pyarmmor__17 in pyarmmor__69]
            pyarmmor__79 = node.module if node.module else ''
            pyarmmor__15 = pyarmmor__6.pack('<BHH', 2, pyarmmor__77, node.level) + b''.join([pyarmmor__80 + pyarmmor__81 for (pyarmmor__80, pyarmmor__81) in zip(pyarmmor__78, pyarmmor__69)]) + pyarmmor__79.encode('utf-8') + bytes([0, 0])
            pyarmmor__73 = pyarmmor__1.Store()
            pyarmmor__74 = [pyarmmor__17.asname if pyarmmor__17.asname else pyarmmor__17.name for pyarmmor__17 in node.names]
            pyarmmor__75 = [pyarmmor__1.Name(id=pyarmmor__17, ctx=pyarmmor__73) for pyarmmor__17 in pyarmmor__74]
            pyarmmor__64 = pyarmmor__1.Assign(targets=[pyarmmor__1.Tuple(elts=pyarmmor__75, ctx=pyarmmor__73)], value=pyarmmor__1.Call(func=pyarmmor__1.Subscript(value=pyarmmor__61, slice=pyarmmor__1.Constant(value=pyarmmor__63), ctx=pyarmmor__1.Load()), args=[pyarmmor__1.Constant(value=pyarmmor__45(pyarmmor__15))], keywords=[]))
            pyarmmor__1.copy_location(pyarmmor__64, node)
            return pyarmmor__64
    pyarmmor__82().visit(pyarmmor__52)
    pyarmmor__1.fix_missing_locations(pyarmmor__52)
    return pyarmmor__60

def mini_build(filename, mtree, output, **pyarmmor__53):
    if pyarmmor__10['keyiv'] is None:
        pyarmmor__10['keyiv'] = bytes(pyarmmor__14(48))
    pyarmmor__84 = pyarmmor__4.path.join(output, filename)
    pyarmmor__60 = pyarmmor__83(mtree, **pyarmmor__53)
    if pyarmmor__53.get('debug'):
        with open(pyarmmor__84 + '.rft', 'w') as pyarmmor__85:
            pyarmmor__85.write(pyarmmor__1.unparse(mtree))
    pyarmmor__86 = pyarmmor__53.get('optimize', -1)
    pyarmmor__87 = '<frozen %s>' % filename
    pyarmmor__24 = compile(mtree, pyarmmor__87, 'exec', optimize=pyarmmor__86)
    if pyarmmor__60 not in pyarmmor__24.co_consts:
        pyarmmor__11.info('append builtins to co_consts')
        pyarmmor__88 = pyarmmor__24.co_consts + (pyarmmor__60,)
        if pyarmmor__41(pyarmmor__24, pyarmmor__88) is None:
            pyarmmor__11.error('patch co_consts failed')
            return
    pyarmmor__89 = pyarmmor__24.co_consts.index(pyarmmor__60)
    pyarmmor__11.debug('find cindex: %d', pyarmmor__89)
    pyarmmor__37(pyarmmor__24, pyarmmor__60)
    pyarmmor__90 = pyarmmor__53.get('rev', 1)
    pyarmmor__91 = pyarmmor__26(pyarmmor__24, miver=pyarmmor__90, cindex=pyarmmor__89)
    pyarmmor__11.info('save obfuscated script %s', pyarmmor__84)
    pyarmmor__4.makedirs(pyarmmor__4.path.dirname(pyarmmor__84), exist_ok=True)
    with open(pyarmmor__84, 'w') as pyarmmor__85:
        pyarmmor__85.write(pyarmmor__9.substitute(shebang=pyarmmor__53.get('shebang', ''), pyarmor_mini=pyarmmor__53.get('mini_import_from', 'pyarmor_mini'), rev=pyarmmor__90, body=repr(pyarmmor__91)))