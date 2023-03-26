# NCMdumper
# 解密ncm文件
import binascii
import struct
import base64
import json
import os
import requests
from Crypto.Cipher import AES


def dump(file_path):
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    def unpad(s): return s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    with open(file_path, 'rb') as f:
        header = f.read(8)
        assert binascii.b2a_hex(header) == b'4354454e4644414d'
        # 解密 key_data
        f.seek(2, 1)
        key_length = f.read(4)
        key_length = struct.unpack('<I', bytes(key_length))[0]
        key_data = f.read(key_length)
        key_data_array = bytearray(key_data)
        for i in range(0, len(key_data_array)):
            key_data_array[i] ^= 0x64
        key_data = bytes(key_data_array)
        cryptor = AES.new(core_key, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(key_data))[17:]
        key_length = len(key_data)
        key_data = bytearray(key_data)
        # 生成用于加密音频数据的 key_box
        key_box = bytearray(range(256))
        c = 0
        last_byte = 0
        key_offset = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last_byte + key_data[key_offset]) & 0xff
            key_offset += 1
            if key_offset >= key_length:
                key_offset = 0
            key_box[i] = key_box[c]
            key_box[c] = swap
            last_byte = c
        # 解密 meta_data
        meta_length = f.read(4)
        meta_length = struct.unpack('<I', bytes(meta_length))[0]
        meta_data = f.read(meta_length)
        meta_data_array = bytearray(meta_data)
        for i in range(0, len(meta_data_array)):
            meta_data_array[i] ^= 0x63
        meta_data = bytes(meta_data_array)
        meta_data = base64.b64decode(meta_data[22:])
        cryptor = AES.new(meta_key, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)
        crc32 = f.read(4)
        crc32 = struct.unpack('<I', bytes(crc32))[0]
        f.seek(5, 1)
        image_size = f.read(4)
        image_size = struct.unpack('<I', bytes(image_size))[0]
        image_data = f.read(image_size)
        artist_list = meta_data['artist']
        cover_url = meta_data['albumPic']
        artists = ' '.join([artist[0] for artist in artist_list])
        file_name = f"{meta_data['musicName']} - {artists}.{meta_data['format']}"
        file_dir = file_path.rsplit('\\', 1)[0]
        with open(f"{file_dir}\\{file_name}", 'wb') as m:
            chunk = bytearray()
            while True:
                chunk = bytearray(f.read(0x8000))
                chunk_length = len(chunk)
                if not chunk:
                    break
                for i in range(1, chunk_length + 1):
                    j = i & 0xff
                    chunk[i - 1] ^= key_box[(key_box[j] +
                                             key_box[(key_box[j] + j) & 0xff]) & 0xff]
            m.write(chunk)
        # 如果封面链接存在，则下载并保存封面图片
        if cover_url:
            response = requests.get(cover_url)
            file_dir = file_path.rsplit('\\', 1)[0]
            with open(f"{file_dir}\\{meta_data['musicName']} - {artists}.jpg", 'wb') as c:
                c.write(response.content)


def file_extension(path):
    return os.path.splitext(path)[1]


if __name__ == '__main__':
    file_path = input("请输入文件所在路径(例如：E:\\ncm_music)\n")
    files = [f for f in os.listdir(file_path) if f.endswith('.ncm')]
    total_files = len(files)
    processed_files = 0
    for filename in files:
        try:
            dump(os.path.join(file_path, filename))
            processed_files += 1
            print(f"Processed {processed_files}/{total_files}: {filename}")
        except Exception as e:
            print(f"Error processing {filename}: {e}")
    print("Decryption completed.")
