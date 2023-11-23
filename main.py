# -*- coding: utf-8 -*-
# @Time    : 2023-11-23
# @Author  : Mamiya Hasaki
from PyQt5 import QtCore
from PyQt5.QtCore import QByteArray

from doc_str import MY_DOC

import base64
import os
import secrets
import sys
import py7zr
import shutil
from datetime import datetime
from typing import Optional, List, Dict

from Crypto.Hash import SHA256
from PyQt5.QtGui import QIcon, QImage, QPixmap
from PyQt5.QtWidgets import (QWidget, QLabel, QLineEdit, QTextEdit, QGridLayout, QApplication, QPushButton, QMessageBox,
                             QMainWindow, QMenuBar, QMenu, QAction, QStatusBar)
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Cipher import AES


# 多重拖拽文本框
class MTextEdit(QTextEdit):
    def __init__(self, title, parent):
        super().__init__(title, parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):
        if e.mimeData().hasText():
            e.accept()
        else:
            e.ignore()

    def dropEvent(self, e):
        filePathList = e.mimeData().text()
        filePathList = filePathList.replace('file:///', '')
        self.setText(filePathList)


# 单行拖拽文本框
class STextEdit(QTextEdit):
    def __init__(self, title, parent):
        super().__init__(title, parent)
        self.setAcceptDrops(True)
        self.window = parent

    def dragEnterEvent(self, e):
        if e.mimeData().hasText():
            e.accept()
        else:
            e.ignore()

    def dropEvent(self, e):
        filePathList = e.mimeData().text()
        filePath = filePathList.split('\n')[0]
        filePath = filePath.replace('file:///', '')
        self.window.fileDecrypt7z(filePath)


class MyWindow(QMainWindow):
    # 0.1. 类内数据成员声明
    bar: QMenuBar
    bar_guide: QMenu
    bar_guide_intro: QAction

    status: QStatusBar

    widget: QWidget
    grid: QGridLayout

    prefix_label: QLabel
    prefix_edit: QLineEdit

    random_label: QLabel
    random_edit: QLineEdit
    random_button: QPushButton

    rsa_hint_label: QLabel
    rsa_hint_button: QPushButton

    rsa_raw_label: QLabel
    rsa_raw_edit: QTextEdit
    rsa_raw_button: QPushButton

    rsa_encrypt_label: QLabel
    rsa_encrypt_edit: QTextEdit
    rsa_encrypt_button: QPushButton

    aes_hint_label: QLabel
    aes_hint_button: QPushButton

    aes_key_label: QLabel
    aes_key_edit: QLineEdit
    aes_key_button: QPushButton

    aes_hash_label: QLabel
    aes_hash_edit: QLineEdit
    aes_hash_button: QPushButton

    aes_raw_label: QLabel
    aes_raw_edit: QTextEdit
    aes_raw_button: QPushButton

    aes_encrypt_label: QLabel
    aes_encrypt_edit: QTextEdit
    aes_encrypt_button: QPushButton

    file_hint_label: QLabel

    file_encrypt_label: QLabel
    file_encrypt_edit: MTextEdit
    file_encrypt_button: QPushButton

    file_decrypt_label: QLabel
    file_decrypt_edit: STextEdit

    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.initUI()

    # 0.3. 界面
    def initUI(self):
        # 整体界面定义
        self.setGeometry(100, 100, 1000, 600)

        author_icon_data = QByteArray().fromRawData(base64.b64decode(MY_DOC['author_icon'], b'-_'))
        author_icon = QImage()
        author_icon.loadFromData(author_icon_data, u'jpg')
        author_icon_pix = QPixmap.fromImage(author_icon)
        self.setWindowIcon(QIcon(author_icon_pix))

        self.setWindowTitle(MY_DOC[u'title'])

        # 1. 菜单栏定义
        self.bar = self.menuBar()
        # 1.1. 菜单栏-文件
        self.bar_guide = self.bar.addMenu(MY_DOC[u'bar_guide'])
        # 1.1.1. 导航页
        self.bar_guide_intro = QAction(MY_DOC[u'bar_guide_intro'], self)
        self.bar_guide_intro.triggered.connect(lambda: self.infoDisplay(MY_DOC[u'bar_guide_intro_content']))
        # 添加
        self.bar_guide.addAction(self.bar_guide_intro)

        # 2. 状态栏
        self.status = self.statusBar()

        # 3. 定义整体布局
        self.grid = QGridLayout()

        # row 1: col 0
        self.prefix_label = QLabel(MY_DOC[u'prefix_label'])
        # row 1: col [1, 2]
        self.prefix_edit = QLineEdit(MY_DOC[u'prefix_edit'])
        # add row 1
        self.grid.addWidget(self.prefix_label, 1, 0)
        self.grid.addWidget(self.prefix_edit, 1, 1, 1, 2)

        # row 2: col 0
        self.random_label = QLabel(MY_DOC[u'random_label'])
        # row 2: col 1
        self.random_edit = QLineEdit(MY_DOC[u'random_edit'])
        # row 2: col 2
        self.random_button = QPushButton(MY_DOC[u'random_button'])
        # add row 2
        self.grid.addWidget(self.random_label, 2, 0)
        self.grid.addWidget(self.random_edit, 2, 1)
        self.grid.addWidget(self.random_button, 2, 2)

        # row 3: col [0, 2]
        self.rsa_hint_label = QLabel(MY_DOC[u'rsa_hint_label'])
        self.rsa_hint_button = QPushButton(MY_DOC[u'rsa_hint_button'])
        self.grid.addWidget(self.rsa_hint_label, 3, 0, 1, 2)
        self.grid.addWidget(self.rsa_hint_button, 3, 2)

        # row 4: col 0
        self.rsa_raw_label = QLabel(MY_DOC[u'rsa_raw_label'])
        # row 4: col 1
        self.rsa_raw_edit = QTextEdit(MY_DOC[u'rsa_raw_edit'])
        self.rsa_raw_edit.setPlaceholderText(MY_DOC[u'rsa_raw_edit_placeholder'])
        # row 4 col 2
        self.rsa_raw_button = QPushButton(MY_DOC[u'rsa_raw_button'])
        # add row 4
        self.grid.addWidget(self.rsa_raw_label, 4, 0)
        self.grid.addWidget(self.rsa_raw_edit, 4, 1)
        self.grid.addWidget(self.rsa_raw_button, 4, 2)

        # row 5: col 0
        self.rsa_encrypt_label = QLabel(MY_DOC[u'rsa_encrypt_label'])
        # row 5: col 1
        self.rsa_encrypt_edit = QTextEdit(MY_DOC[u'rsa_encrypt_edit'])
        self.rsa_encrypt_edit.setPlaceholderText(MY_DOC[u'rsa_encrypt_edit_placeholder'])
        # row 5 col 2
        self.rsa_encrypt_button = QPushButton(MY_DOC[u'rsa_encrypt_button'])
        # add row 5
        self.grid.addWidget(self.rsa_encrypt_label, 5, 0)
        self.grid.addWidget(self.rsa_encrypt_edit, 5, 1)
        self.grid.addWidget(self.rsa_encrypt_button, 5, 2)

        # row 6: col [0, 2]
        self.aes_hint_label = QLabel(MY_DOC[u'aes_hint_label'])
        self.aes_hint_button = QPushButton(MY_DOC[u'aes_hint_button'])
        self.grid.addWidget(self.aes_hint_label, 6, 0, 1, 2)
        self.grid.addWidget(self.aes_hint_button, 6, 2)

        # row 7: col 0
        self.aes_key_label = QLabel(MY_DOC[u'aes_key_label'])
        # row 7: col 1
        self.aes_key_edit = QLineEdit(MY_DOC[u'aes_key_edit'])
        # row 7 col 2
        self.aes_key_button = QPushButton(MY_DOC[u'aes_key_button'])
        # add row 7
        self.grid.addWidget(self.aes_key_label, 7, 0)
        self.grid.addWidget(self.aes_key_edit, 7, 1)
        self.grid.addWidget(self.aes_key_button, 7, 2)

        # row 8: col 0
        self.aes_hash_label = QLabel(MY_DOC[u'aes_hash_label'])
        # row 8: col 1
        self.aes_hash_edit = QLineEdit(MY_DOC[u'aes_hash_edit'])
        # row 8 col 2
        self.aes_hash_button = QPushButton(MY_DOC[u'aes_hash_button'])
        # add row 8
        self.grid.addWidget(self.aes_hash_label, 8, 0)
        self.grid.addWidget(self.aes_hash_edit, 8, 1)
        self.grid.addWidget(self.aes_hash_button, 8, 2)

        # row 9: col 0
        self.aes_raw_label = QLabel(MY_DOC[u'aes_raw_label'])
        # row 9: col 1
        self.aes_raw_edit = QTextEdit(MY_DOC[u'aes_raw_edit'])
        self.aes_raw_edit.setPlaceholderText(MY_DOC[u'aes_raw_edit_placeholder'])
        # row 9 col 2
        self.aes_raw_button = QPushButton(MY_DOC[u'aes_raw_button'])
        # add row 9
        self.grid.addWidget(self.aes_raw_label, 9, 0)
        self.grid.addWidget(self.aes_raw_edit, 9, 1)
        self.grid.addWidget(self.aes_raw_button, 9, 2)

        # row 10: col 0
        self.aes_encrypt_label = QLabel(MY_DOC[u'aes_encrypt_label'])
        # row 10: col 1
        self.aes_encrypt_edit = QTextEdit(MY_DOC[u'aes_encrypt_edit'])
        self.aes_encrypt_edit.setPlaceholderText(MY_DOC[u'aes_encrypt_edit_placeholder'])
        # row 10 col 2
        self.aes_encrypt_button = QPushButton(MY_DOC[u'aes_encrypt_button'])
        # add row 10
        self.grid.addWidget(self.aes_encrypt_label, 10, 0)
        self.grid.addWidget(self.aes_encrypt_edit, 10, 1)
        self.grid.addWidget(self.aes_encrypt_button, 10, 2)

        # row 11: col [0, 2]
        self.file_hint_label = QLabel(MY_DOC[u'file_hint_label'])
        self.grid.addWidget(self.file_hint_label, 11, 0, 1, 3)

        # row 12: col 0
        self.file_encrypt_label = QLabel(MY_DOC[u'file_encrypt_label'], self)
        # row 12: col 1
        self.file_encrypt_edit = MTextEdit(MY_DOC[u'file_encrypt_edit'], self)
        self.file_encrypt_edit.setFocusPolicy(QtCore.Qt.NoFocus)
        # row 12 col 2
        self.file_encrypt_button = QPushButton(MY_DOC[u'file_encrypt_button'], self)
        # add row 12
        self.grid.addWidget(self.file_encrypt_label, 12, 0)
        self.grid.addWidget(self.file_encrypt_edit, 12, 1)
        self.grid.addWidget(self.file_encrypt_button, 12, 2)

        # row 13: col 0
        self.file_decrypt_label = QLabel(MY_DOC[u'file_decrypt_label'], self)
        # row 13: col 1
        self.file_decrypt_edit = STextEdit(MY_DOC[u'file_decrypt_edit'], self)
        self.file_decrypt_edit.setPlaceholderText(MY_DOC[u'file_decrypt_edit_placeholder'])
        self.file_decrypt_edit.setFocusPolicy(QtCore.Qt.NoFocus)
        # add row 13
        self.grid.addWidget(self.file_decrypt_label, 13, 0)
        self.grid.addWidget(self.file_decrypt_edit, 13, 1, 1, 2)

        # 信号与回调
        self.random_button.clicked.connect(self.generateRandom128)
        self.rsa_hint_button.clicked.connect(self.generateRsaKey1024)
        self.rsa_raw_button.clicked.connect(self.encryptRsa)
        self.rsa_encrypt_button.clicked.connect(self.decryptRsa)
        self.aes_hint_button.clicked.connect(self.saveAesKey)
        self.aes_key_button.clicked.connect(self.generateAesSha256)
        self.aes_hash_button.clicked.connect(self.findAesFromSha256)
        self.aes_raw_button.clicked.connect(self.encryptAes)
        self.aes_encrypt_button.clicked.connect(self.decryptAes)
        self.file_encrypt_button.clicked.connect(self.fileEncrypt7z)

        # 整体布局添加
        self.widget = QWidget()
        self.widget.setLayout(self.grid)
        self.setCentralWidget(self.widget)

    # 0.4. 常用工具函数
    def checkPrefix(self) -> Optional[str]:
        prefix = self.prefix_edit.text()
        # 如果希望 prefix 支持中文，只需要去掉 ".encode('utf-8')" 即可
        if prefix.encode(u'utf-8').isalnum():
            return prefix
        else:
            self.status.showMessage(MY_DOC[u'check_prefix_err1_fmt'].format(prefix))
            QMessageBox.critical(self, u'Error', MY_DOC[u'check_prefix_err2_fmt'].format(prefix))
            return None

    def saveRsaKey(self, prefix: str, key_type: str, key: bytes) -> bool:
        key_name = MY_DOC[u'key_name_dict'][key_type]

        # 如果文件已经存在，发出文件覆盖的警告
        key_file = u'{}_rsa_{}_key.pem'.format(prefix, key_type)
        if os.path.exists(key_file):
            self.status.showMessage(MY_DOC[u'save_rsa_key_warn_exist_fmt'].format(key_name, key_file))
            QMessageBox.warning(self, u'Warning', MY_DOC[u'save_rsa_key_warn_exist_fmt'].format(key_name, key_file))

        # 异常处理
        try:
            with open(key_file, u'wb') as f:
                f.write(key)
            return True
        except Exception as e:
            self.status.showMessage(MY_DOC[u'save_rsa_key_err1_fmt'].format(key_name, key_file))
            QMessageBox.critical(self, u'Error', MY_DOC[u'save_rsa_key_err2_fmt'].format(key_name, key_file, repr(e)))
            return False

    # 返回 None 意味着读取失败, 否则认为读取成功
    def loadRsaKey(self, prefix: str, key_type: str) -> Optional[RSA.RsaKey]:
        key_name = MY_DOC[u'key_name_dict'][key_type]

        # 先检测文件是否存在
        key_file = u'{}_rsa_{}_key.pem'.format(prefix, key_type)
        if not os.path.exists(key_file):
            self.status.showMessage(MY_DOC[u'load_rsa_key_err_fmt'].format(key_name, key_file))
            QMessageBox.critical(self, u'Error', MY_DOC[u'load_rsa_key_err_fmt'].format(key_name, key_file))
            return None

        # 异常处理
        try:
            with open(key_file) as f:
                data = f.read()
                key = RSA.importKey(data)
            return key
        except Exception as e:
            self.status.showMessage(MY_DOC[u'load_rsa_key_err1_fmt'].format(key_name, key_file))
            QMessageBox.critical(self, u'Error', MY_DOC[u'load_rsa_key_err2_fmt'].format(key_name, key_file, repr(e)))
            return None

    def infoDisplay(self, info: str):
        QMessageBox.information(self, u'Information', info)

    # 1. 生成 128 bit 的随机 base-64 字符 (输出为 24 byte 的 ASCII 字符串, 实际信息量为 128 bit)
    def generateRandom128(self) -> str:
        random_bytes = secrets.token_bytes(16)  # 16 byte == 128 bit
        random_base64 = base64.b64encode(random_bytes, b'-_')
        random_str = random_base64.decode(u'utf-8')
        self.random_edit.setText(random_str)
        self.status.showMessage(MY_DOC[u'generate_random_128_ok_fmt'].format(random_str))
        return random_str

    # 2. 检查 RSA 的公私钥文件是否可存在或可用
    def generateRsaKey1024(self) -> None:
        prefix = self.checkPrefix()
        if prefix is None:
            return None

        random_generator = Random.new().read
        rsa = RSA.generate(1024, random_generator)
        # 生成公私钥
        private_key = rsa.exportKey()
        public_key = rsa.publickey().exportKey()
        temp_key_name_dict = {u'public': public_key, u'private': private_key}

        # 保存
        success_key = []
        fail_key = []
        for key_type in MY_DOC[u'key_name_dict'].keys():
            is_success = self.saveRsaKey(prefix, key_type, temp_key_name_dict[key_type])
            if is_success:
                success_key.append(key_type)
            else:
                fail_key.append(key_type)
        if len(fail_key) == 0:
            self.status.showMessage(MY_DOC[u'generate_rsa_key_1024_success'])
        elif len(success_key) == 0:
            self.status.showMessage(MY_DOC[u'generate_rsa_key_1024_fail'])
        else:
            key_name_dict = MY_DOC[u'key_name_dict']
            self.status.showMessage(MY_DOC[u'generate_rsa_key_1024_mix_fmt'].format(
                key_name_dict[success_key[0]], key_name_dict[fail_key[0]]))

    # 3. 公钥加密 (可对 utf-8 字符串加密, 密文采用 base64 编码)
    def encryptRsa(self) -> Optional[str]:
        prefix = self.checkPrefix()
        if prefix is None:
            return

        public_key = self.loadRsaKey(prefix, u'public')
        if public_key is None:
            return None

        # msg (utf-8) -> encrypt_msg_bytes (bytes) -> encrypt_msg_base64 (base-64-bytes)
        msg = self.rsa_raw_edit.toPlainText()
        cipher = PKCS1_cipher.new(public_key)
        msg_bytes = b''
        try:
            msg_bytes = bytes(msg.encode(u'utf-8'))
            encrypt_msg_bytes = cipher.encrypt(msg_bytes)
            encrypt_msg_base64 = base64.b64encode(encrypt_msg_bytes, b'-_')
        except ValueError as e:
            self.status.showMessage(MY_DOC[u'encrypt_rsa_value_err1_fmt'].format(len(msg_bytes)))
            QMessageBox.critical(self, u'Error', MY_DOC[u'encrypt_rsa_value_err2_fmt'].format(
                len(msg_bytes), public_key.size_in_bytes() * 8, public_key.size_in_bytes() - 11, repr(e)))
            return None
        except Exception as e:
            self.status.showMessage(MY_DOC[u'encrypt_rsa_err1_fmt'].format(len(msg_bytes)))
            QMessageBox.critical(self, u'Error', MY_DOC[u'encrypt_rsa_err2_fmt'].format(repr(e)))
            return None

        # encrypt_msg_base64 (base-64-bytes) -> encrypt_msg_base64 (base-64-str)
        encrypt_msg_base64 = encrypt_msg_base64.decode(u'utf-8')
        self.rsa_encrypt_edit.setText(encrypt_msg_base64)
        self.status.showMessage(MY_DOC[u'encrypt_rsa_ok'].format(len(msg_bytes)))
        return encrypt_msg_base64

    # 4. 私钥解密 (恢复为 utf-8 字符串)
    def decryptRsa(self) -> Optional[str]:
        prefix = self.checkPrefix()
        if prefix is None:
            return None

        private_key = self.loadRsaKey(prefix, u'private')
        if private_key is None:
            return None

        # encrypt_msg_base64 (base-64-str) -> encrypt_msg_bytes (bytes)
        encrypt_msg_base64 = self.rsa_encrypt_edit.toPlainText()
        try:
            encrypt_msg_bytes = base64.b64decode(encrypt_msg_base64, b'-_')
        except Exception as e:
            self.status.showMessage(MY_DOC[u'decrypt_rsa_err1_base64'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'decrypt_rsa_err2_base64_fmt'].format(repr(e)))
            return None

        # encrypt_msg_bytes (bytes) -> msg_bytes (bytes)
        cipher = PKCS1_cipher.new(private_key)
        try:
            msg_bytes = cipher.decrypt(encrypt_msg_bytes, 0)
        except Exception as e:
            self.status.showMessage(MY_DOC[u'decrypt_rsa_err1_decrypt'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'decrypt_rsa_err2_decrypt_fmt'].format(repr(e)))
            return None

        msg = msg_bytes.decode(u'utf-8')
        self.rsa_raw_edit.setText(msg)
        self.status.showMessage(MY_DOC[u'decrypt_rsa_ok'].format(len(msg_bytes)))
        return msg

    # AES tools
    def getAesKey(self) -> Optional[str]:
        # 检查AES密钥是否为合法的 24 字节 base-64 字符串（128 bit）
        aes_key_base64 = self.aes_key_edit.text()
        try:
            aes_key = base64.b64decode(aes_key_base64, b'-_')
        except Exception as e:
            self.status.showMessage(MY_DOC[u'get_aes_key_err1_base64'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'get_aes_key_err2_base64_fmt'].format(repr(e)))
            return None
        if len(aes_key) != 16:
            self.status.showMessage(MY_DOC[u'get_aes_key_err1_len_fmt'].format(len(aes_key) * 8))
            QMessageBox.critical(self, u'Error', MY_DOC[u'get_aes_key_err2_len_fmt'].format(len(aes_key) * 8))
            return None

        # 重新编码回去并回显，避免 base-64 终止符的问题，当然其实不考虑也行，这属于用户的误操作问题
        aes_key_base64 = base64.b64encode(aes_key, b'-_').decode('utf-8')
        return aes_key_base64

    def getAllLocalAesKey(self) -> Optional[List[str]]:
        prefix = self.checkPrefix()
        if prefix is None:
            return None
        key_file = u'{}_aes_key.txt'.format(prefix)
        try:
            # 如果不存在，则创建文件
            if not os.path.exists(key_file):
                with open(key_file, u'w'):
                    pass
            # 先读入已有的 key
            with open(key_file, u'r') as f:
                all_key = f.read().splitlines()
            return all_key
        except Exception as e:
            self.status.showMessage(MY_DOC[u'get_all_local_aes_key_err1_fmt'].format(key_file))
            QMessageBox.critical(self, u'Error', MY_DOC[u'get_all_local_aes_key_err2_fmt'].format(key_file, repr(e)))
            return None

    def loadAllValidAesKey(self) -> Optional[List[str]]:
        # 读入合法的AES密钥
        temp_key_base64 = self.getAllLocalAesKey()
        temp_key_base64.append(self.aes_key_edit.text())
        if temp_key_base64 is None:
            return None

        all_key_base64 = []
        for key_base64 in temp_key_base64:
            try:
                key = base64.b64decode(key_base64, b'-_')
            except:
                continue
            if len(key) != 16:
                continue
            all_key_base64.append(key_base64)
        all_key_base64 = list(set(all_key_base64))
        return all_key_base64

    def getAesHash(self) -> Optional[bytes]:
        digest_base64 = self.aes_hash_edit.text()
        try:
            digest = base64.b64decode(digest_base64, b'-_')
        except Exception as e:
            self.status.showMessage(MY_DOC[u'get_aes_hash_err1_base64'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'get_aes_hash_err2_base64_fmt'].format(repr(e)))
            return None
        if len(digest) != 32:
            self.status.showMessage(MY_DOC[u'get_aes_hash_err1_len_fmt'].format(len(digest) * 8))
            QMessageBox.critical(self, u'Error', MY_DOC[u'get_aes_hash_err2_len_fmt'].format(len(digest) * 8))
            return None
        return digest

    # 5. 将 AES 密钥保存在本地
    def saveAesKey(self) -> bool:
        aes_key_base64 = self.getAesKey()
        if aes_key_base64 is None:
            return False
        self.aes_key_edit.setText(aes_key_base64)

        # 保存
        prefix = self.checkPrefix()
        if prefix is None:
            return False
        key_file = u'{}_aes_key.txt'.format(prefix)
        all_key = self.getAllLocalAesKey()
        if all_key is None:
            return False

        # 再写入已有的 key
        try:
            with open(key_file, u'w+') as f:
                all_key.append(aes_key_base64)
                all_key = list(set(all_key))
                for key in all_key:
                    f.write(key + u'\n')
                self.status.showMessage(MY_DOC[u'save_aes_key_ok_fmt'].format(aes_key_base64, key_file))
                QMessageBox.information(self, u'Information', MY_DOC[u'save_aes_key_ok_fmt'].format(
                    aes_key_base64, key_file))
            return True
        except Exception as e:
            self.status.showMessage(MY_DOC[u'save_aes_key_err1_fmt'].format(key_file))
            QMessageBox.critical(self, u'Error', MY_DOC[u'save_aes_key_err2_fmt'].format(key_file, repr(e)))

    # 6. 生成 AES 密钥的 SHA256
    def generateAesSha256(self) -> Optional[str]:
        aes_key_base64 = self.getAesKey()
        if aes_key_base64 is None:
            return None
        self.aes_key_edit.setText(aes_key_base64)

        aes_key = base64.b64decode(aes_key_base64, b'-_')
        sha256 = SHA256.new()
        sha256.update(aes_key)
        digest = sha256.digest()
        digest_base64 = base64.b64encode(digest, b'-_').decode(u'utf-8')
        self.aes_hash_edit.setText(digest_base64)
        self.status.showMessage(MY_DOC[u'generate_aes_sha256_ok_fmt'].format(aes_key_base64, digest_base64))
        return digest_base64

    # 7. 基于 AES 密钥的 SHA-256 结果，尝试在本地密钥本里搜索是否存在匹配的 AES 密钥
    def findAesFromSha256(self) -> Optional[str]:
        all_key_base64 = self.loadAllValidAesKey()
        if all_key_base64 is None:
            return None

        digest = self.getAesHash()
        if digest is None:
            return None
        digest_base64 = self.aes_hash_edit.text()

        # 对比与匹配
        for key_base64 in all_key_base64:
            key = base64.b64decode(key_base64, b'-_')
            sha256 = SHA256.new()
            sha256.update(key)
            new_digest = sha256.digest()
            if new_digest == digest:
                self.aes_key_edit.setText(key_base64)
                self.status.showMessage(MY_DOC[u'find_aes_key_from_sha256_ok1_fmt'].format(digest_base64, key_base64))
                QMessageBox.information(self, u'Information', MY_DOC[u'find_aes_key_from_sha256_ok2_fmt'].format(
                    digest_base64, key_base64))
                return key_base64

        self.status.showMessage(MY_DOC[u'find_aes_key_from_sha256_warn1_fmt'].format(digest_base64))
        QMessageBox.warning(self, u'Warning', MY_DOC[u'find_aes_key_from_sha256_warn2_fmt'].format(digest_base64))
        return None

    # 8. AES 对称加密 (可对 utf-8 字符串加密, 密文采用 base64 编码)
    def encryptAes(self) -> Optional[str]:
        aes_key_base64 = self.getAesKey()
        if aes_key_base64 is None:
            return None
        self.aes_key_edit.setText(aes_key_base64)
        aes_key = base64.b64decode(aes_key_base64, b'-_')

        # msg (utf-8) -> encrypt_msg (bytes) -> encrypt_msg (base-64)
        msg = self.aes_raw_edit.toPlainText()
        cipher = AES.new(aes_key, AES.MODE_CBC)
        try:
            iv = cipher.iv                          # iv 用明文传输即可，在密文前端以base-64编码作为前缀发出去
            msg_bytes = bytes(msg.encode(u'utf-8'))
            padding_len = 16 - len(msg_bytes) % 16  # padding to 16 bytes
            padding_len_bytes = padding_len.to_bytes(1, u'little')
            encrypt_msg_bytes = cipher.encrypt(msg_bytes + bytes(padding_len - 1) + padding_len_bytes)
            encrypt_msg_base64 = base64.b64encode(iv + encrypt_msg_bytes, b'-_')
        except Exception as e:
            self.status.showMessage(MY_DOC[u'encrypt_aes_err1'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'encrypt_aes_err2_fmt'].format(repr(e)))
            return None

        # encrypt_msg (base-64) -> encrypt_msg (base-64-str)
        encrypt_msg = encrypt_msg_base64.decode(u'utf-8')
        self.aes_encrypt_edit.setText(encrypt_msg)
        self.status.showMessage(MY_DOC[u'encrypt_aes_ok'])
        return encrypt_msg

    # 9. AES 对称解密 (恢复为 utf-8 字符串)
    def decryptAes(self) -> Optional[str]:
        aes_key_base64 = self.getAesKey()
        if aes_key_base64 is None:
            return None
        self.aes_key_edit.setText(aes_key_base64)
        aes_key = base64.b64decode(aes_key_base64, b'-_')

        # msg (utf-8) -> encrypt_msg (bytes) -> encrypt_msg (base-64)
        encrypt_iv_msg_base64 = self.aes_encrypt_edit.toPlainText()
        try:
            encrypt_iv_msg_bytes = base64.b64decode(encrypt_iv_msg_base64, b'-_')
            iv = encrypt_iv_msg_bytes[0:16]
            encrypt_msg_bytes = encrypt_iv_msg_bytes[16:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            msg_bytes = cipher.decrypt(encrypt_msg_bytes)
            padding_len = msg_bytes[-1:]
            padding_len = int.from_bytes(padding_len, u'little')
            msg = msg_bytes[:(-padding_len)].decode(u'utf-8')
            # print('Hi', msg)
        except Exception as e:
            self.status.showMessage(MY_DOC[u'decrypt_aes_err1'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'decrypt_aes_err2_fmt'].format(repr(e)))
            return None

        self.aes_raw_edit.setText(msg)
        self.status.showMessage(MY_DOC[u'decrypt_aes_ok'])
        return msg

    # 将选中的文件/目录分类，并给出相对最长公共子路径的相对路径排布
    def cookFileDir(self, pathList: List[str]) -> Dict[str, Optional[Dict[str, str]]]:
        allValidPath = []
        fileList = []
        dirList = []
        fileDict = {}
        dirDict = {}

        for path in pathList:
            if os.path.isfile(path):
                fileList.append(path)
                allValidPath.append(path)
            elif os.path.isdir(path):
                dirList.append(path)
                allValidPath.append(path)

        # prefix = os.path.commonpath(allValidPath)
        for file in fileList:
            try:
                # 开摆，用最简单的实现以防bug
                fileDict[file] = os.path.basename(file)
                # common_path = os.path.relpath(file, prefix)
                # if common_path == '.':
                #     common_path = os.path.basename(file)
                # fileDict[file] = common_path
            except:
                # @todo 如果用户有很逆天的操作，也许这里会出现bug，但是我懒得处理了
                pass
        if len(fileDict) == 0:
            fileDict = None

        for directory in dirList:
            try:
                # 开摆，用最简单的实现以防bug
                dirDict[directory] = os.path.basename(directory)
                # common_path = os.path.relpath(directory, prefix)
                # if common_path == '.':
                #     common_path = os.path.basename(directory)
                # dirDict[directory] = common_path
            except:
                # @todo 如果用户有很逆天的操作，也许这里会出现bug，但是我懒得处理了
                pass
        if len(dirDict) == 0:
            dirDict = None

        result = {
            'file': fileDict,
            'dir': dirDict,
        }
        return result

    # 10. 用 7z 压缩文件
    def fileEncrypt7z(self) -> Optional[str]:
        aes_key_base64 = self.getAesKey()
        if aes_key_base64 is None:
            return None
        self.aes_key_edit.setText(aes_key_base64)
        aes_key = base64.b64decode(aes_key_base64, b'-_')

        sha256 = SHA256.new()
        sha256.update(aes_key)
        digest = sha256.digest()
        digest_base64 = base64.b64encode(digest, b'-_').decode(u'utf-8')

        files = self.file_encrypt_edit.toPlainText()
        if len(files) == 0:
            self.status.showMessage(MY_DOC[u'file_encrypt_7z_err1'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_encrypt_7z_err1'])
            return None

        pathList = files.splitlines(False)
        result = self.cookFileDir(pathList)

        # 预防一些稀奇古怪的bug
        if (result is None) or (result['dir'] is None and result['file'] is None):
            self.status.showMessage(MY_DOC[u'file_encrypt_7z_err2_unknown'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_encrypt_7z_err2_unknown'])
            return None

        try:
            output_file_name = digest_base64 + u'.7z'
            # 某些文件输入可能导致py7zr卡死，很奇怪
            with py7zr.SevenZipFile(output_file_name, u'w', password=aes_key_base64) as f:
                if result['dir'] is not None:
                    for file_name, rel_path in result['dir'].items():
                        f.writeall(file_name, rel_path)
                if result['file'] is not None:
                    for file_name, rel_path in result['file'].items():
                        f.write(file_name, rel_path)
            with py7zr.SevenZipFile(u'~' + output_file_name, u'w', password=aes_key_base64) as f2:
                f2.write(digest_base64 + u'.7z')
            os.remove(output_file_name)
            os.rename(u'~' + output_file_name, output_file_name)

        except Exception as e:
            self.status.showMessage(MY_DOC[u'file_encrypt_7z_err3'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_encrypt_7z_err4_fmt'].format(repr(e)))
            return None

        self.status.showMessage(MY_DOC[u'file_encrypt_7z_ok_fmt'].format(output_file_name))
        QMessageBox.information(self, u'Information', MY_DOC[u'file_encrypt_7z_ok_fmt'].format(output_file_name))
        return output_file_name

    # 11. 用 7z 解压文件
    def fileDecrypt7z(self, path: str) -> Optional[str]:
        if not py7zr.is_7zfile(path):
            self.status.showMessage(MY_DOC[u'file_decrypt_7z_err1'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err1'])
            return None

        all_key_base64 = self.loadAllValidAesKey()
        if all_key_base64 is None:
            return None

        target = None
        file_name = None
        try:
            with py7zr.SevenZipFile(path, u'r') as f:
                inner_names = f.getnames()
                if len(inner_names) != 1:
                    self.status.showMessage(MY_DOC[u'file_decrypt_7z_err2_fmt'].format(len(inner_names)))
                    QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err2_fmt'].format(len(inner_names)))
                    return None

                inner_name = inner_names[0]
                digest_base64 = os.path.splitext(inner_name)[0]
                digest = base64.b64decode(digest_base64, b'-_')
                suffix = os.path.splitext(inner_name)[-1]
                if len(digest) != 32 or suffix != u'.7z':
                    self.status.showMessage(MY_DOC[u'file_decrypt_7z_err3'])
                    QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err3'])
                    return None

                for key_base64 in all_key_base64:
                    key = base64.b64decode(key_base64, b'-_')
                    sha256 = SHA256.new()
                    sha256.update(key)
                    new_digest = sha256.digest()
                    # key_base64 就是正确的解压密码
                    if new_digest == digest:
                        target = key_base64
                        file_name = inner_name
                        break

        except Exception as e:
            self.status.showMessage(MY_DOC[u'file_decrypt_7z_err4'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err4_fmt'].format(repr(e)))
            return None

        # 说明没找到
        if target is None:
            self.status.showMessage(MY_DOC[u'file_decrypt_7z_err_return'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err_return'])
            return None

        try:
            with py7zr.SevenZipFile(path, u'r', password=target) as f:
                now = datetime.now()
                now_name = now.strftime(u'%Y~%m~%d-%H~%M~%S')
                output_dir = u'./{}'.format(now_name)
                if os.path.exists(output_dir):
                    shutil.rmtree(output_dir)
                os.makedirs(output_dir)

                f.extractall(path=output_dir)

            output_dir2 = u'{}/{}'.format(output_dir, digest_base64)
            output_file = u'{}/{}'.format(output_dir, file_name)
            os.makedirs(output_dir2)
            with py7zr.SevenZipFile(output_file, u'r', password=target) as f:
                f.extractall(path=output_dir2)
            os.remove(output_file)
        except Exception as e:
            self.status.showMessage(MY_DOC[u'file_decrypt_7z_err4'])
            QMessageBox.critical(self, u'Error', MY_DOC[u'file_decrypt_7z_err4_fmt'].format(repr(e)))
            return None

        self.status.showMessage(MY_DOC[u'file_decrypt_7z_ok_fmt'].format(inner_name))
        QMessageBox.information(self, u'Information', MY_DOC[u'file_decrypt_7z_ok_full_fmt'].format(
            inner_name, output_dir2))
        return target


if __name__ == u'__main__':
    app = QApplication(sys.argv)
    form = MyWindow()
    form.show()
    sys.exit(app.exec_())
