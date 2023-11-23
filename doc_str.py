# -*- coding: utf-8 -*-
# @Time    : 2023-11-23
# @Author  : Mamiya Hasaki

def ToRed(text: str) -> str:
    return u'<font color="red">{}</font>'.format(text)


def ToOrange(text: str) -> str:
    return u'<font color="orange">{}</font>'.format(text)


MY_DOC = {
    # u'program_icon': u'./hasaki.jpg',
    u'author_icon': u'_9j_4AAQSkZJRgABAQAAAQABAAD_2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL_2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL_wAARCABkAGQDASIAAhEBAxEB_8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL_8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4-Tl5ufo6erx8vP09fb3-Pn6_8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL_8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3-Pn6_9oADAMBAAIRAxEAPwDxxELNgVtaZpEl26hVPNQ6fZGWQDGa94-HHgyL7OuqX0QK_wDLNG_i9z7V7s5qnHnlseTUnKclSp7sy_CvwyhW0Goauwt7ZRuO7gkf0rW1Dxvpvh-E2vh-whjVePOkXlvfHX8z-FUfHHjA3129nayYs4TtG0_fYd_p6V5hqF40rNzXK1Kp71T7jejRjDbfudBq3xH8QXLt_wATa4Qf3YiEH6Vzx8Za-sm-PW9QVvUXDf1rFlbJqHBp-6uh2RgehaN8W9bsmEWqrHq1meHSVQJMezdD-Nd_PoXhX4k6OL_TYoBIflJVfKkjb-62Oh-oINeC28McoILbT1Gelb3hTWtQ8La7FfWRLxsQs8QPyyp6H39D2rJprWGjK9mno0UvFPgm50C7mhXdIIz84ZdroO2R6e4yK491KNg19Qa7Bp3jbToZIJF-1NGZLO46F1_iQ-4P3l_EV4L4l0CaynlYxlXjbbKmMFT7jt_XqK7KU_awu90cc_3U-V7M5ilGAPftTwdiAHO4UIQr7sA45ANM0EKsOuQfeihnLMWJJJ7migR6V4E0NtY1m2tVHDtlj6KOpr3Lxbqceg-DJ3tSE3ILeDHbPH8smuJ-EunC30vUdTYfOE8qM_hk_wBKv_F6fyNB020U8mckj2Vcf1rDEPmrqn0RyYVe66nV_keSXd2WzzxWRNLuJ5qeTdJ0BNQ_Z_nw7qmfWipOx6NKnoU3Py5x9aURkKGc4Q_dPrU7CKJiFPmHrnsKghdDcqlwGMIIzg8ge3v_AIVzymdKjYlHlRsHRz77hUYkeNyFYgj0NXtZ0K70O42y4ktpE82KZR8sif3h9O47fSsyNQcEn92Dy3ovf9M_lUKp1HJW3O58O6yNOtIrGS5lSSRPthk6_Z2z8rqPUL8zDupYd66fWng8TWCaj5MUGoxn7HdJn5PNHRGP91-qN64HpXmNprH2O-W-RAZWPzswztj6FV9Mrxn8q19N1iPRdWMN6TLp8hOn36_34f8Alm_1C4IP-zWtKo4S5kc1ekqkeVnGavam01GaPY6AMRtcYK-oP06VSBBru_Funv58lteOr3duQqXa9J4yPkY_Ud_w9K4Vo2jkKMMEV3Ss_eRywbS5XuhKKUHFFIo-oPByLZ-BxzguVc_8CkC_yFZvxbCtJaqeTsfaP8_SpLa5EHg-8UHH2a3X808lj-rGq_xXfN3YOOVaM4_M_wCIrjm37dy7tiwsP3aR5NO7w2xRflLdSOtZjnKqzZwCCfpV28lDzkDoOKjtbV72yuFiUtJbZfA6mPqfy6_TPpWU5Howj2GLCLbUFiuP9WflfHdCM7h-HIqT-yZIdeGnXT-WS_lM4HG1sYf6chvpXU6Noa-L_Colilji1Ow_dQMThXUHO1j9Twewx2NXNS0w3fh601MwNHe6URFdRMPmEQOGU-uzOQe6kVzufQ6VSurjke1t_AhOowyDVtOuDBCceY4mU4CDJxtI4I6bcmvOTcQz39zHFNZWcc5-SCQuUjyQQBJjsehPGDXul74dh1Np_MyFvIElJHaUKUJ_FWH5V4p4j8Lw2PjO9s7Gzu4LSGURxx3LB3JwOcjghuo9iKmDTM8W3C19jPlhntZ5bS5iMU0Rwy5yMHkYPcVo6tEy21rc9VvLBJD7tGxQ_wDoJ_OtLxNZC3stGlJ3OIprN3_v-TKyqT77WA_4DTbiMyaP4a7_ADTR4PTBkNdMLvQ53JcikxtvqQ1Pw9EJ_nlsF8pvV7dj_wCysQR9R6VzN3GYp3il-bb91vUdjXRtpk-lXUt5BbyfZiSJYipGUPBx6ggn6HFZOpwHKc7lVcK_95eoP5GvVp0ZqNn0PNlWhKV11MnYDzRQwIOKKk1ue66TfLe6JPCx4u7LUHwP9nyj_T9KTx3ef2n4E0DVUOWaLaxH94KD_OM1iaJmDxB4c0pW3ebp12GPr5okA_8AQRSaRcnUvhHqVq5zLpNws4HfYTk_oXrmxCtUdu5pg1amkef-YWYc9T3rS8P3y2Ov27yyGOF3CyOB93PGf1wfYmsmRNjvHnocZ_rV26gEtnBfxAeXNlZFH_LOUfeX8eGHsfauWcb6HbGVncmutfk0m6ur3THm0-C8mYxWkE2Fwh25J64znAHavUvAXii08V2M9vdx7dQSPbMkhyZ4um4H-LGcHuM-hrhfCVjPrvhrU9At4LR7w4eGWeMElN24orn_AFZJ6N0zwcZFXdC0LUdG1yzjjtLtNR-0IVDwNGkaA_vSzH5SCpK4BOc1zzirBTq1Y1Fpe7PXrOFrayggY5MSBAfUDgfoBWVrvh6y1uWGaZriGeIbRLbSeW7L_dJ7j07jsa15GHkuwUsApIUdTisk6lMZ_NUARED90QD-vrXJdrVHtunGa5ZK6OA-I-mQado2iW9pB5VvDNIqqCTgEAnJPJJPOfeq-h24ltNPcY_0RNwOeQzF2_8AZh-VbvxTuojpdhbLgu8gl6chf_rnH5Vn-G9v9ipkcvIfxwAB-gr0cG7WPDzGzk0jf0q-vLPfHEnmxEktCyb1Iz6dvrTtX8FaR4l0OabRYfsuqwgu1oDgOO-0f4flVaBprdGCzyjdySGIz-VWoJ721P2uMXWFBPmRqxOO_SvT9rZ8ydn-fqeKsM38KbPEp9MljndGVgQcEYor3gXul3Sia4s7eSRhks0WSe_XBord1Ff4TP2k1pocBpV6tt8RdMuGfKW8kNkvvgBWP5lqf4KlW28b6x4dnOIdRS5s8HpvUsV_TdXGx3ZS8iuhJlo5A455yDnP51uapcHTfiTe6lAceVdi6THfeA39TWVWi5Wit2dlKty3bOeuYniYxyjEkZMT_Ucf5-laOkyqtpJbyIMzkMQx-V_T6HIPPbPtWr45sYoNenvbYf6LesJkI6YkUOp_Vh_wE1zqFktoVk43Kdjfif6isKVKM5WkbVazjFOJveGIJxqpfS7iWLUImMkI8ssWH8aOo7Y59CM9DivWtO8RW-oKkd9_xL7oDlJCTFJ7o_Qj2OCK818I3c51K31CyRW1C3LSMh_jAXa4_wCBL-o967lArxK6jcrqGGejelYVsHH7RdHMJxf7s6KbU9PtEDTX1uq-u_P8qzJNV0HDXCXDTKOWWIEj8qyMibejWkq9juUbT-Oea5rU7b7Bcbo45ViYfeCnCH0z6VxywyjqtUd0cxqy00TF8cSPfX0DyKFZnTao7JuGP0P507w-pZmBPyw7gq9ssev5D9ayLya4nlhmml82KMYzjBA9eOtaehnyp7ps4VlQD_eyR_hV0mudWOetdxbZ3uhafHcR_bJgGTOI1PQ47n-ldD9K53wzdxhJbAOv7v8AeIoPIBPPH15_GuiU5rnrOXtHzHr4RQ9inBHNap4fujeFrHyliYbtrZ4J649qK6tSFGMA0V0RxlRK1zjnl9KUnK258nIxBArpNZcSpY3uebiziBPq0YMZ_wDQRXNMjIfmBH1FaZuDPoMcROXtpjtH-y4_xH617kW00eBNHVWsg17wqlsxzPan7OCfQktEfwbcv_AxXN4Fzo0luQVntnaSPPUqfvL-HX8DTdE1H7JdPHIxWC4QxSEds8hvwYA_hVvU4m2LqcJwJid-3okw--PoQQw9ifSk4rmv3Em7crNr4a2sl1rrSBwBFEzvnrjofyzn6A16eyFUWFgA0bMOO-Tk_rz-NeX_AAuldPGlgkbFWeTbx05BHI7j2r1m_ijhkMKkb0mlVlB6KCAo_n-VTinrGPl_mRRi-eT_AK6GdIAO4_OkOk3s6F44SAR_GwXP4Gul0Wws204XnDTnsV5T8O1W3Ga8apiJJ2SPoKGBpy1k7nlOo6OWzJHG0Em4jb5Z2OfT2P0rnmuZbaGSJPkZsBgRzgHnB9a9tniSaNo5UDo3BVuRXnviHwW8Sy3NhI0ycs0MnLD6Hv8AzrD2ybvazNZYGUV7rujl7fULmx1GO_t5MXEfQnow7qfUEV6t4c1238QwqYSI51x50TNzH7-4968Vmult4yZWwFGdxr0TwTaW1h4dj1mfEctzCZZJH48uLqF-mBk-_wBKidty8I53cVsepRyaQq4Z5XI6ttPNFeH3HxW1SS5lOmaRE9mGIieVZCzj1OOBn0orRU59iHVw9_jZ5zNcO5-bB-opsMr-YRxgrjGKKK-lbfMfPtaEUhw5xW7oUjXEV_ZS_NC9s8pB7OgypHv1H0JooqXswe6NT4aEj4g6MAetyP5GvSbiZzJczliXLO554JzRRWVf4_kvzZMdvmbujzSLPHGGO08H3FbDdaKK8TE_EfRZe_cZC9VZuMmiiuOR60Djb7wRpGu3M8tyJ495yywSbATj6UzWIVtvhzFZxMyxtFDbk99hZQfxxRRRB3kvUxqxUYTaXQ5-HTbJI9pto3I_ikG4n8TRRRXvJKx80f_Z',
    u'title': u'不可信信道中的文本/文件安全加密工具',

    # u'rsa_raw_button2': u'检测公/私钥是否存在',
    # u'rsa_encrypt_button2': u'重新生成公/私钥',

    u'check_prefix_err1_fmt': u'名称前缀"{}"的内容只能是英文字符和数字的组合！',
    u'check_prefix_err2_fmt': u'{}的内容只能是英文字符和数字的组合！<br>'.format(ToRed('名称前缀')) + \
                              u'当前名称不合法前缀为"{}"<br>' + \
                              u'注：如果希望支持中文字符，只需删掉checkPrefix函数的".encode(\'utf-8\')"即可<br>' + \
                              u'默认不支持中文字符是为了避免不期望的编码格式问题的产生',

    u'save_rsa_key_warn_exist_fmt': u'{}文件"{}"已存在，已经用新生成的文件覆盖',

    u'save_rsa_key_err1_fmt': u'访问{}文件"{}"时出现异常',
    u'save_rsa_key_err2_fmt': u'访问{}文件"{}"时出现异常，原因是:<br>{}',

    u'load_rsa_key_err_fmt': u'{}文件"{}"不存在',

    u'load_rsa_key_err1_fmt': u'访问{}文件"{}"时出现异常',
    u'load_rsa_key_err2_fmt': u'访问{}文件"{}"时出现异常，原因是:<br>{}',

    u'key_name_dict': {
        u'public': u'公钥',
        u'private': u'私钥',
    },

    u'bar_guide': u'指南',
    u'bar_guide_intro': u'使用简介',
    u'bar_guide_intro_content': u'todo ...',

    u'prefix_label': u'名称前缀',
    u'prefix_edit': u'my',

    u'random_label': u'随机数发生器',
    u'random_edit': u'',
    u'random_button': u'重新生成随机数',
    u'generate_random_128_ok_fmt': u'成功生成128bit的随机数"{}"，已采用base-64编码输出',

    u'rsa_hint_label': u'{}：<br>'.format(ToRed('RSA使用说明')) + \
                       u'1. {}先生成一对公私钥，把{}通过不安全信道发给{}<br>'.format(
                           ToOrange('收方'), ToOrange('公钥'), ToOrange('发方')) + \
                       u'2. {}将收到的{}放在本程序目录下，用{}对明文加密得到{}，把密文通过不安全信道发给{}<br>'.format(
                           ToOrange('发方'), ToOrange('公钥'), ToOrange('公钥'), ToOrange('密文'), ToOrange('收方')) + \
                       u'3. {}收到密文，用{}对密文解密得到{}，整个过程不会泄露明文'.format(
                           ToOrange('收方'), ToOrange('私钥'), ToOrange('明文')),
    u'rsa_hint_button': u'重新生成公/私钥',
    u'generate_rsa_key_1024_success': u'RSA公钥与私钥均生成成功',
    u'generate_rsa_key_1024_fail': u'RSA公钥与私钥均生成失败',
    u'generate_rsa_key_1024_mix_fmt': u'RSA{}生成成功，但{}生成失败',

    u'rsa_raw_label': u'RSA明文',
    u'rsa_raw_edit': u'',
    u'rsa_raw_edit_placeholder': u'请输入要加密的RSA明文，并确保目录下正确存放了对方的公钥\n' + \
                                 u'注1: 一般而言，RSA流程是用来交换AES密钥的，真正通信通过AES加密进行\n' + \
                                 u'注2: AES密钥应为随机数，将随机数发生器的结果作为RSA明文与对方交互',
    u'rsa_raw_button': u'用公钥生成密文',
    u'encrypt_rsa_value_err1_fmt': u'RSA加密失败，可能是因为明文过长，明文长度为{}字节',
    u'encrypt_rsa_value_err2_fmt': u'输入的RSA明文字符串可能过长，输入长度为{}byte<br>' + \
                                   u'注: 该公钥的加密方式是填充方式为PKCS1的RSA-{}，最大加密字节数为{}byte<br>' + \
                                   u'报错原因是:<br>{}',
    u'encrypt_rsa_err1_fmt': u'对RSA明文字符串的加密过程中出现未知错误',
    u'encrypt_rsa_err2_fmt': u'对RSA明文字符串的加密过程中出现未知错误，报错原因是:<br>{}',
    u'encrypt_rsa_ok': u'RSA加密成功，密文输出在"RSA密文"栏',

    u'rsa_encrypt_label': u'RSA密文',
    u'rsa_encrypt_edit': u'',
    u'rsa_encrypt_edit_placeholder': u'请输入要解密的RSA密文，并确保目录下正确存放了自己的私钥\n' + \
                                     u'常见流程: 收方生成一对公私钥，把公钥发给发方，发方用公钥加密随机数得到密文，把密文发给收方，收方用私钥解密得到明文随机数，将随机数作为AES密钥，随后用相同随机数采用AES对称加密通信',
    u'rsa_encrypt_button': u'用私钥生成明文',
    u'decrypt_rsa_err1_base64': u'RSA密文字符串解码失败，可能是因为密文并非base64编码',
    u'decrypt_rsa_err2_base64_fmt': u'对RSA密文字符串的解密过程中出现错误，可能是因为密文并非base64编码<br>' + \
                                    u'报错原因是:<br>{}',
    u'decrypt_rsa_err1_decrypt': u'对RSA密文字符串的解密过程中出现错误',
    u'decrypt_rsa_err2_decrypt_fmt': u'对RSA密文字符串的解密过程中出现错误，报错原因是:<br>{}',
    u'decrypt_rsa_ok': u'RSA解密成功，明文输出在"RSA明文"栏',

    u'aes_hint_label': u'{}：<br>'.format(ToRed('AES使用说明')) + \
                       u'1. 收方双方设置相同的{}，执行加解密过程即可<br>'.format(
                           ToOrange('AES密钥')) + \
                       u'2. 通过{}可以实现安全密钥交换，AES密钥应为双方相同的固定随机值<br>'.format(
                           ToOrange('RSA')) + \
                       u'3. 可以将当前AES密钥保存在本地，日后可通过密钥的{}值在本地尝试匹配已有的AES密钥<br>'.format(
                           ToOrange('SHA-256')) + \
                       u'4. 交换密钥的SHA-256值不会泄露密钥本身，如果对方本地没有保存该密钥，则无法通过SHA-256找到密钥',
    u'aes_hint_button': u'保存当前AES密钥到本地',
    u'get_aes_key_err1_base64': u'错误：AES密钥并非base64编码！',
    u'get_aes_key_err2_base64_fmt': u'错误：AES密钥并非base64编码！<br>报错原因是:<br>{}',
    u'get_aes_key_err1_len_fmt': u'AES密钥不是有效比特数为128的base-64串，实际比特数为{}',
    u'get_aes_key_err2_len_fmt': u'AES密钥不是有效比特数为128的base-64串，实际比特数为{}',
    u'get_all_local_aes_key_err1_fmt': u'本地AES密钥文件"{}"打开失败',
    u'get_all_local_aes_key_err2_fmt': u'本地AES密钥文件"{}"打开失败，报错原因是:<br>{}',
    u'get_aes_hash_err1_base64': u'错误：AES密钥的SHA256可能不满足base-64编码！',
    u'get_aes_hash_err2_base64_fmt': u'错误：AES密钥的SHA256可能不满足base-64编码，报错原因是:<br>{}',
    u'get_aes_hash_err1_len_fmt': u'AES密钥的SHA256不是有效比特数为256的base-64串，实际比特数为{}',
    u'get_aes_hash_err2_len_fmt': u'AES密钥的SHA256不是有效比特数为256的base-64串，实际比特数为{}',
    u'save_aes_key_ok_fmt': u'base-64编码的AES密钥"{}"已成功写入文件{}',
    u'save_aes_key_err1_fmt': u'AES密钥保存失败，因为文件"{}"打开失败',
    u'save_aes_key_err2_fmt': u'AES密钥保存失败，因为文件"{}"打开失败，报错原因是:<br>{}',

    u'aes_key_label': u'AES密钥',
    u'aes_key_edit': u'',
    u'aes_key_button': u'生成AES密钥的SHA256',
    u'generate_aes_sha256_ok_fmt': u'AES密钥"{}"的SHA-256结果"{}"生成成功',

    u'aes_hash_label': u'AES密钥的SHA256',
    u'aes_hash_edit': u'',
    u'aes_hash_button': u'由SHA256尝试寻找本地AES密钥',
    u'find_aes_key_from_sha256_ok1_fmt': u'成功在本地AES缓存的密钥库中找到与"{}"匹配的AES串"{}"',
    u'find_aes_key_from_sha256_ok2_fmt': u'成功在本地AES缓存的密钥库中找到与"{}"匹配的AES串"{}"<br>' + \
                                         u'结果已经回显到{}文本栏了'.format(ToRed('AES密钥')),
    u'find_aes_key_from_sha256_warn1_fmt': u'没有在本地密码本中找到与"{}"相同的AES密钥',
    u'find_aes_key_from_sha256_warn2_fmt': u'没有在本地密码本中找到与"{}"相同的AES密钥',

    u'aes_raw_label': u'AES明文',
    u'aes_raw_edit': u'',
    u'aes_raw_edit_placeholder': u'请输入要加密的AES明文，并确保AES密钥栏填写了和对方相同的密钥\n' + \
                                 u'注1: AES密钥应为随机数，由随机数发生器生成，通过RSA流程实现密钥的交换\n' + \
                                 u'注2: 如果双方曾保存过共同的AES密钥，可交换AES密钥的SHA-256值以协商密钥\n' + \
                                 u'注3: 从SHA-256值倒推AES密钥是不可能的，只能正向匹配，所以交换SHA-256是安全的',
    u'aes_raw_button': u'用AES密钥加密',
    u'encrypt_aes_err1': u'AES加密过程发生错误',
    u'encrypt_aes_err2_fmt': u'AES加密过程发生错误，报错原因是:<br>{}',
    u'encrypt_aes_ok': u'AES加密成功！',

    u'aes_encrypt_label': u'AES密文',
    u'aes_encrypt_edit': u'',
    u'aes_encrypt_edit_placeholder': u'请输入要解密的AES密文\n' + \
                                     u'注: 密文前面16字节编码了iv，并且后面会补0',
    u'aes_encrypt_button': u'用AES密钥解密',
    u'decrypt_aes_err1': u'AES解密过程发生错误',
    u'decrypt_aes_err2_fmt': u'AES解密过程发生错误，报错原因是:<br>{}',
    u'decrypt_aes_ok': u'AES解密成功！',

    u'file_hint_label': u'{}：<br>'.format(ToRed('文件加密传输使用说明')) + \
                        u'1. 基于当前{}对文件压缩包进行加密（压缩包密码是base-64编码后的AES密钥）<br>'.format(
                            ToOrange('AES密钥')) + \
                        u'2. 可以将随机数作为AES密钥，然后采用{}的方式交换<br>'.format(
                            ToOrange('RSA')) + \
                        u'3. 如果曾经交换过该AES密钥，也可交换该密钥的{}以在本地查找AES密钥<br>'.format(
                            ToOrange('SHA-256')),

    u'file_encrypt_label': u'基于AES密钥<br>进行文件加密<br>文件拖拽到右边',
    u'file_encrypt_edit': u'',
    u'file_encrypt_button': u'输入正确的AES密钥\n拖拽待加密文件到左边\n再按本按钮进行加密',

    u'file_encrypt_7z_err1': u'待加密压缩文件为空，请将待加密文件拖拽到左侧框内后再按按钮',
    u'file_encrypt_7z_err2_unknown': u'fileEncrypt7z函数发生未知错误',
    u'file_encrypt_7z_err3': u'加密压缩包生成过程中发生错误',
    u'file_encrypt_7z_err4_fmt': u'加密压缩包生成过程中发生错误，报错原因是:<br>{}',
    u'file_encrypt_7z_ok_fmt': u'加密压缩包"{}"生成成功！',

    u'file_decrypt_label': u'基于AES密钥<br>进行文件解密<br>文件拖拽到右边',
    u'file_decrypt_edit': u'',
    u'file_decrypt_button': u'输入正确的AES密钥\n拖拽待解密文件到左边\n再按本按钮进行解密',
    u'file_decrypt_edit_placeholder': u'将双层7z压缩文件拖入本文本框，将根据输入的AES密钥或本地缓存的AES密钥尝试解压。\n' + \
                                      u'如果解压成功，将自动在目录下生成以密钥SHA-256值为文件名的文件夹。\n'
                                      u'注: 内层压缩包的文件名标识了AES密钥的SHA-256值，千万不要改内层压缩包名！',
    u'file_decrypt_7z_err1': u'待解密压缩文件不是一个7z文件',
    u'file_decrypt_7z_err2_fmt': u'待解压的7z文件的内层文件并不是单个7z文件，内层文件数为{}',
    u'file_decrypt_7z_err3': u'待解密压缩文件的内层文件不符合自动解压规范',
    u'file_decrypt_7z_err4': u'解密压缩包生成过程中发生错误',
    u'file_decrypt_7z_err4_fmt': u'解密压缩包生成过程中发生错误，报错原因是:<br>{}',
    u'file_decrypt_7z_err_return': u'没有在AES密钥中找到该压缩包匹配的解压密码',
    u'file_decrypt_7z_ok_fmt': u'压缩包"{}"解密成功！',
    u'file_decrypt_7z_ok_full_fmt': u'压缩包"{}"解密成功！解压结果放在目录"{}"下！',
}
