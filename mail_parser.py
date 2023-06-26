#-*- coding: utf-8 -*-

import argparse
import sys, os, io
import yara
import re
import json
import time
import datetime
import DB
from urllib.parse import unquote


class StartYara():
    def __init__(self):
        # self.rule_path = 'mail_rule'
        self.email_list = []
        self.proton_email_list = []
        self.tutanota_email_list = []
        self.mailfence_email_list = []
        self.outlook_email_list = []
        self.yahoo1_email_list = []
        self.yahoo2_email_list = []
        self.kakao_email_list = []
        self.gmail_email_list = []
        self.naver_email_list = []

    def get_yara_return(self, data):
        self.matched_result = data["strings"]


# 현재 쓰지는 않음 필요시 쓰기
    def rule_compile(self, rule_file_path):
        rules = yara.compile(filepath = rule_file_path)
        return rules

    def input_mathed_result_yara(self):
        for value in self.matched_result:
            flag_offset = value[1]
            if flag_offset == '$s1':
                self.proton_email_list.append(value[0])
            elif flag_offset == '$s2':
                self.tutanota_email_list.append(value[0])
            elif flag_offset == '$s3' or flag_offset == '$s4' or flag_offset == '$s5' or flag_offset == '$s6' or flag_offset == '$s7' or flag_offset == '$s9':
                self.email_list.append(value[0])
            elif flag_offset == '$s8':
                self.mailfence_email_list.append(value[0])
            elif flag_offset == '$s10':
                self.outlook_email_list.append(value[0])
            elif flag_offset == '$s11':
                self.yahoo1_email_list.append(value[0])
            elif flag_offset == '$s12':
                self.yahoo2_email_list.append(value[0])
            elif flag_offset == '$s13':
                self.kakao_email_list.append(value[0])
            elif flag_offset == '$s14':
                self.gmail_email_list.append(value[0])
            elif flag_offset == '$s15':
                self.naver_email_list.append(value[0])

    #Mail2Tor, OnionMail, Daniel's Mail 수집
    def input_db_email(self, t_file):
        email_info_list = {}
        for email_index in self.email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(7) == b'\x22\x5F\x63\x73\x72\x66\x22'):
                        email_info_list['Service'] = "Onion Mail"
                        break
                    elif (t_file.read(19) == b'\x22\x73\x65\x6E\x64\x5F\x62\x75\x74\x74\x6F\x6E\x5F\x63\x6F\x75\x6E\x74\x22'):
                        email_info_list['Service'] = "Danwin1210"
                        break
                    elif (t_file.read(11) == b'\x22\x73\x75\x73\x69\x4E\x6F\x6E\x63\x65\x22'):
                        email_info_list['Service'] = "I2P susimail"
                        break
                    elif (t_file.read(9) == b'\x22\x73\x65\x71\x4E\x75\x6D\x73\x22'):
                        email_info_list['Service'] = "Naver Works"
                        break
                    else:
                        k += 1
                        if k > 20000:
                            email_info_list['Service'] = "DNMX"
                            break
                t_file.seek(email_index)
                add_t_file = t_file.read(email_index)

                if email_info_list['Service'] == "DNMX":
                    em_mt = re.compile(b'name=\"querystring\"\r\n\r\n')
                    mail2tor_tmp = em_mt.findall(add_t_file)
                    if len(mail2tor_tmp) != 0:
                        email_info_list['Service'] = "Mail2Tor"

                # Recipient
                em_re = re.compile(b'name=\"(?:send_to|to|new_to)\"\r\n\r\n.+\r\n')
                recipient_tmp = em_re.findall(add_t_file)
                recipient_tmp = recipient_tmp[0].decode('utf-8').replace("name=\"to\"", "").replace("name=\"send_to\"", "").replace("name=\"new_to\"", "").replace("\r\n", "").replace(";", ", ")

                email_info_list['Recipient'] = recipient_tmp

                # cc
                em_cc = re.compile(b'name=\"(?:send_to_cc|cc|new_cc)\"\r\n\r\n.+\r\n')
                cc_tmp = em_cc.findall(add_t_file)
                if len(cc_tmp) == 0:
                    cc_tmp = ""
                else:
                    cc_tmp = cc_tmp[0].decode('utf-8').replace("name=\"cc\"", "").replace("name=\"send_to_cc\"", "").replace("name=\"new_cc\"", "").replace("\r\n", "").replace(";", ", ")

                email_info_list['CC'] = cc_tmp

                # bcc
                em_bcc = re.compile(b'name=\"(?:send_to_bcc|bcc|new_bcc)\"\r\n\r\n.+\r\n')
                bcc_tmp = em_bcc.findall(add_t_file)
                if len(bcc_tmp) == 0:
                    bcc_tmp = ""
                else:
                    bcc_tmp = bcc_tmp[0].decode('utf-8').replace("name=\"bcc\"", "").replace("name=\"send_to_bcc\"", "").replace("name=\"new_bcc\"", "").replace("\r\n", "").replace(";", ", ")

                email_info_list['BCC'] = bcc_tmp

                # sender
                em_sender = re.compile(b'name=\"(?:username|from|senderAddress)\"\r\n\r\n.+\r\n')
                sender_tmp = em_sender.findall(add_t_file)
                if len(sender_tmp) == 0:
                    sender_tmp = ""
                else:
                    sender_tmp = sender_tmp[0].decode('utf-8').replace("name=\"username\"", "").replace("name=\"from\"", "").replace("name=\"senderAddress\"", "").replace("\r\n", "")

                email_info_list['Sender'] = sender_tmp

                # Subject
                em_sub = re.compile(b'name=\"(?:subject|new_subject)\"\r\n\r\n.+\r\n')
                subject_tmp = em_sub.findall(add_t_file)
                subject_tmp = subject_tmp[0].decode('utf-8').replace("name=\"subject\"", "").replace("name=\"new_subject\"", "").replace("\r\n", "")

                email_info_list['Subject'] = subject_tmp

                # Body
                em = re.compile(b'name=\"(?:body|editordata|new_text)\"\r\n\r\n.+\r\n-{2,}',re.DOTALL)
                body_tmp = em.findall(add_t_file)
                body_tmp = body_tmp[0].split(b"------")[0].strip()
                body_tmp = body_tmp.decode('utf-8').replace("name=\"body\"\r\n\r\n", "").replace("name=\"editordata\"\r\n\r\n", "").replace("name=\"new_text\"\r\n\r\n", "")
                email_info_list['Body'] = body_tmp

                # attachment
                em_f = re.compile(b'name=\"(?:files|attachfile|new_filename)\".+\s{2}Content-Type.+')
                file_tmp = em_f.findall(add_t_file)
                if len(file_tmp) == 0:
                    file_tmp = ""
                else:
                    file_tmp = ','.join([item.decode('utf-8').replace("name=\"files\";", "").replace("name=\"attachfile\";", "").replace("name=\"new_filename\";", "").replace("filename=", "").replace("\r", "").replace("\n", "").replace("Content-Type", " Content-Type") for item in file_tmp])

                email_info_list['SentDate'] = ""

                # mailbox
                em_d = re.compile(b'name=\"(?:mailbox|folder)\"\r\n\r\n.+\r\n')
                desc_tmp = em_d.findall(add_t_file)
                if len(desc_tmp) != 0:
                    desc_tmp = desc_tmp[0].decode('utf-8').replace("name=\"mailbox\"", "").replace("name=\"folder\"", "").replace("\r\n", "")
                    if (len(file_tmp) == 0) or ("\"\" Content-Type: " in file_tmp):
                        file_tmp = ""
                        email_info_list['Description'] = "Mailbox : " + desc_tmp
                    else:
                        email_info_list['Description'] = "Mailbox : " + desc_tmp + ", Attachfile : " + file_tmp
                else:
                    if (len(file_tmp) == 0) or ("\"\" Content-Type: " in file_tmp):
                        file_tmp = ""
                        email_info_list['Description'] = file_tmp
                    else:
                        email_info_list['Description'] = "Attachfile : " + file_tmp

                DB.email_db(email_info_list)
            except:
                pass

    #Protonmail 수집
    def input_db_protonmail(self, t_file):
        email_info_list = {}
        for email_index in self.proton_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(2) == b'\x7D\x7D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 2)

                proton_mail_json = json.loads(add_t_file)
                proton_mail_json = proton_mail_json.get("Message")

                email_info_list['Subject'] = str(proton_mail_json.get("Subject"))
                email_info_list['Body'] = str(proton_mail_json.get("Body"))
                email_info_list_datetime = proton_mail_json.get("Time")
                utc = datetime.timezone(datetime.timedelta(hours=+0))
                email_info_list['SentDate'] = datetime.datetime.fromtimestamp(email_info_list_datetime, tz=utc).isoformat()
                email_info_list['Sender'] = proton_mail_json.get("Sender").get("Address")

                proton_recipient_list = [recipient["Address"] for recipient in proton_mail_json["ToList"]]
                proton_reply_recipient_list = [recipient["Address"] for recipient in proton_mail_json["replyTo"]]
                proton_recipient_list = list(set(proton_recipient_list+proton_reply_recipient_list))
                email_info_list['Recipient'] = ", ".join(proton_recipient_list)

                proton_cc_list = [cc["Address"] for cc in proton_mail_json["CCList"]]
                email_info_list['CC'] = ", ".join(proton_cc_list)

                proton_bcc_list = [bcc["Address"] for bcc in proton_mail_json["BCCList"]]
                email_info_list['BCC'] = ", ".join(proton_bcc_list)

                email_info_list['Description'] = ""
                email_info_list['Service'] = 'ProtonMail'

                DB.email_db(email_info_list)
            except:
                pass

    #Tutanota mail 수집
    def input_db_tutanotaemail(self, t_file):
        email_info_list = {}
        for email_index in self.tutanota_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(3) == b'\x7D\x5D\x7D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 3)

                tutanota_mail_json = json.loads(add_t_file)

                email_info_list['Subject'] = str(tutanota_mail_json.get("subject"))
                email_info_list['Body'] = str(tutanota_mail_json.get("body"))
                email_info_list_datetime = int(tutanota_mail_json.get("sentDate"))/1000
                utc = datetime.timezone(datetime.timedelta(hours=+0))
                email_info_list['SentDate'] = datetime.datetime.fromtimestamp(email_info_list_datetime, tz=utc).isoformat()
                email_info_list['Sender'] = tutanota_mail_json.get("sender").get("address")
                # email_info_list['Sender'] = str(tutanota_sender_json.get("address"))

                tutanota_recipient_list = [recipient["address"] for recipient in tutanota_mail_json["toRecipients"]]
                tutanota_reply_recipient_list = [recipient["address"] for recipient in tutanota_mail_json["replyTos"]]
                tutanota_recipient_list = list(set(tutanota_recipient_list + tutanota_reply_recipient_list))
                email_info_list['Recipient'] = ", ".join(tutanota_recipient_list)

                tutanota_cc_list = [cc["address"] for cc in tutanota_mail_json["ccRecipients"]]
                email_info_list['CC'] = ", ".join(tutanota_cc_list)

                tutanota_bcc_list = [bcc["address"] for bcc in tutanota_mail_json["bccRecipients"]]
                email_info_list['BCC'] = ", ".join(tutanota_bcc_list)

                email_info_list['Description'] = ""
                email_info_list['Service'] = "Tutanota"

                DB.email_db(email_info_list)
            except:
                pass

    #mailfence mail수집
    def input_db_mailfencemail(self, t_file):
        email_info_list = {}
        for email_index in self.mailfence_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(18) == b'\x7C\x4D\x65\x73\x73\x61\x67\x65\x54\x69\x6D\x65\x73\x74\x61\x6D\x70\x7C'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 18)

                mailfence_seg = add_t_file.split(b"|")

                # 부가정보
                mf_protocol_version = mailfence_seg[0].decode('utf-8')
                mf_column_numbers = mailfence_seg[2].decode('utf-8')
                mf_host = mailfence_seg[3].decode('utf-8')
                mf_hash = mailfence_seg[4].decode('utf-8')
                mf_class_name = mailfence_seg[5].decode('utf-8')
                mf_function = mailfence_seg[6].decode('utf-8')

                start_index = None
                end_index = None
                # 첨부파일
                for i, element in enumerate(mailfence_seg):
                    if b"com.contactoffice.gwt.mail.client.rpc.RpcAttachment/" in element:
                        start_index = i
                    elif b"com.contactoffice.gwt.mail.client.rpc.RpcMailFolder/" in element:
                        end_index = i
                        break

                mf_attach = None
                if start_index is not None and end_index is not None:
                    mf_attach_temp = mailfence_seg[start_index+1:end_index]
                    new_attach = []
                    for i in range(2, len(mf_attach_temp), 3):
                        if i < len(mf_attach_temp):
                            temp = mf_attach_temp[i].decode('utf-8').split(';')
                            attach_name = temp[-1].replace(" name=", "")
                            attach_type = temp[0]
                            new_attach.append(f'"{attach_name}" Content-Type: {attach_type}')
                    mf_attach = ", ".join(new_attach)
                    email_info_list['Description'] = f"Attachfile : {mf_attach}"
                    # 메일 박스(부가정보)
                    mf_mailbox = mailfence_seg[end_index + 1].decode('utf-8')

                start_index = None
                end_index = None
                # 송신자
                for i, element in enumerate(mailfence_seg):
                    if b"com.contactoffice.gwt.mail.client.rpc.RpcRecipient/" in element:
                        start_index = i
                    elif b"from" == element:
                        end_index = i
                        break

                if start_index is not None and end_index is not None:
                    mf_sender = mailfence_seg[start_index+1:end_index]
                    email_info_list['Sender'] = mf_sender[0].decode('utf-8')

                start_index = None
                end_index = None
                # 수신자
                for i, element in enumerate(mailfence_seg):
                    if b"from" == element:
                        if b"java.util.ArrayList/" in mailfence_seg[i+1]:
                            start_index = i+1
                        else:
                            start_index = i
                    elif b"cc" == element or b"bcc" == element:
                        if b"@" in mailfence_seg[i-1]:
                            end_index = i-2
                        else:
                            end_index = i-3
                        break
                    elif b"[Ljava.lang.String;/" in element:
                        end_index = i-3
                        break

                if start_index is not None and end_index is not None:
                    mf_recipients = mailfence_seg[start_index+1:end_index+1]
                    new_recipients = []
                    for i in mf_recipients:
                        if b"@" in i:
                            new_recipients.append(i.decode('utf-8'))
                    mf_recipients = ", ".join(new_recipients)

                    email_info_list['Recipient'] = mf_recipients

                start_index = None
                end_index = None
                # 참조
                for i, element in enumerate(mailfence_seg):
                    if b"cc" == element:
                        if b"@" in mailfence_seg[i-1]:
                            start_index = i-2
                        else:
                            start_index = i-3
                    elif b"bcc" == element:
                        if b"@" in mailfence_seg[i - 1]:
                            end_index = i-2
                        else:
                            end_index = i-3
                        break
                    elif b"[Ljava.lang.String;/" in element:
                        end_index = i-3
                        break

                if start_index is not None and end_index is not None:
                    mf_cc = mailfence_seg[start_index+1:end_index+1]
                    new_cc = []
                    for i in mf_cc:
                        if b"@" in i:
                            new_cc.append(i.decode('utf-8'))
                    mf_cc = ", ".join(new_cc)

                    email_info_list['CC'] = mf_cc
                else:
                    email_info_list['CC'] = ""

                start_index = None
                end_index = None
                bcc_mark = 0
                pem_mark = 0
                # 숨은 참조
                for i, element in enumerate(mailfence_seg):
                    if b"bcc" == element:
                        if b"@" in mailfence_seg[i-1]:
                            start_index = i-2
                        else:
                            start_index = i-3
                        bcc_mark = 1
                    elif b"[Ljava.lang.String;/" in element:
                        end_index = i-1
                        if b"-----END PGP MESSAGE-----" in mailfence_seg[i-1]:
                            pem_mark = 1
                        break

                if start_index is not None and end_index is not None:
                    if pem_mark == 1:
                        if b"@" in mailfence_seg[start_index+1]:
                            mf_bcc = mailfence_seg[start_index+1:end_index-1]
                        else:
                            mf_bcc = mailfence_seg[start_index:end_index-1]
                    else:
                        if b"@" in mailfence_seg[start_index+1]:
                            mf_bcc = mailfence_seg[start_index+1:end_index-2]
                        else:
                            mf_bcc = mailfence_seg[start_index:end_index-2]
                    new_bcc = []
                    for i in mf_bcc:
                        if b"@" in i:
                            new_bcc.append(i.decode('utf-8'))
                    mf_bcc = ", ".join(new_bcc)

                    email_info_list['BCC'] = mf_bcc
                else:
                    email_info_list['BCC'] = ""

                # 제목, 본문, 전송 시간
                index = end_index+1

                if index is not None:
                    # 내용
                    if bcc_mark == 0 or pem_mark == 1:
                        mf_body = mailfence_seg[index-1]
                    else:
                        mf_body = mailfence_seg[index-2]
                    email_info_list['Body'] = mf_body.decode('utf-8')

                    # 전송 시간
                    mf_sentdate = mailfence_seg[index+1]
                    email_info_list['SentDate'] = mf_sentdate.decode('utf-8')

                    # 제목
                    mf_subject = mailfence_seg[index+4]
                    email_info_list['Subject'] = mf_subject.decode('utf-8')

                hint_index = None
                exp_index = None
                # 그 밖의 정보(암호화되어 있는 메일의 경우)
                for i, element in enumerate(mailfence_seg):
                    if b"PEMHint" in element:
                        hint_index = i
                    elif b"PEMExpiration" in element:
                        exp_index = i
                        break

                if hint_index is not None and exp_index is not None:
                    # 암호화 메일의 암호 힌트 및 만료 기간
                    mf_hint = mailfence_seg[hint_index+1].decode('utf-8')
                    mf_expire = int(mailfence_seg[exp_index+1].decode('utf-8'))/1000
                    utc = datetime.timezone(datetime.timedelta(hours=+0))
                    mf_expire = datetime.datetime.fromtimestamp(mf_expire, tz=utc).isoformat()
                    email_info_list['Description'] = f"PEMHint : {mf_hint}, PEMExpiration : {mf_expire}"
                else:
                    if mf_attach is None:
                        email_info_list['Description'] = ""

                email_info_list['Service'] = "Mailfence"

                DB.email_db(email_info_list)
            except:
                pass

    # outlook.com수집
    def input_db_outlookmail(self, t_file):
        email_info_list = {}
        for email_index in self.outlook_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(5) == b'\x7D\x5D\x7D\x7D\x5D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 5)
                add_t_file = add_t_file + "}]}}".encode('utf-8')

                outlook_mail_json = json.loads(add_t_file)
                outlook_body_json = outlook_mail_json["Body"]["ItemChanges"][0]["Updates"]

                to_list = [recipient["EmailAddress"] for recipient in outlook_body_json[0]["Item"]["ToRecipients"]]
                email_info_list['Recipient'] = ", ".join(to_list)

                cc_list = [cc["EmailAddress"] for cc in outlook_body_json[1]["Item"]["CcRecipients"]]
                email_info_list['CC'] = ", ".join(cc_list)

                bcc_list = [bcc["EmailAddress"] for bcc in outlook_body_json[2]["Item"]["BccRecipients"]]
                email_info_list['BCC'] = ", ".join(bcc_list)

                email_info_list['Subject'] = outlook_body_json[3]["Item"]["Subject"]
                email_info_list['Body'] = outlook_body_json[4]["Item"]["Body"]["Value"]
                email_info_list['Sender'] = outlook_body_json[9]["Item"]['From']['Mailbox']['EmailAddress']

                email_info_list['SentDate'] = ""
                email_info_list['Description'] = "TimeZone : " + str(outlook_mail_json.get("Header").get("TimeZoneContext").get("TimeZoneDefinition").get("Id"))

                email_info_list['Service'] = 'Outlook.com'

                DB.email_db(email_info_list)
            except:
                pass

    # yahoo 수집
    def input_db_yahoomail(self, t_file):
        email_info_list = {}
        for email_index in self.yahoo1_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    # if (t_file.read(13) == b'\x22\x65\x72\x72\x6F\x72\x22\x3A\x6E\x75\x6C\x6C\x7D'):
                    if (t_file.read(22) == b'\x22\x72\x65\x73\x70\x6F\x6E\x73\x65\x54\x79\x70\x65\x22\x3A\x22\x6A\x73\x6F\x6E\x22\x7D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 22)

                yahoo_mail_json = json.loads(add_t_file)
                # yahoo_mail_json = yahoo_mail_json["result"]["responses"][0]["response"]["result"]
                yahoo_mail_json = yahoo_mail_json["requests"][0]["payloadParts"][0]["payload"]

                email_info_list['Subject'] = yahoo_mail_json["message"]["headers"]["subject"]
                email_info_list['Body'] = yahoo_mail_json["simpleBody"]["html"]
                # yahoo_mail_datetime = yahoo_mail_json["message"]["headers"]["to"]["date"]
                # utc = datetime.timezone(datetime.timedelta(hours=+0))
                # email_info_list['SentDate'] = datetime.datetime.fromtimestamp(yahoo_mail_datetime, tz=utc).isoformat()
                email_info_list['SentDate'] = ""
                email_info_list['Sender'] = yahoo_mail_json["message"]["headers"]["from"][0]["email"]

                yahoo_recipient_list = [recipient["email"] for recipient in yahoo_mail_json["message"]["headers"]["to"]]
                yahoo_reply_recipient_list = [recipient["email"] for recipient in yahoo_mail_json["message"]["headers"]["replyTo"]]
                yahoo_recipient_list = yahoo_recipient_list + yahoo_reply_recipient_list
                email_info_list['Recipient'] = ", ".join(yahoo_recipient_list)

                yahoo_cc_list = [cc["email"] for cc in yahoo_mail_json["message"]["headers"]["cc"]]
                email_info_list['CC'] = ", ".join(yahoo_cc_list)

                yahoo_bcc_list = [bcc["email"] for bcc in yahoo_mail_json["message"]["headers"]["bcc"]]
                email_info_list['BCC'] = ", ".join(yahoo_bcc_list)

                yahoo_attach_file = [recipient["multipartName"].replace("multipart://","") for recipient in yahoo_mail_json["message"]["attachments"]]
                yahoo_attach_list = ", ".join(yahoo_attach_file)

                if len(yahoo_attach_list) == 0:
                    email_info_list['Description'] = ""
                else:
                    email_info_list['Description'] = f"Attachfile : {yahoo_attach_list}"
                email_info_list['Service'] = 'YahooMail'

                DB.email_db(email_info_list)
            except:
                pass

    # kakao 수집
    def input_db_kakaomail(self, t_file):
        email_info_list = {}
        for email_index in self.kakao_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(2) == b'\x7D\x7D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(k + 2)

                kakao_mail_json = json.loads(add_t_file)

                email_info_list['Subject'] = str(kakao_mail_json.get("subject"))
                email_info_list['Body'] = str(kakao_mail_json.get("contents"))
                email_info_list['SentDate'] = datetime.datetime.strptime(str(kakao_mail_json.get("composerTime")), "%Y%m%d%H%M%S")
                email_info_list['Sender'] = kakao_mail_json.get("from").get("addr")

                kakao_recipient_list = [recipient["addr"] for recipient in kakao_mail_json["toList"]]
                email_info_list['Recipient'] = ", ".join(kakao_recipient_list)

                kakao_cc_list = [cc["addr"] for cc in kakao_mail_json["ccList"]]
                email_info_list['CC'] = ", ".join(kakao_cc_list)

                kakao_bcc_list = [bcc["addr"] for bcc in kakao_mail_json["bccList"]]
                email_info_list['BCC'] = ", ".join(kakao_bcc_list)

                kakao_attach_file = ["Attachfile : \""+str(attach["fileName"])+"\" Content-Type: "+str(attach["contentType"]) for attach in kakao_mail_json["attachments"]]
                kakao_attach_list = ", ".join(kakao_attach_file)

                if len(kakao_attach_list) == 0:
                    email_info_list['Description'] = ""
                else:
                    email_info_list['Description'] = kakao_attach_list

                email_info_list['Service'] = 'Daum Kakao Mail'

                DB.email_db(email_info_list)
            except:
                pass

    # gmail 수집
    def input_db_gmail(self, t_file):
        email_info_list = {}
        for email_index in self.gmail_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(4) == b'\x5D\x2C\x32\x5D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(email_index)

                g_send = re.compile(b'\[\[\"msg-a:r-.+?\",\[1,\".+?\"')
                g_send_tmp = g_send.findall(add_t_file)
                email_info_list['Sender'] = (re.sub(b'\[\[\"msg-a:r-.+?\",\[1,', b'', g_send_tmp[0])).decode('utf-8').replace("\"", "")

                g_recp = re.compile(b'\[\[1,\".+?\"\]\]')
                g_recp_tmp = g_recp.findall(add_t_file)
                email_info_list['Recipient'] = (re.sub(b'\",\".+?\"\]\]', b'', g_recp_tmp[0])).decode('utf-8').replace("[1,", "").replace("[", "").replace("\"", "").replace("],",", ").replace("]]","")

                if (len(g_recp_tmp) < 2) or (len(g_recp_tmp[1]) == 0):
                    email_info_list['CC'] = ""
                else:
                    email_info_list['CC'] = (re.sub(b'\",\".+?\"\]\]', b'', g_recp_tmp[1])).decode('utf-8').replace("[1,", "").replace("[", "").replace(" 1,", "").replace("\"", "").replace("],",", ").replace("]]","")

                if (len(g_recp_tmp) < 3) or (len(g_recp_tmp[2]) == 0):
                    email_info_list['BCC'] = ""
                else:
                    email_info_list['BCC'] = (re.sub(b'\",\".+?\"\]\]', b'', g_recp_tmp[2])).decode('utf-8').replace("[1,", "").replace("[", "").replace(" 1,", "").replace("\"", "").replace("],",", ").replace("]]","")

                g_header = re.compile(b'\"\]\],.+?,\d{13,14},\".+?\",\[')
                g_header_tmp = g_header.findall(add_t_file)

                g_date = re.compile(b',\d{13,14},')
                g_date_tmp = g_date.findall(g_header_tmp[0])
                g_date_tmp = int(g_date_tmp[0].decode('utf-8').replace(",", ""))/1000
                utc = datetime.timezone(datetime.timedelta(hours=+0))
                email_info_list['SentDate'] = datetime.datetime.fromtimestamp(g_date_tmp, tz=utc).isoformat()

                g_sub = re.compile(b'\d{13,14},\".+?."')
                g_sub_tmp = g_sub.findall(g_header_tmp[0])
                email_info_list['Subject'] = (re.sub(b'\d+,', b'', g_sub_tmp[0])).decode('utf-8').replace(",\"","").replace("\",[","")

                g_body = re.compile(b'\[\[0,\".+?\"\]\]')
                g_body_tmp = g_body.findall(add_t_file)
                email_info_list['Body'] = g_body_tmp[0].decode('utf-8').replace("[[0,\"","").replace("\"]]","")

                g_attach = re.compile(b'\],\[\[\".+?\/.+?\",\".+?\",\d+,')
                g_attach_tmp = g_attach.findall(add_t_file)
                g_attach_tmp = (re.sub(b'\",\d+,', b'', g_attach_tmp[0])).decode('utf-8').replace("],[[", "").replace("\"", "")
                g_attach_tmp = g_attach_tmp.split(",")
                email_info_list['Description'] = f"Attachfile : \"{g_attach_tmp[1]}\" Content-Type: {g_attach_tmp[0]}"

                email_info_list['Service'] = "Gmail"

                DB.email_db(email_info_list)
            except:
                pass

    # naver mail 수집
    def input_db_navermail(self, t_file):
        email_info_list = {}
        for email_index in self.naver_email_list:
            try:
                k = 0
                while True:
                    t_file.seek(email_index + k)
                    if (t_file.read(3) == b'\x26\x75\x3D'):
                        break
                    else:
                        k += 1
                t_file.seek(email_index)
                add_t_file = t_file.read(email_index)

                n_send = re.compile(b'senderName=.+?&senderAddress')
                n_send_tmp = n_send.findall(add_t_file)
                email_info_list['Sender'] = unquote(n_send_tmp[0].decode('utf-8').replace("senderName=", "").replace("&senderAddress", ""))

                n_to = re.compile(b'&to=.+?&cc')
                n_to_tmp = n_to.findall(add_t_file)
                n_to_list = unquote(n_to_tmp[0].decode('utf-8').replace("&to=", "").replace("&cc", "")).split(";")[:-1]
                email_info_list['Recipient'] = ", ".join(n_to_list)

                n_cc = re.compile(b'&cc=.+?&bcc')
                n_cc_tmp = n_cc.findall(add_t_file)
                if len(n_cc_tmp) == 0:
                    email_info_list['CC'] = ""
                else:
                    n_cc_list = unquote(n_cc_tmp[0].decode('utf-8').replace("&cc=", "").replace("&bcc", "")).split(";")[:-1]
                    email_info_list['CC'] = ", ".join(n_cc_list)

                n_bcc = re.compile(b'&bcc=.+?&subject')
                n_bcc_tmp = n_bcc.findall(add_t_file)
                if len(n_bcc_tmp) == 0:
                    email_info_list['BCC'] = ""
                else:
                    n_bcc_list = unquote(n_bcc_tmp[0].decode('utf-8').replace("&bcc=", "").replace("&subject", "")).split(";")[:-1]
                    email_info_list['BCC'] = ", ".join(n_bcc_list)

                n_subj = re.compile(b'&subject=.+?&body')
                n_subj_tmp = n_subj.findall(add_t_file)
                email_info_list['Subject'] = unquote(n_subj_tmp[0].decode('utf-8').replace("&subject=", "").replace("&body", ""))

                n_body = re.compile(b'&body=.+?&contentType=')
                n_body_tmp = n_body.findall(add_t_file)
                email_info_list['Body'] = unquote(n_body_tmp[0].decode('utf-8').replace("&body=", "").replace("&contentType=", ""))

                email_info_list['SentDate'] = ""
                email_info_list['Description'] = ""

                email_info_list['Service'] = "Naver mail"

                DB.email_db(email_info_list)
            except:
                pass

    def rule_match_string(self, compiled_rules, target_file_name):
        try:
            t_file = open(target_file_name, "rb")
            loop_num = 8
            number_bit_5g = int(os.path.getsize(target_file_name)/loop_num)

            for file_index in range(loop_num) :
                # 아니면 계속 들어감
                StartYara.__init__(self)
                
                self.file_data = t_file.read(number_bit_5g)
                compiled_rules.match(data=self.file_data, callback=self.get_yara_return)
                self.file_data = io.BytesIO(self.file_data)

                # 파싱 작업 돌리기
                StartYara.input_mathed_result_yara(self)

                StartYara.input_db_email(self, self.file_data)

                StartYara.input_db_protonmail(self, self.file_data)

                StartYara.input_db_tutanotaemail(self, self.file_data)

                StartYara.input_db_mailfencemail(self, self.file_data)

                StartYara.input_db_outlookmail(self, self.file_data)

                StartYara.input_db_yahoomail(self, self.file_data)

                StartYara.input_db_kakaomail(self, self.file_data)

                StartYara.input_db_gmail(self, self.file_data)

                StartYara.input_db_navermail(self, self.file_data)

        except Exception as e:
            print(e)
            return

    def yara_run(self, target, rule_path):
        try:
            rules = yara.compile(filepath = rule_path)
            return self.rule_match_string(rules, target)
        except Exception as e:
            print(target)
            print(e)

def excute():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "-in", action="store", dest="input_path", help="Input file path")
    parser.add_argument("-o", "-out", action="store", dest="out_path", help="Output file path")
    # parser.add_argument("-yar", action="store", dest="rule_path", help="Input yara rule file path")
    rule_path = "mail_rule.yar"
    args = parser.parse_args()

    DB.create_DB(os.path.join(args.out_path, "email.db"))

    result = StartYara()
    result.yara_run(args.input_path, rule_path)


if __name__ == "__main__":
    now = datetime.datetime.now()
    print("Time Memory Parser Start : ", now)

    excute()

    now = datetime.datetime.now()
    print("Time Memory Parser End : ", now)  # seconds

